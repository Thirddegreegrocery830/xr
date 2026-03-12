use super::{alloc_bss, ParseResult, Segment, Symbol, VaRangeSet};
use crate::loader::{Arch, DecodeMode, RelocPointer};
use crate::va::Va;
use anyhow::Result;
use rustc_hash::FxHashSet;

pub(super) fn parse_macho(
    bytes: &'static [u8],
    macho: &goblin::mach::MachO,
    bss_bufs: &mut Vec<Box<[u8]>>,
) -> Result<ParseResult> {
    use goblin::mach::constants::cputype::*;
    let arch = match macho.header.cputype() {
        CPU_TYPE_X86_64 => Arch::X86_64,
        CPU_TYPE_ARM64 => Arch::Arm64,
        CPU_TYPE_X86 => Arch::X86,
        CPU_TYPE_ARM => Arch::Arm32,
        m => {
            eprintln!("warning: unknown Mach-O cputype {m:#x}, treating as unknown");
            Arch::Unknown
        }
    };

    const NO_SCAN_SECTIONS: &[&str] = &[
        "__DATA_CONST,__got",
        "__DATA,__got",
        "__DATA_CONST,__auth_got",
        "__DATA,__la_symbol_ptr",
        "__DATA,__nl_symbol_ptr",
        "__DATA_CONST,__cfstring",
        "__DATA,__cfstring",
    ];

    let mut segments = Vec::new();
    for seg in macho.segments.iter() {
        let seg_name = seg.name().unwrap_or("?").to_string();
        for section in seg.sections().map_err(|e| anyhow::anyhow!("{e}"))? {
            let (sect, data) = section;
            let sect_name = sect.name().unwrap_or("?").to_string();
            let size = sect.size as usize;
            if size == 0 {
                continue;
            }
            let exec = seg.initprot & goblin::mach::constants::VM_PROT_EXECUTE != 0;
            let read = seg.initprot & goblin::mach::constants::VM_PROT_READ != 0;
            let write = seg.initprot & goblin::mach::constants::VM_PROT_WRITE != 0;
            let full_name = format!("{seg_name},{sect_name}");
            let byte_scannable = !exec && !NO_SCAN_SECTIONS.iter().any(|&n| n == full_name);

            let section_data: &'static [u8] = if data.is_empty() {
                alloc_bss(size, bss_bufs)
            } else {
                let file_offset = sect.offset as usize;
                if file_offset + size > bytes.len() {
                    continue;
                }
                &bytes[file_offset..file_offset + size]
            };

            segments.push(Segment {
                va: Va::new(sect.addr),
                data: section_data,
                executable: exec,
                readable: read,
                writable: write,
                mode: DecodeMode::Default,
                name: full_name,
                byte_scannable,
            });
        }
    }

    let entry_points = vec![Va::new(macho.entry)];
    let mut symbols = Vec::new();
    if let Some(syms) = macho.symbols.as_ref() {
        for (name, nlist) in syms.iter().flatten() {
            if !name.is_empty() && nlist.n_value != 0 {
                symbols.push(Symbol { name: name.to_string(), va: Va::new(nlist.n_value) });
            }
        }
    }

    let preferred_base = macho
        .segments
        .iter()
        .find(|s| s.name().is_ok_and(|n| n == "__TEXT"))
        .map_or(0, |s| s.vmaddr);
    let reloc_pointers = build_macho_fixup_pointers(bytes, macho, preferred_base, &segments);

    Ok(ParseResult {
        arch,
        segments,
        entry_points,
        symbols,
        pie_base: 0,
        got_slots: FxHashSet::default(),
        reloc_pointers,
    })
}

/// Walk LC_DYLD_CHAINED_FIXUPS to extract rebase pointers.
///
/// Supports `DYLD_CHAINED_PTR_64_OFFSET` (format 6, common in arm64 user-space
/// binaries) and `DYLD_CHAINED_PTR_64` (format 2, used in x86_64 binaries).
/// Each rebase entry encodes a pointer-sized slot whose value (after relocation)
/// points to `preferred_base + target_offset`.  These are emitted as
/// `DataPointer` xrefs.
///
/// Bind entries (imports from other dylibs) are skipped — their targets are
/// external symbols not mapped in this binary.
fn build_macho_fixup_pointers(
    bytes: &[u8],
    macho: &goblin::mach::MachO,
    preferred_base: u64,
    segments: &[Segment],
) -> Vec<RelocPointer> {
    use goblin::mach::load_command::CommandVariant;

    let seg_set = VaRangeSet::build(segments);

    let Some(lc) = macho.load_commands.iter().find_map(|lc| {
        if let CommandVariant::DyldChainedFixups(ref cmd) = lc.command {
            Some(cmd)
        } else {
            None
        }
    }) else {
        return Vec::new();
    };

    let data_off = lc.dataoff as usize;
    let data_size = lc.datasize as usize;
    if data_off + data_size > bytes.len() || data_size < 28 {
        return Vec::new();
    }

    let starts_offset = u32::from_le_bytes(
        bytes[data_off + 4..data_off + 8].try_into().expect("checked above"),
    ) as usize;

    let si_off = data_off + starts_offset;
    if si_off + 4 > bytes.len() {
        return Vec::new();
    }
    let seg_count = u32::from_le_bytes(
        bytes[si_off..si_off + 4].try_into().expect("checked above"),
    ) as usize;

    let mut result = Vec::new();

    for seg_idx in 0..seg_count {
        let off_off = si_off + 4 + seg_idx * 4;
        if off_off + 4 > bytes.len() {
            break;
        }
        let seg_info_off = u32::from_le_bytes(
            bytes[off_off..off_off + 4].try_into().expect("checked above"),
        ) as usize;
        if seg_info_off == 0 {
            continue;
        }

        let ss_off = si_off + seg_info_off;
        if ss_off + 22 > bytes.len() {
            continue;
        }

        let page_size = u16::from_le_bytes(
            bytes[ss_off + 4..ss_off + 6].try_into().expect("checked"),
        ) as usize;
        let pointer_format = u16::from_le_bytes(
            bytes[ss_off + 6..ss_off + 8].try_into().expect("checked"),
        );
        let segment_offset = u64::from_le_bytes(
            bytes[ss_off + 8..ss_off + 16].try_into().expect("checked"),
        );
        let page_count = u16::from_le_bytes(
            bytes[ss_off + 20..ss_off + 22].try_into().expect("checked"),
        ) as usize;

        let is_offset_format = match pointer_format {
            6 => true,
            2 => false,
            _ => continue,
        };

        for p_idx in 0..page_count {
            let ps_off = ss_off + 22 + p_idx * 2;
            if ps_off + 2 > bytes.len() {
                break;
            }
            let page_start = u16::from_le_bytes(
                bytes[ps_off..ps_off + 2].try_into().expect("checked"),
            );
            const DYLD_CHAINED_PTR_START_NONE: u16 = 0xFFFF;
            if page_start == DYLD_CHAINED_PTR_START_NONE {
                continue;
            }

            let mut chain_off =
                segment_offset as usize + p_idx * page_size + page_start as usize;

            loop {
                if chain_off + 8 > bytes.len() {
                    break;
                }
                let val = u64::from_le_bytes(
                    bytes[chain_off..chain_off + 8]
                        .try_into()
                        .expect("checked above"),
                );

                let is_bind = (val >> 63) & 1 != 0;
                let next = ((val >> 51) & 0xFFF) as usize;

                if !is_bind {
                    let target_raw = val & 0xF_FFFF_FFFF; // bits[35:0]
                    let high8 = (val >> 36) & 0xFF;
                    let target_va = if is_offset_format {
                        Va::new((high8 << 56) | (preferred_base + target_raw))
                    } else {
                        Va::new((high8 << 56) | target_raw)
                    };
                    let slot_va = Va::new(preferred_base + chain_off as u64);

                    if seg_set.contains(target_va) {
                        result.push(RelocPointer {
                            from: slot_va,
                            to: target_va,
                        });
                    }
                }

                if next == 0 {
                    break;
                }
                chain_off += next * 4;
            }
        }
    }

    result
}
