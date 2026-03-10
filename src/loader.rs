use anyhow::{anyhow, Result};
use dylex::DyldContext;
use goblin::Object;
use memmap2::Mmap;
use std::any::Any;
use std::collections::HashMap;
use std::ops::Range;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    X86_64,
    Arm64,
    X86,
    Arm32,
    Unknown,
}

/// Decode mode — some architectures have multiple modes active simultaneously.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeMode {
    /// Normal mode (ARM64, x86, x86-64)
    Default,
    /// ARM Thumb (2-byte aligned, mixed 16/32-bit instructions)
    Thumb,
    /// ARM32 classic (4-byte aligned)
    Arm32,
}

/// A single mapped segment of the binary — executable or data.
/// Backed by a byte slice into the mmap'd file. Zero copy.
#[derive(Debug, Clone)]
pub struct Segment {
    /// Virtual address of the segment start.
    pub va: u64,
    /// Raw bytes — a slice into the mmap (zero-copy).
    pub data: &'static [u8],
    /// Whether this segment contains executable code.
    pub executable: bool,
    /// Whether this segment contains readable data.
    pub readable: bool,
    /// Whether this segment contains writable data.
    pub writable: bool,
    /// Whether this segment should be byte-scanned for pointer values.
    /// False for sections like `.data.rel.ro` which contain relocatable
    /// data that produces too many false-positive pointer hits without
    /// relocation-table context.
    pub byte_scannable: bool,
    /// Decode mode for this segment (relevant for ARM).
    pub mode: DecodeMode,
    /// Human-readable name (e.g. "__TEXT", ".text", "LOAD[0]").
    pub name: String,
}

impl Segment {
    /// Byte slice at a given virtual address range, if within this segment.
    pub fn bytes_at(&self, va: u64, len: usize) -> Option<&[u8]> {
        let offset = va.checked_sub(self.va)? as usize;
        self.data.get(offset..offset + len)
    }

    /// VA range covered by this segment.
    pub fn va_range(&self) -> Range<u64> {
        self.va..self.va + self.data.len() as u64
    }

    /// True if the given VA falls within this segment.
    pub fn contains(&self, va: u64) -> bool {
        self.va_range().contains(&va)
    }
}

/// A loaded binary — mmap'd file + parsed segment list.
/// The mmap is kept alive for the lifetime of this struct.
/// All segment data slices are zero-copy into the mmap.
pub struct LoadedBinary {
    /// Architecture detected from the binary.
    pub arch: Arch,
    /// All mapped segments (code + data).
    pub segments: Vec<Segment>,
    /// Entry points / known function seeds.
    pub entry_points: Vec<u64>,
    /// Exports / named symbols with their addresses.
    pub symbols: Vec<(String, u64)>,
    /// Non-zero if this is a PIE ELF that was rebased by the loader.
    /// All segment VAs, entry points, and symbols have already had this
    /// value added. 0 for non-PIE binaries and non-ELF formats.
    pub pie_base: u64,
    /// GOT slot VA → extern VA mapping.
    ///
    /// Maps rebased GOT slot VAs to the synthetic "extern segment" VAs that IDA
    /// assigns to undefined symbols, so indirect `CALL [RIP+got_slot]` (FF 15)
    /// and `JMP [RIP+got_slot]` (FF 25) xrefs can be emitted with correct targets.
    ///
    /// Populated by `build_elf_got_map` for ELF PIE binaries.  Empty for Mach-O,
    /// PE, and non-PIE ELF (where GOT-indirect calls target resolved addresses).
    pub got_map: HashMap<u64, u64>,
    /// The underlying mmap — kept alive here.
    _mmap: Mmap,
    /// Zero-filled BSS buffers allocated by the loader.
    /// Kept alive here so the `&'static [u8]` slices in `segments` remain valid.
    /// Dropped after `segments` (struct fields drop in declaration order).
    _bss_bufs: Vec<Box<[u8]>>,
    /// For dyld shared caches: the DyldContext (owns the subcache mmaps).
    /// Segment slices borrow from these mmaps zero-copy.
    /// Must be dropped AFTER `segments` — field order guarantees this.
    _dyld_ctx: Option<Box<dyn Any + Send + Sync>>,
}

impl LoadedBinary {
    /// Load a binary from disk. Mmap's the file, parses segments.
    /// Returns a `LoadedBinary` whose segment slices are zero-copy into the mmap.
    /// Supports ELF, single-arch Mach-O, and PE. Fat (universal) Mach-O binaries
    /// are not supported — extract the desired arch slice first (e.g. with `lipo`).
    pub fn load(path: &Path) -> Result<Self> {
        Self::load_with_base(path, None)
    }

    /// Like `load`, but allows overriding the base VA for PIE ELF binaries.
    ///
    /// `base` is the virtual address at which the binary's first PT_LOAD segment
    /// (the one with `p_vaddr == 0`) is assumed to be mapped.  For non-PIE ELF,
    /// Mach-O, and PE binaries the preferred base is already baked into the binary
    /// and `base` is ignored.
    ///
    /// When `base` is `None` the default PIE base (`0x0040_0000`) is used, which
    /// matches IDA's default load address for Linux PIE ELF shared libraries.
    pub fn load_with_base(path: &Path, base: Option<u64>) -> Result<Self> {
        let file = std::fs::File::open(path)?;
        let mmap = unsafe { Mmap::map(&file)? };

        // Detect dyld shared cache by magic prefix before handing off to goblin.
        // The magic is "dyld_v1 " followed by the arch name (e.g. "arm64e", "x86_64h").
        if mmap.starts_with(b"dyld_v1 ") {
            let (arch, segments, entry_points, symbols, pie_base, got_map, dyld_ctx) =
                parse_dyld_cache(path)?;
            // Segment slices are zero-copy into dyld_ctx's mmaps.
            // dyld_ctx is stored here and dropped after segments (field order).
            return Ok(LoadedBinary {
                arch,
                segments,
                entry_points,
                symbols,
                pie_base,
                got_map,
                _mmap: mmap,
                _bss_bufs: vec![],
                _dyld_ctx: Some(Box::new(dyld_ctx)),
            });
        }

        // We extend the lifetime of the mmap slice to 'static so we can
        // hand out segment slices that outlive the local `mmap` borrow.
        // Safety: `_mmap` is stored in the returned struct and never dropped
        // before the segments — the Vec<Segment> is dropped first.
        let bytes: &'static [u8] = unsafe { std::slice::from_raw_parts(mmap.as_ptr(), mmap.len()) };

        let mut bss_bufs: Vec<Box<[u8]>> = Vec::new();
        let (arch, segments, entry_points, symbols, pie_base, got_map) =
            parse_binary(bytes, &mut bss_bufs, base)?;

        Ok(LoadedBinary {
            arch,
            segments,
            entry_points,
            symbols,
            pie_base,
            got_map,
            _mmap: mmap,
            _bss_bufs: bss_bufs,
            _dyld_ctx: None,
        })
    }

    /// Construct a LoadedBinary directly from segments, for use in tests.
    #[cfg(test)]
    pub fn from_segments(arch: Arch, segments: Vec<Segment>) -> Self {
        use std::io::Write;
        // mmap requires a non-empty file-backed region on macOS.
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(&[0u8]).unwrap();
        let mmap = unsafe { memmap2::Mmap::map(tmp.as_file()).unwrap() };
        Self {
            arch,
            segments,
            entry_points: vec![],
            symbols: vec![],
            pie_base: 0,
            got_map: HashMap::new(),
            _mmap: mmap,
            _bss_bufs: vec![],
            _dyld_ctx: None,
        }
    }

    /// Find the segment containing a given virtual address.
    pub fn segment_at(&self, va: u64) -> Option<&Segment> {
        self.segments.iter().find(|s| s.contains(va))
    }

    /// True if the given VA is in any mapped segment.
    pub fn is_mapped(&self, va: u64) -> bool {
        self.segment_at(va).is_some()
    }

    /// True if the given VA is in an executable segment.
    pub fn is_executable(&self, va: u64) -> bool {
        self.segment_at(va).is_some_and(|s| s.executable)
    }

    /// All executable segments.
    pub fn code_segments(&self) -> impl Iterator<Item = &Segment> {
        self.segments.iter().filter(|s| s.executable)
    }

    /// All data (non-executable) segments.
    pub fn data_segments(&self) -> impl Iterator<Item = &Segment> {
        self.segments.iter().filter(|s| !s.executable && s.readable)
    }

    /// All segments worth byte-scanning for pointers.
    /// Excludes executable segments and segments marked as not byte-scannable
    /// (e.g. `.data.rel.ro` which has a very high FP rate without relocation
    /// context). Only non-executable, readable, byte_scannable segments
    /// (.data, .bss, .got, etc.) are scanned.
    pub fn scannable_data_segments(&self) -> impl Iterator<Item = &Segment> {
        self.segments
            .iter()
            .filter(|s| s.readable && !s.executable && s.byte_scannable)
    }

    /// Lowest virtual address of any mapped segment.
    /// Useful as a minimum bound for filtering out-of-range ref targets.
    pub fn min_va(&self) -> u64 {
        self.segments.iter().map(|s| s.va).min().unwrap_or(0)
    }
}

/// Return type shared by all binary-format parsers.
/// Tuple: (arch, segments, entry_points, symbols, pie_base, got_map).
/// pie_base is non-zero only for PIE ELF binaries rebased by parse_elf.
/// got_map is populated by build_elf_got_map for PIE ELF; empty for other formats.
type ParseResult = Result<(
    Arch,
    Vec<Segment>,
    Vec<u64>,
    Vec<(String, u64)>,
    u64,
    HashMap<u64, u64>,
)>;

/// Allocate a zero-filled buffer of `size` bytes, store it in `bufs` for
/// lifetime management, and return a `&'static [u8]` into it.
///
/// Safety: the returned slice is valid as long as the owning `bufs` Vec
/// (and thus `LoadedBinary::_bss_bufs`) is alive — same drop-order guarantee
/// as `LoadedBinary::_mmap` for the mmap-backed slices.
fn alloc_bss(size: usize, bufs: &mut Vec<Box<[u8]>>) -> &'static [u8] {
    let buf: Box<[u8]> = vec![0u8; size].into_boxed_slice();
    let ptr = buf.as_ptr();
    bufs.push(buf);
    // Safety: ptr points into the Box we just pushed, which lives in `bufs`
    // (ultimately in `LoadedBinary::_bss_bufs`). The struct drops `_bss_bufs`
    // after `segments`, so the slice outlives all Segment references.
    unsafe { std::slice::from_raw_parts(ptr, size) }
}

fn parse_binary(
    bytes: &'static [u8],
    bss_bufs: &mut Vec<Box<[u8]>>,
    base: Option<u64>,
) -> ParseResult {
    match Object::parse(bytes)? {
        Object::Elf(elf) => parse_elf(bytes, &elf, bss_bufs, base),
        Object::Mach(goblin::mach::Mach::Binary(macho)) => parse_macho(bytes, &macho, bss_bufs),
        Object::Mach(goblin::mach::Mach::Fat(_)) => {
            Err(anyhow!("fat (universal) Mach-O binaries are not supported; extract the desired arch slice first (e.g. with `lipo -extract`)"))
        }
        Object::PE(pe) => parse_pe(bytes, &pe, bss_bufs),
        Object::Unknown(_) => {
            // Raw binary — treat as flat, unknown arch
            let seg = Segment {
                va: 0,
                data: bytes,
                executable: true,
                readable: true,
                writable: false,
                mode: DecodeMode::Default,
                name: "raw".to_string(),
                byte_scannable: true,
            };
            Ok((Arch::Unknown, vec![seg], vec![0], vec![], 0, HashMap::new()))
        }
        _ => Err(anyhow!("unsupported binary format")),
    }
}

// ── dyld shared cache ─────────────────────────────────────────────────────────

/// Extended return type for dyld cache: includes the DyldContext so the caller
/// can store it and keep the mmaps alive for the lifetime of the segments.
type DyldParseResult = Result<(
    Arch,
    Vec<Segment>,
    Vec<u64>,
    Vec<(String, u64)>,
    u64,
    HashMap<u64, u64>,
    DyldContext,
)>;

fn parse_dyld_cache(path: &Path) -> DyldParseResult {
    let ctx =
        DyldContext::open(path).map_err(|e| anyhow!("failed to open dyld shared cache: {e}"))?;

    // Arch from the magic string: "dyld_v1  arm64e", "dyld_v1  x86_64h", etc.
    let arch = match ctx.architecture() {
        a if a.starts_with("arm64") => Arch::Arm64,
        a if a.starts_with("x86_64") => Arch::X86_64,
        a if a.starts_with("i386") => Arch::X86,
        a => {
            eprintln!("warning: unknown dyld cache arch '{a}', treating as unknown");
            Arch::Unknown
        }
    };

    eprintln!(
        "dyld shared cache: arch={arch:?}  mappings={}  images={}  subcaches={}",
        ctx.mappings.len(),
        ctx.image_count(),
        ctx.subcaches.len(),
    );

    let mut segments = Vec::new();

    for mapping in &ctx.mappings {
        if mapping.size == 0 {
            continue;
        }

        // Zero-copy: slice directly into the DyldContext's mmap(s).
        // Safety: ctx is moved into LoadedBinary::_dyld_ctx and lives at least
        // as long as the segments Vec — field declaration order guarantees
        // _dyld_ctx is dropped after segments.
        let data: &'static [u8] = match ctx.data_at_addr(mapping.address, mapping.size as usize) {
            Ok(slice) => unsafe { std::slice::from_raw_parts(slice.as_ptr(), slice.len()) },
            Err(e) => {
                eprintln!(
                    "warning: skipping mapping {:#x}+{:#x}: {e}",
                    mapping.address, mapping.size
                );
                continue;
            }
        };

        segments.push(Segment {
            va: mapping.address,
            data,
            executable: mapping.is_executable(),
            readable: mapping.is_readable(),
            writable: mapping.is_writable(),
            byte_scannable: mapping.is_readable() && !mapping.is_executable(),
            mode: DecodeMode::Default,
            name: format!("DSC[{:#x}]", mapping.address),
        });
    }

    if segments.is_empty() {
        return Err(anyhow!("dyld shared cache: no usable mappings found"));
    }

    Ok((arch, segments, vec![], vec![], 0, HashMap::new(), ctx))
}

fn parse_elf(
    bytes: &'static [u8],
    elf: &goblin::elf::Elf,
    bss_bufs: &mut Vec<Box<[u8]>>,
    base_override: Option<u64>,
) -> ParseResult {
    let arch = match elf.header.e_machine {
        goblin::elf::header::EM_X86_64 => Arch::X86_64,
        goblin::elf::header::EM_AARCH64 => Arch::Arm64,
        goblin::elf::header::EM_386 => Arch::X86,
        goblin::elf::header::EM_ARM => Arch::Arm32,
        m => {
            eprintln!("warning: unknown ELF e_machine {m:#x}, treating as unknown");
            Arch::Unknown
        }
    };

    // Sections that should NOT be byte-scanned for pointers.
    // .data.rel.ro contains compiler-generated relocation tables; without
    // relocation-table context we cannot distinguish actual pointers from
    // array indices, offsets, and other in-range integer values — producing
    // a ~5-29x FP:TP ratio in benchmarks.
    const NO_SCAN_SECTIONS: &[&str] = &[".data.rel.ro", ".data.rel.ro.local"];

    // Sections that are NOT machine code, even when they appear in an exec PT_LOAD.
    // On many ELF binaries the exec PT_LOAD (R-X) contains .text alongside .rodata,
    // .eh_frame_hdr, and .eh_frame. Treating those as code generates many false-positive
    // jump/call xrefs from random byte patterns decoded as instructions.
    const NON_CODE_SECTIONS: &[&str] = &[
        ".rodata",
        ".rodata1",
        ".eh_frame_hdr",
        ".eh_frame",
        ".gcc_except_table",
        ".note.gnu.build-id",
        ".note.ABI-tag",
    ];

    // Per-section metadata: VA range, file backing, and scan flags.
    // SHT_NOBITS (BSS) sections have no file bytes and are skipped here;
    // they are covered by the PT_LOAD memsz tail instead.
    struct SectionInfo {
        va: u64,
        end: u64,
        file_offset: usize,
        file_size: usize,
        name: String,
        /// False for .data.rel.ro and similar — too many FPs without reloc context.
        byte_scannable: bool,
        /// False for .rodata, .eh_frame* etc. — not machine code.
        is_code: bool,
    }
    let mut section_infos: Vec<SectionInfo> = Vec::new();
    for sh in &elf.section_headers {
        use goblin::elf::section_header::*;
        if sh.sh_type == SHT_NULL || sh.sh_type == SHT_NOBITS || sh.sh_addr == 0 || sh.sh_size == 0
        {
            continue;
        }
        if let Some(name) = elf.shdr_strtab.get_at(sh.sh_name) {
            section_infos.push(SectionInfo {
                va: sh.sh_addr,
                end: sh.sh_addr + sh.sh_size,
                file_offset: sh.sh_offset as usize,
                file_size: sh.sh_size as usize,
                name: name.to_string(),
                byte_scannable: !NO_SCAN_SECTIONS.contains(&name),
                is_code: !NON_CODE_SECTIONS.contains(&name),
            });
        }
    }
    section_infos.sort_by_key(|s| s.va);

    let mode = if arch == Arch::Arm32 {
        DecodeMode::Arm32
    } else {
        DecodeMode::Default
    };

    // PIE ELF detection: ET_DYN whose lowest-addressed PT_LOAD has p_vaddr == 0.
    // Such binaries are mapped by the OS/loader at a non-zero base; without
    // rebasing, small immediates (e.g. MOV rax, 1) fall in the same VA space
    // as real code and produce massive false-positive data_ptr xrefs.
    // We use the traditional Linux x86-64 / AArch64 PIE base: 0x0040_0000.
    //
    // We use .min() over the PT_LOAD p_vaddr values rather than .next() so that
    // out-of-order program headers (where a non-zero PT_LOAD appears before the
    // zero-based one in the file) still trigger rebasing correctly.
    use goblin::elf::header::ET_DYN;
    use goblin::elf::program_header::PT_LOAD;
    // Determine the base VA for PIE ELF binaries (ET_DYN with first PT_LOAD at 0).
    // base_override lets the caller specify an explicit load address; otherwise
    // the traditional Linux PIE base 0x0040_0000 is used (matches IDA default).
    let pie_base: u64 = if elf.header.e_type == ET_DYN {
        let min_load_va = elf
            .program_headers
            .iter()
            .filter(|ph| ph.p_type == PT_LOAD)
            .map(|ph| ph.p_vaddr)
            .min()
            .unwrap_or(1);
        if min_load_va == 0 {
            base_override.unwrap_or(0x0040_0000)
        } else {
            0
        }
    } else {
        0
    };

    // Apply pie_base to section VAs so that section-based segment building
    // below uses rebased addresses consistently.
    if pie_base != 0 {
        for si in &mut section_infos {
            si.va += pie_base;
            si.end += pie_base;
        }
    }

    let mut segments = Vec::new();
    for ph in &elf.program_headers {
        use goblin::elf::program_header::*;
        if ph.p_type != PT_LOAD {
            continue;
        }
        let exec = ph.p_flags & PF_X != 0;
        let read = ph.p_flags & PF_R != 0;
        let write = ph.p_flags & PF_W != 0;

        // Rebased VA of this PT_LOAD.
        let ph_va = ph.p_vaddr + pie_base;

        // For exec PT_LOADs with section info: emit one sub-segment per section.
        // This marks non-code sections (.rodata, .eh_frame*) as non-executable so
        // they are not instruction-scanned, while keeping them in the segment list
        // so that `in_any_segment()` still validates ADRP/LEA targets within them.
        if exec && !section_infos.is_empty() {
            let ph_va_start = ph_va;
            let ph_va_end = ph_va + ph.p_memsz;
            let secs: Vec<&SectionInfo> = section_infos
                .iter()
                .filter(|s| s.va >= ph_va_start && s.end <= ph_va_end)
                .collect();
            if !secs.is_empty() {
                for sec in &secs {
                    if sec.file_offset + sec.file_size > bytes.len() {
                        continue;
                    }
                    let data = &bytes[sec.file_offset..sec.file_offset + sec.file_size];
                    segments.push(Segment {
                        va: sec.va, // already rebased above
                        data,
                        // Only mark executable if the section is actual code.
                        executable: sec.is_code,
                        readable: read,
                        writable: write,
                        byte_scannable: sec.byte_scannable,
                        mode,
                        name: sec.name.clone(),
                    });
                }
                // BSS tail (memsz > last section end): zero-initialised coverage.
                let last_end = secs.iter().map(|s| s.end).max().unwrap_or(ph_va_end);
                if last_end < ph_va_end {
                    let bss_sz = (ph_va_end - last_end) as usize;
                    let bss_data: &'static [u8] = alloc_bss(bss_sz, bss_bufs);
                    segments.push(Segment {
                        va: last_end,
                        data: bss_data,
                        executable: false,
                        readable: read,
                        writable: write,
                        byte_scannable: false,
                        mode,
                        name: format!("BSS[{:#x}]", last_end),
                    });
                }
                // BSS tail handled above; skip the PT_LOAD-granular fallback.
                continue;
            }
        }

        // PT_LOAD-granular fallback: one segment per PT_LOAD (no section info,
        // or non-exec segments where section-splitting is not worth the complexity).
        // For data segments: mark non-scannable if they overlap any NO_SCAN section.
        if ph.p_filesz > 0 {
            let offset = ph.p_offset as usize;
            let filesz = ph.p_filesz as usize;
            if offset + filesz <= bytes.len() {
                let data = &bytes[offset..offset + filesz];
                // Non-scannable if this PT_LOAD overlaps any no-scan section range.
                let ph_va_end = ph_va + ph.p_filesz;
                let byte_scannable = !section_infos
                    .iter()
                    .any(|s| !s.byte_scannable && s.va < ph_va_end && s.end > ph_va);
                segments.push(Segment {
                    va: ph_va,
                    data,
                    executable: exec,
                    readable: read,
                    writable: write,
                    byte_scannable,
                    mode,
                    name: format!("LOAD[{:#x}]", ph_va),
                });
            }
        }

        // Zero-initialized BSS tail: memsz > filesz.
        // We represent it as an empty-data segment so that in_any_segment()
        // covers the full VA range (including .bss targets of ADRP pairs).
        // Nothing is scanned or decoded in this segment.
        if ph.p_memsz > ph.p_filesz {
            let bss_va = ph_va + ph.p_filesz;
            let bss_sz = (ph.p_memsz - ph.p_filesz) as usize;
            // Use a leak'd Box so the lifetime is 'static. Since BSS is
            // zero-initialized and we never write it, this is safe.
            let bss_data: &'static [u8] = alloc_bss(bss_sz, bss_bufs);
            segments.push(Segment {
                va: bss_va,
                data: bss_data,
                executable: false,
                readable: read,
                writable: write,
                byte_scannable: false, // BSS is all zeros — nothing to scan
                mode,
                name: format!("BSS[{:#x}]", bss_va),
            });
        }
    }

    let entry_points = if elf.entry != 0 {
        vec![elf.entry + pie_base]
    } else {
        vec![]
    };
    let mut symbols = Vec::new();
    for sym in &elf.syms {
        if sym.st_value == 0 {
            continue;
        }
        if let Some(name) = elf.strtab.get_at(sym.st_name) {
            if !name.is_empty() {
                // ARM Thumb symbols have LSB set — strip it for the address.
                // Apply pie_base after stripping the Thumb LSB.
                let addr = (sym.st_value & !1) + pie_base;
                symbols.push((name.to_string(), addr));
            }
        }
    }

    // GOT map (got_slot_va → extern_va): build for PIE ELF with dynamic relocations.
    //
    // IDA assigns synthetic "extern segment" VAs to all SHN_UNDEF non-TLS dynamic
    // symbols (STT_FUNC first by dynsym index, then others by dynsym index), then
    // records xrefs for indirect CALL/JMP through GOT slots that belong to those
    // symbols (FF 15 / FF 25 on x86-64; ADRP+LDR+BLR on AArch64).
    //
    // Algorithm (confirmed empirically, 0 mismatches on libharlem-shake.so):
    //   extern_base = max(PT_LOAD p_vaddr + p_memsz) + pie_base + 0x20
    //   Ordered = [STT_FUNC SHN_UNDEF sorted by dynsym_idx] ++ [others SHN_UNDEF sorted by dynsym_idx]
    //   (STT_TLS excluded; all others included even without GLOB_DAT/JUMP_SLOT relocs)
    //   extern_va[i] = extern_base + i * 8
    //   Map: got_slot_va = r_offset+pie_base → extern_va for each GLOB_DAT/JUMP_SLOT reloc
    let got_map = build_elf_got_map(elf, pie_base);

    Ok((arch, segments, entry_points, symbols, pie_base, got_map))
}

/// Build the GOT slot → extern VA mapping for an ELF binary.
///
/// IDA assigns synthetic "extern segment" VAs to imported symbols in this order
/// (verified empirically against IDA ground truth, 0 mismatches on libharlem-shake.so):
///
///   extern_base = max(PT_LOAD p_vaddr + p_memsz) + pie_base + 0x20
///
///   Collect ALL SHN_UNDEF symbols from .dynsym EXCEPT STT_TLS symbols.
///   Sort them: STT_FUNC symbols first (by dynsym index), then all others (by dynsym index).
///   Assign: extern_va[i] = extern_base + i * 8
///
///   For each SHN_UNDEF symbol that also has a GLOB_DAT / JUMP_SLOT relocation,
///   record got_slot_va → extern_va in the map.
///
/// Key properties:
/// - IDA includes SHN_UNDEF symbols regardless of whether they have a GOT reloc
///   (i.e., SHN_UNDEF symbols with only R_X86_64_64 / COPY / TPOFF relocs still
///   consume an extern segment slot and shift the indices of all following symbols).
/// - STT_TLS symbols are excluded from the extern segment.
/// - The GOT VA ordering used by build_got_map in prior sessions was wrong because
///   it ignored SHN_UNDEF symbols without GLOB_DAT/JUMP_SLOT relocs.
fn build_elf_got_map(elf: &goblin::elf::Elf, pie_base: u64) -> HashMap<u64, u64> {
    use goblin::elf::program_header::PT_LOAD;
    use goblin::elf::section_header::SHN_UNDEF;
    use goblin::elf::sym::{STT_FUNC, STT_TLS};

    // extern_base: one slot above the highest PT_LOAD end, plus 0x20 alignment pad.
    let extern_base = elf
        .program_headers
        .iter()
        .filter(|ph| ph.p_type == PT_LOAD)
        .map(|ph| ph.p_vaddr + ph.p_memsz)
        .max()
        .unwrap_or(0)
        + pie_base
        + 0x20;

    // Collect all SHN_UNDEF, non-STT_TLS symbols from .dynsym, by dynsym index.
    // We need the dynsym index (position in .dynsym) as the sort key.
    let mut func_syms: Vec<u32> = Vec::new(); // STT_FUNC SHN_UNDEF sym indices
    let mut other_syms: Vec<u32> = Vec::new(); // other SHN_UNDEF sym indices

    for (i, sym) in elf.dynsyms.iter().enumerate() {
        if sym.st_shndx != SHN_UNDEF as usize {
            continue;
        }
        if sym.st_type() == STT_TLS {
            continue;
        }
        // Skip the null symbol (index 0 in .dynsym always has an empty name).
        // IDA does not include it in the extern segment.
        if elf
            .dynstrtab
            .get_at(sym.st_name)
            .is_none_or(|n| n.is_empty())
        {
            continue;
        }
        if sym.st_type() == STT_FUNC {
            func_syms.push(i as u32);
        } else {
            other_syms.push(i as u32);
        }
    }

    // IDA sorts: STT_FUNC SHN_UNDEF first (by dynsym index), then all others (by dynsym index).
    // Both groups are already in ascending dynsym index order from the loop above.
    let ordered: Vec<u32> = func_syms.iter().chain(other_syms.iter()).copied().collect();

    if ordered.is_empty() {
        return HashMap::new();
    }

    // Build dynsym_index → extern_va assignment.
    let sym_to_extern: HashMap<u32, u64> = ordered
        .iter()
        .enumerate()
        .map(|(i, &sym_idx)| (sym_idx, extern_base + i as u64 * 8))
        .collect();

    // Relocation types that carry a GOT slot for an imported symbol.
    // x86-64: R_X86_64_GLOB_DAT (6), R_X86_64_JUMP_SLOT (7)
    // AArch64: R_AARCH64_GLOB_DAT (1025), R_AARCH64_JUMP_SLOT (1026)
    const R_X86_64_GLOB_DAT: u32 = 6;
    const R_X86_64_JUMP_SLOT: u32 = 7;
    const R_AARCH64_GLOB_DAT: u32 = 1025;
    const R_AARCH64_JUMP_SLOT: u32 = 1026;

    let is_got_reloc = |r_type: u32| {
        matches!(
            r_type,
            R_X86_64_GLOB_DAT | R_X86_64_JUMP_SLOT | R_AARCH64_GLOB_DAT | R_AARCH64_JUMP_SLOT
        )
    };

    // For each GLOB_DAT/JUMP_SLOT reloc referencing an SHN_UNDEF symbol,
    // map got_slot_va → extern_va.
    elf.dynrelas
        .iter()
        .chain(elf.dynrels.iter())
        .chain(elf.pltrelocs.iter())
        .filter_map(|rel| {
            if !is_got_reloc(rel.r_type) || rel.r_sym == 0 {
                return None;
            }
            let extern_va = sym_to_extern.get(&(rel.r_sym as u32))?;
            let got_va = rel.r_offset + pie_base;
            Some((got_va, *extern_va))
        })
        .collect()
}

fn parse_macho(
    bytes: &'static [u8],
    macho: &goblin::mach::MachO,
    bss_bufs: &mut Vec<Box<[u8]>>,
) -> ParseResult {
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

    // Mach-O sections that should NOT be byte-scanned for pointers.
    //
    // `__DATA_CONST,__got` / `__DATA,__got` — GOT entries are relocatable slot VAs,
    //   not real pointers; without dyld fixup-chain context they produce many FPs.
    // `__DATA_CONST,__auth_got` — same as __got but pointer-authenticated (AArch64).
    // `__DATA,__la_symbol_ptr` / `__DATA,__nl_symbol_ptr` — lazy/non-lazy pointer
    //   tables; same FP issue as GOT.
    // `__DATA_CONST,__cfstring` / `__DATA,__cfstring` — CFString structures embed
    //   compile-time layout offsets that coincidentally look like mapped VAs.
    //
    // These mirror ELF's NO_SCAN_SECTIONS (`.data.rel.ro`, `.data.rel.ro.local`).
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
        // Each Mach-O section within the segment
        for section in seg.sections().map_err(|e| anyhow::anyhow!("{e:?}"))? {
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
                // S_ZEROFILL / S_GB_ZEROFILL / S_THREAD_LOCAL_ZEROFILL:
                // goblin returns an empty slice; allocate a zero-filled backing
                // so in_any_segment() covers these VAs. Byte-scanning all-zeros
                // produces no hits (target==0 is filtered), so no FP cost.
                alloc_bss(size, bss_bufs)
            } else {
                // File-backed section: slice directly into the mmap.
                let file_offset = sect.offset as usize;
                if file_offset + size > bytes.len() {
                    continue;
                }
                &bytes[file_offset..file_offset + size]
            };

            segments.push(Segment {
                va: sect.addr,
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

    let entry_points = vec![macho.entry];
    let mut symbols = Vec::new();
    if let Some(syms) = macho.symbols.as_ref() {
        for (name, nlist) in syms.iter().flatten() {
            if !name.is_empty() && nlist.n_value != 0 {
                symbols.push((name.to_string(), nlist.n_value));
            }
        }
    }

    Ok((arch, segments, entry_points, symbols, 0, HashMap::new()))
}

fn parse_pe(
    bytes: &'static [u8],
    pe: &goblin::pe::PE,
    bss_bufs: &mut Vec<Box<[u8]>>,
) -> ParseResult {
    use goblin::pe::header::*;

    let arch = match pe.header.coff_header.machine {
        COFF_MACHINE_X86_64 => Arch::X86_64,
        COFF_MACHINE_X86 => Arch::X86,
        COFF_MACHINE_ARM64 => Arch::Arm64,
        COFF_MACHINE_ARMNT => Arch::Arm32,
        m => {
            eprintln!("warning: unknown PE machine {m:#x}, treating as unknown");
            Arch::Unknown
        }
    };

    let image_base = pe.image_base as u64;
    let mut segments = Vec::new();

    for section in &pe.sections {
        use goblin::pe::section_table::*;
        let raw_offset = section.pointer_to_raw_data as usize;
        let raw_size = section.size_of_raw_data as usize;
        let virt_size = section.virtual_size as usize;
        let chars = section.characteristics;
        let exec = chars & IMAGE_SCN_MEM_EXECUTE != 0;
        let read = chars & IMAGE_SCN_MEM_READ != 0;
        let write = chars & IMAGE_SCN_MEM_WRITE != 0;
        let va = image_base + section.virtual_address as u64;
        let name = section.name().unwrap_or("?").to_string();

        // DWARF debug sections (goblin resolves COFF long-name offsets like "/35"
        // to their real names, e.g. ".debug_info"). They contain raw code addresses
        // as debug metadata — not real xrefs. Register for VA coverage but skip scanning.
        let is_debug = name.starts_with(".debug_");
        if is_debug {
            if raw_size > 0 && raw_offset + raw_size <= bytes.len() {
                segments.push(Segment {
                    va,
                    data: &bytes[raw_offset..raw_offset + raw_size],
                    executable: exec,
                    readable: read,
                    writable: write,
                    mode: DecodeMode::Default,
                    name,
                    byte_scannable: false,
                });
            }
            continue;
        }

        if raw_size == 0 {
            // BSS-like section: SizeOfRawData=0 but VirtualSize > 0.
            // Allocate a zero-filled backing so in_any_segment() covers these
            // VAs. Byte-scanning all-zeros produces no hits (target==0 filtered).
            if virt_size == 0 {
                continue;
            }
            let bss_data: &'static [u8] = alloc_bss(virt_size, bss_bufs);
            segments.push(Segment {
                va,
                data: bss_data,
                executable: exec,
                readable: read,
                writable: write,
                mode: DecodeMode::Default,
                name,
                byte_scannable: false,
            });
            continue;
        }

        if raw_offset + raw_size > bytes.len() {
            continue;
        }
        let data = &bytes[raw_offset..raw_offset + raw_size];

        // If VirtualSize > SizeOfRawData, the tail is BSS (zero-initialized).
        // Add the BSS segment BEFORE moving name into the file-backed segment.
        if virt_size > raw_size {
            let bss_va = va + raw_size as u64;
            let bss_sz = virt_size - raw_size;
            let bss_data: &'static [u8] = alloc_bss(bss_sz, bss_bufs);
            segments.push(Segment {
                va: bss_va,
                data: bss_data,
                executable: exec,
                readable: read,
                writable: write,
                mode: DecodeMode::Default,
                name: format!("{name}[bss]"),
                byte_scannable: false,
            });
        }

        segments.push(Segment {
            va,
            data,
            executable: exec,
            readable: read,
            writable: write,
            mode: DecodeMode::Default,
            name,
            byte_scannable: true,
        });
    }

    let entry_points = if pe.entry != 0 {
        vec![image_base + pe.entry as u64]
    } else {
        vec![]
    };

    let mut symbols = Vec::new();
    for export in &pe.exports {
        if let Some(name) = export.name {
            symbols.push((name.to_string(), image_base + export.rva as u64));
        }
    }

    Ok((arch, segments, entry_points, symbols, 0, HashMap::new()))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Build a minimal valid 64-bit PIE ELF (ET_DYN, EM_X86_64) with a single
    /// PT_LOAD at p_vaddr=0 and a .text section at raw vaddr 0x1000.
    /// Written to a tempfile and passed to `LoadedBinary::load_with_base` in tests.
    fn make_minimal_pie_elf() -> Vec<u8> {
        // File layout:
        //   0x00..0x40   ELF header (Ehdr64, 64 bytes)
        //   0x40..0x78   Program header (Phdr64, 56 bytes)
        //   0x78..0x80   .shstrtab content: b"\x00.text\x00" (8 bytes)
        //   0x80..0xc0   .text: 64 zero bytes
        //   0xc0..0x180  Section header table: 3 × Shdr64 (64 bytes each)

        let shstrtab_off: u64 = 0x78;
        let shstrtab_content: &[u8] = b"\x00.text\x00";
        let shstrtab_size = shstrtab_content.len() as u64;

        let text_off: u64 = shstrtab_off + shstrtab_size; // 0x80
        let text_size: u64 = 64;
        // text_vaddr == text_off: the section lives at file offset 0x80, and
        // since p_vaddr=0 / p_offset=0 the raw vaddr equals the file offset.
        // This places it squarely within the PT_LOAD's [0, file_size) range.
        let text_vaddr: u64 = text_off; // 0x80

        let shoff: u64 = text_off + text_size; // 0xc0
        let file_size: u64 = shoff + 3 * 64; // 0x180

        let mut buf = vec![0u8; file_size as usize];

        // Helper: write `n` LE bytes of `val` at offset `off`.
        fn w(buf: &mut [u8], off: usize, val: u64, n: usize) {
            buf[off..off + n].copy_from_slice(&val.to_le_bytes()[..n]);
        }

        // ── ELF header ────────────────────────────────────────────────────────
        buf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        buf[4] = 2; // ELFCLASS64
        buf[5] = 1; // ELFDATA2LSB
        buf[6] = 1; // EV_CURRENT

        let h = 16usize; // start of fields after e_ident
        w(&mut buf, h, 3, 2); // e_type = ET_DYN
        w(&mut buf, h + 2, 62, 2); // e_machine = EM_X86_64
        w(&mut buf, h + 4, 1, 4); // e_version
        w(&mut buf, h + 8, 0, 8); // e_entry
        w(&mut buf, h + 16, 0x40, 8); // e_phoff
        w(&mut buf, h + 24, shoff, 8); // e_shoff
        w(&mut buf, h + 32, 0, 4); // e_flags
        w(&mut buf, h + 36, 64, 2); // e_ehsize
        w(&mut buf, h + 38, 56, 2); // e_phentsize
        w(&mut buf, h + 40, 1, 2); // e_phnum
        w(&mut buf, h + 42, 64, 2); // e_shentsize
        w(&mut buf, h + 44, 3, 2); // e_shnum
        w(&mut buf, h + 46, 1, 2); // e_shstrndx = 1 (.shstrtab)

        // ── PT_LOAD at p_vaddr=0 (PIE) ────────────────────────────────────────
        let ph = 0x40usize;
        w(&mut buf, ph, 1, 4); // p_type = PT_LOAD
        w(&mut buf, ph + 4, 0x5, 4); // p_flags = PF_R|PF_X
        w(&mut buf, ph + 8, 0, 8); // p_offset = 0
        w(&mut buf, ph + 16, 0, 8); // p_vaddr = 0  ← PIE
        w(&mut buf, ph + 24, 0, 8); // p_paddr
        w(&mut buf, ph + 32, file_size, 8); // p_filesz
        w(&mut buf, ph + 40, file_size, 8); // p_memsz
        w(&mut buf, ph + 48, 0x1000, 8); // p_align

        // ── .shstrtab ─────────────────────────────────────────────────────────
        buf[shstrtab_off as usize..shstrtab_off as usize + shstrtab_content.len()]
            .copy_from_slice(shstrtab_content);

        // ── Section 0: null (all zeros) ───────────────────────────────────────

        // ── Section 1: .shstrtab ──────────────────────────────────────────────
        let s1 = shoff as usize + 64;
        w(&mut buf, s1, 0, 4); // sh_name = 0 (empty — minimal)
        w(&mut buf, s1 + 4, 3, 4); // sh_type = SHT_STRTAB
        w(&mut buf, s1 + 8, 0, 8); // sh_flags (not SHF_ALLOC — not runtime-mapped)
        w(&mut buf, s1 + 16, 0, 8); // sh_addr = 0 (not mapped, parse_elf skips sh_addr==0)
        w(&mut buf, s1 + 24, shstrtab_off, 8); // sh_offset
        w(&mut buf, s1 + 32, shstrtab_size, 8); // sh_size
        w(&mut buf, s1 + 48, 1, 8); // sh_addralign

        // ── Section 2: .text ──────────────────────────────────────────────────
        let s2 = shoff as usize + 128;
        w(&mut buf, s2, 1, 4); // sh_name = 1 → ".text" in shstrtab
        w(&mut buf, s2 + 4, 1, 4); // sh_type = SHT_PROGBITS
        w(&mut buf, s2 + 8, 0x6, 8); // sh_flags = SHF_ALLOC|SHF_EXECINSTR
        w(&mut buf, s2 + 16, text_vaddr, 8); // sh_addr = 0x1000 (raw, pre-rebase)
        w(&mut buf, s2 + 24, text_off, 8); // sh_offset
        w(&mut buf, s2 + 32, text_size, 8); // sh_size
        w(&mut buf, s2 + 48, 0x10, 8); // sh_addralign

        buf
    }

    fn write_tmp(bytes: &[u8]) -> tempfile::NamedTempFile {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(bytes).unwrap();
        tmp.flush().unwrap();
        tmp
    }

    /// Load the same ELF at three different bases and check that every segment
    /// VA is exactly `pie_base` more than the corresponding raw-base VA.
    /// This tests the core rebasing invariant without depending on exact layout
    /// offsets that would have to be kept in sync with make_minimal_pie_elf.
    fn segment_vas(elf: &[u8], base: Option<u64>) -> Vec<u64> {
        let tmp = write_tmp(elf);
        let bin = LoadedBinary::load_with_base(tmp.path(), base).unwrap();
        let mut vas: Vec<u64> = bin.segments.iter().map(|s| s.va).collect();
        vas.sort_unstable();
        vas
    }

    /// Default load uses 0x400000 as the PIE base.
    #[test]
    fn test_load_pie_default_base() {
        let elf = make_minimal_pie_elf();
        let tmp = write_tmp(&elf);
        let binary = LoadedBinary::load(tmp.path()).unwrap();
        assert_eq!(binary.pie_base, 0x0040_0000);
        // Every segment VA must be >= pie_base (they were raw-vaddr=0 or small offsets).
        assert!(
            binary.segments.iter().all(|s| s.va >= 0x0040_0000),
            "all segment VAs should be rebased above 0x400000, got: {:?}",
            binary.segments.iter().map(|s| s.va).collect::<Vec<_>>()
        );
    }

    /// Overriding base to 0 leaves VAs unrelocated (raw file VAs).
    #[test]
    fn test_load_pie_base_zero() {
        let elf = make_minimal_pie_elf();
        let raw_vas = segment_vas(&elf, Some(0));
        let tmp = write_tmp(&elf);
        let binary = LoadedBinary::load_with_base(tmp.path(), Some(0)).unwrap();
        assert_eq!(binary.pie_base, 0);
        // With base=0 segment VAs equal the raw (unrelocated) values.
        let mut got: Vec<u64> = binary.segments.iter().map(|s| s.va).collect();
        got.sort_unstable();
        assert_eq!(got, raw_vas, "base=0 should not shift VAs");
    }

    /// Overriding base applies an exact shift to every segment VA.
    #[test]
    fn test_load_pie_custom_base() {
        let elf = make_minimal_pie_elf();
        let raw_vas = segment_vas(&elf, Some(0));
        let custom_base = 0x7f00_0000u64;
        let tmp = write_tmp(&elf);
        let binary = LoadedBinary::load_with_base(tmp.path(), Some(custom_base)).unwrap();
        assert_eq!(binary.pie_base, custom_base);
        let mut got: Vec<u64> = binary.segments.iter().map(|s| s.va).collect();
        got.sort_unstable();
        let expected: Vec<u64> = raw_vas.iter().map(|v| v + custom_base).collect();
        assert_eq!(
            got, expected,
            "custom base should shift all VAs by exactly custom_base"
        );
    }

    /// Different base values produce consistently shifted VAs relative to each other.
    #[test]
    fn test_load_pie_base_shift_consistency() {
        let elf = make_minimal_pie_elf();
        let base_a = 0x0040_0000u64;
        let base_b = 0x0080_0000u64;
        let vas_a = segment_vas(&elf, Some(base_a));
        let vas_b = segment_vas(&elf, Some(base_b));
        assert_eq!(vas_a.len(), vas_b.len(), "same number of segments");
        let delta = base_b - base_a;
        for (a, b) in vas_a.iter().zip(vas_b.iter()) {
            assert_eq!(b - a, delta, "VA shift mismatch: {a:#x} vs {b:#x}");
        }
    }
}
