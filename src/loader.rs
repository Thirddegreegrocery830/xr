use crate::va::Va;
use anyhow::{anyhow, Result};
use dylex::DyldContext;
use goblin::Object;
use memmap2::Mmap;
use std::any::Any;
use std::collections::HashSet;
use std::ops::Range;
use std::path::Path;

/// Default PIE base for ET_DYN ELF binaries whose lowest PT_LOAD has `p_vaddr == 0`.
/// Matches the traditional Linux x86-64 / AArch64 PIE base and IDA default.
const DEFAULT_PIE_BASE: u64 = 0x0040_0000;

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
#[derive(Debug)]
pub struct Segment {
    /// Virtual address of the segment start.
    pub va: Va,
    /// Raw bytes — a slice into the mmap (zero-copy).
    ///
    /// `pub(crate)` instead of `pub`: the `&'static` lifetime is a lie — the
    /// backing allocation (mmap / `_bss_bufs`) lives only as long as
    /// `LoadedBinary`. The public [`data()`](Segment::data) accessor returns
    /// `&[u8]` tied to `&self`, preventing callers from holding the slice
    /// beyond the segment's lifetime.
    pub(crate) data: &'static [u8],
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
    /// Raw byte data backing this segment.
    ///
    /// The returned reference is tied to `&self` rather than being `'static`,
    /// so callers cannot outlive the owning [`LoadedBinary`].
    pub fn data(&self) -> &[u8] {
        self.data
    }

    /// Byte slice at a given virtual address range, if within this segment.
    pub fn bytes_at(&self, va: Va, len: usize) -> Option<&[u8]> {
        let offset = va.raw().checked_sub(self.va.raw())? as usize;
        self.data.get(offset..offset + len)
    }

    /// VA range covered by this segment.
    pub fn va_range(&self) -> Range<Va> {
        self.va..self.va + self.data.len() as u64
    }

    /// True if the given VA falls within this segment.
    pub fn contains(&self, va: Va) -> bool {
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
    pub entry_points: Vec<Va>,
    /// Exports / named symbols with their addresses.
    pub symbols: Vec<(String, Va)>,
    /// Non-zero if this is a PIE ELF that was rebased by the loader.
    /// All segment VAs, entry points, and symbols have already had this
    /// value added. 0 for non-PIE binaries and non-ELF formats.
    pub pie_base: u64,
    /// Set of GOT slot VAs (from GLOB_DAT / JUMP_SLOT relocations).
    ///
    /// Used by the x86-64 scanner to restrict `CALL [RIP+disp32]` /
    /// `JMP [RIP+disp32]` xref emission to actual import-GOT slots
    /// (vs arbitrary RIP-relative indirect calls through non-GOT pointers).
    /// Populated for ELF binaries; empty for Mach-O and PE.
    pub got_slots: HashSet<Va>,
    /// Relocation-derived pointer pairs `(from_va, to_va)`.
    ///
    /// Each entry represents a pointer-sized slot at `from_va` that the
    /// relocation table says points to `to_va`.  Emitted as `DataPointer`
    /// xrefs in the scan pass.  Populated from ELF `.rela.dyn` / `.rel.dyn`
    /// (R_*_RELATIVE, R_*_64, R_*_ABS64) and PE base relocations + IAT.
    /// Empty for formats without relocation tables.
    pub reloc_pointers: Vec<(Va, Va)>,
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
            let result = parse_dyld_cache(path)?;
            let p = result.parsed;
            // Segment slices are zero-copy into dyld_ctx's mmaps.
            // dyld_ctx is stored here and dropped after segments (field order).
            return Ok(LoadedBinary {
                arch: p.arch,
                segments: p.segments,
                entry_points: p.entry_points,
                symbols: p.symbols,
                pie_base: p.pie_base,
                got_slots: p.got_slots,
                reloc_pointers: p.reloc_pointers,
                _mmap: mmap,
                _bss_bufs: vec![],
                _dyld_ctx: Some(Box::new(result.dyld_ctx)),
            });
        }

        // We extend the lifetime of the mmap slice to 'static so we can
        // hand out segment slices that outlive the local `mmap` borrow.
        // Safety: `_mmap` is stored in the returned struct and never dropped
        // before the segments — the Vec<Segment> is dropped first.
        let bytes: &'static [u8] = unsafe { std::slice::from_raw_parts(mmap.as_ptr(), mmap.len()) };

        let mut bss_bufs: Vec<Box<[u8]>> = Vec::new();
        let p = parse_binary(bytes, &mut bss_bufs, base)?;

        Ok(LoadedBinary {
            arch: p.arch,
            segments: p.segments,
            entry_points: p.entry_points,
            symbols: p.symbols,
            pie_base: p.pie_base,
            got_slots: p.got_slots,
            reloc_pointers: p.reloc_pointers,
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
            got_slots: HashSet::new(),
            reloc_pointers: Vec::new(),
            _mmap: mmap,
            _bss_bufs: vec![],
            _dyld_ctx: None,
        }
    }

    /// Find the segment containing a given virtual address.
    pub fn segment_at(&self, va: Va) -> Option<&Segment> {
        self.segments.iter().find(|s| s.contains(va))
    }

    /// True if the given VA is in any mapped segment.
    pub fn is_mapped(&self, va: Va) -> bool {
        self.segment_at(va).is_some()
    }

    /// True if the given VA is in an executable segment.
    pub fn is_executable(&self, va: Va) -> bool {
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
    pub fn min_va(&self) -> Va {
        self.segments.iter().map(|s| s.va).min().unwrap_or(Va::ZERO)
    }
}

/// Return type shared by all binary-format parsers.
/// Result of parsing a binary format (ELF, Mach-O, PE).
struct ParseResult {
    arch: Arch,
    segments: Vec<Segment>,
    entry_points: Vec<Va>,
    symbols: Vec<(String, Va)>,
    /// Non-zero only for PIE ELF binaries rebased by `parse_elf`.
    pie_base: u64,
    /// GOT slot VAs from GLOB_DAT / JUMP_SLOT relocs. Empty for non-ELF.
    got_slots: HashSet<Va>,
    /// Relocation-derived pointer pairs `(from_va, to_va)`.
    reloc_pointers: Vec<(Va, Va)>,
}

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
) -> Result<ParseResult> {
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
                va: Va::ZERO,
                data: bytes,
                executable: true,
                readable: true,
                writable: false,
                mode: DecodeMode::Default,
                name: "raw".to_string(),
                byte_scannable: true,
            };
            Ok(ParseResult {
                arch: Arch::Unknown,
                segments: vec![seg],
                entry_points: vec![Va::ZERO],
                symbols: vec![],
                pie_base: 0,
                got_slots: HashSet::new(),
                reloc_pointers: Vec::new(),
            })
        }
        _ => Err(anyhow!("unsupported binary format")),
    }
}

// ── dyld shared cache ─────────────────────────────────────────────────────────

/// Extended return type for dyld cache: includes the DyldContext so the caller
/// can store it and keep the mmaps alive for the lifetime of the segments.
struct DyldParseResult {
    parsed: ParseResult,
    dyld_ctx: DyldContext,
}

fn parse_dyld_cache(path: &Path) -> Result<DyldParseResult> {
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
            va: Va(mapping.address),
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

    Ok(DyldParseResult {
        parsed: ParseResult {
            arch,
            segments,
            entry_points: vec![],
            symbols: vec![],
            pie_base: 0,
            got_slots: HashSet::new(),
            reloc_pointers: Vec::new(),
        },
        dyld_ctx: ctx,
    })
}

fn parse_elf(
    bytes: &'static [u8],
    elf: &goblin::elf::Elf,
    bss_bufs: &mut Vec<Box<[u8]>>,
    base_override: Option<u64>,
) -> Result<ParseResult> {
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
            base_override.unwrap_or(DEFAULT_PIE_BASE)
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
                        va: Va(sec.va), // already rebased above
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
                        va: Va(last_end),
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
                    va: Va(ph_va),
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
                va: Va(bss_va),
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
        vec![Va(elf.entry + pie_base)]
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
                let addr = Va((sym.st_value & !1) + pie_base);
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
    let got_slots = build_elf_got_slots(elf, pie_base);
    let reloc_pointers = build_elf_reloc_pointers(elf, pie_base, &segments);

    Ok(ParseResult { arch, segments, entry_points, symbols, pie_base, got_slots, reloc_pointers })
}

/// Collect the set of GOT slot VAs from GLOB_DAT / JUMP_SLOT relocations.
///
/// These are the GOT entries that the dynamic linker fills with import
/// addresses.  Used by the x86-64 scanner to distinguish actual GOT-indirect
/// calls (`CALL [RIP+got_slot]`) from other RIP-relative indirect calls.
fn build_elf_got_slots(elf: &goblin::elf::Elf, pie_base: u64) -> HashSet<Va> {
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

    elf.dynrelas
        .iter()
        .chain(elf.dynrels.iter())
        .chain(elf.pltrelocs.iter())
        .filter(|rel| is_got_reloc(rel.r_type) && rel.r_sym != 0)
        .map(|rel| Va(rel.r_offset + pie_base))
        .collect()
}

/// O(log n) segment membership check for relocation pointer builders.
///
/// Builds a sorted, disjoint interval table from the segments and uses
/// binary search (`partition_point`) to test membership — matching the
/// strategy used by `SegmentIndex` in `arch::mod`.
struct VaRangeSet {
    /// Sorted by start VA; assumed disjoint (same invariant as SegmentIndex).
    ranges: Vec<(u64, u64)>,
}

impl VaRangeSet {
    fn build(segments: &[Segment]) -> Self {
        let mut ranges: Vec<(u64, u64)> = segments
            .iter()
            .map(|s| (s.va.raw(), s.va.raw() + s.data.len() as u64))
            .collect();
        ranges.sort_unstable_by_key(|&(start, _)| start);
        Self { ranges }
    }

    #[inline]
    fn contains(&self, va: u64) -> bool {
        let idx = self.ranges.partition_point(|&(start, _)| start <= va);
        if idx == 0 {
            return false;
        }
        let (start, end) = self.ranges[idx - 1];
        va >= start && va < end
    }
}

/// Extract relocation-derived pointer pairs `(from_va, to_va)` from ELF
/// relocation tables (`.rela.dyn` / `.rel.dyn`).
///
/// Handles:
/// - `R_*_RELATIVE` (no symbol): `from = r_offset + pie_base`, `target = r_addend + pie_base`
/// - `R_*_64` / `R_*_ABS64` (with defined symbol): `from = r_offset + pie_base`,
///   `target = sym.st_value + pie_base + r_addend`
///
/// Only emits pairs where `target` falls within a mapped segment (filters out
/// references to external/undefined symbols).
fn build_elf_reloc_pointers(
    elf: &goblin::elf::Elf,
    pie_base: u64,
    segments: &[Segment],
) -> Vec<(Va, Va)> {
    use goblin::elf::section_header::SHN_UNDEF;

    // Relocation types that encode a full pointer value.
    const R_X86_64_RELATIVE: u32 = 8;
    const R_X86_64_64: u32 = 1;
    const R_AARCH64_RELATIVE: u32 = 1027;
    const R_AARCH64_ABS64: u32 = 257;

    let seg_set = VaRangeSet::build(segments);

    let mut result = Vec::new();

    for rel in elf.dynrelas.iter().chain(elf.dynrels.iter()) {
        let from = rel.r_offset + pie_base;
        let r_type = rel.r_type;

        if r_type == R_X86_64_RELATIVE || r_type == R_AARCH64_RELATIVE {
            // RELATIVE: target = pie_base + addend (no symbol lookup).
            let target = (rel.r_addend.unwrap_or(0) as u64).wrapping_add(pie_base);
            if seg_set.contains(target) {
                result.push((Va(from), Va(target)));
            }
        } else if r_type == R_X86_64_64 || r_type == R_AARCH64_ABS64 {
            // ABS64: target = sym.st_value + pie_base + addend (defined symbols only).
            if rel.r_sym != 0 {
                let sym = &elf.dynsyms.get(rel.r_sym).or_else(|| elf.syms.get(rel.r_sym));
                if let Some(sym) = sym {
                    if sym.st_shndx != SHN_UNDEF as usize && sym.st_value != 0 {
                        let target = sym
                            .st_value
                            .wrapping_add(pie_base)
                            .wrapping_add(rel.r_addend.unwrap_or(0) as u64);
                        if seg_set.contains(target) {
                            result.push((Va(from), Va(target)));
                        }
                    }
                }
            }
        }
    }

    result
}

fn parse_macho(
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
                va: Va(sect.addr),
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

    let entry_points = vec![Va(macho.entry)];
    let mut symbols = Vec::new();
    if let Some(syms) = macho.symbols.as_ref() {
        for (name, nlist) in syms.iter().flatten() {
            if !name.is_empty() && nlist.n_value != 0 {
                symbols.push((name.to_string(), Va(nlist.n_value)));
            }
        }
    }

    Ok(ParseResult {
        arch,
        segments,
        entry_points,
        symbols,
        pie_base: 0,
        got_slots: HashSet::new(),
        reloc_pointers: Vec::new(),
    })
}

fn parse_pe(
    bytes: &'static [u8],
    pe: &goblin::pe::PE,
    bss_bufs: &mut Vec<Box<[u8]>>,
) -> Result<ParseResult> {
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
        let va = Va(image_base + section.virtual_address as u64);
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
        vec![Va(image_base + pe.entry as u64)]
    } else {
        vec![]
    };

    let mut symbols = Vec::new();
    for export in &pe.exports {
        if let Some(name) = export.name {
            symbols.push((name.to_string(), Va(image_base + export.rva as u64)));
        }
    }

    let reloc_pointers = build_pe_reloc_pointers(bytes, pe, image_base, &segments);

    Ok(ParseResult {
        arch,
        segments,
        entry_points,
        symbols,
        pie_base: 0,
        got_slots: HashSet::new(),
        reloc_pointers,
    })
}

/// Extract relocation-derived pointer pairs from PE base relocation table.
///
/// PE `.reloc` contains base relocation blocks. Each `IMAGE_REL_BASED_DIR64`
/// entry (type 10) identifies a 64-bit pointer slot. We read the pointer value
/// from the file and emit `(slot_va, pointer_value)` when the pointer falls
/// within a mapped segment.
/// Sorted RVA→file-offset map for O(log n) reads from PE sections.
struct PeSectionMap {
    /// (sec_rva, sec_end_rva, sec_raw_offset, sec_raw_size) sorted by rva.
    entries: Vec<(u32, u32, usize, usize)>,
}

impl PeSectionMap {
    fn build(pe: &goblin::pe::PE) -> Self {
        let mut entries: Vec<(u32, u32, usize, usize)> = pe
            .sections
            .iter()
            .filter(|s| s.size_of_raw_data > 0)
            .map(|s| {
                (
                    s.virtual_address,
                    s.virtual_address + s.virtual_size,
                    s.pointer_to_raw_data as usize,
                    s.size_of_raw_data as usize,
                )
            })
            .collect();
        entries.sort_unstable_by_key(|e| e.0);
        Self { entries }
    }

    /// Resolve an RVA to a file offset, or `None` if out of range.
    fn rva_to_file_offset(&self, rva: u32) -> Option<usize> {
        let idx = self.entries.partition_point(|e| e.0 <= rva);
        if idx == 0 {
            return None;
        }
        let (sec_rva, sec_end, sec_raw_off, sec_raw_size) = self.entries[idx - 1];
        if rva >= sec_rva && rva < sec_end {
            let offset_in_sec = (rva - sec_rva) as usize;
            if offset_in_sec < sec_raw_size {
                return Some(sec_raw_off + offset_in_sec);
            }
        }
        None
    }

    /// Read a little-endian u64 from the file at the given RVA.
    fn read_u64_at_rva(&self, bytes: &[u8], rva: u32) -> Option<u64> {
        let off = self.rva_to_file_offset(rva)?;
        let slice = bytes.get(off..off + 8)?;
        Some(u64::from_le_bytes(slice.try_into().unwrap()))
    }
}

fn build_pe_reloc_pointers(
    bytes: &[u8],
    pe: &goblin::pe::PE,
    image_base: u64,
    segments: &[Segment],
) -> Vec<(Va, Va)> {
    let seg_set = VaRangeSet::build(segments);
    let sec_map = PeSectionMap::build(pe);

    let mut result = Vec::new();

    const IMAGE_REL_BASED_DIR64: u16 = 10;

    // Parse the base relocation table.
    // Each block: 4-byte page RVA, 4-byte block size, then 2-byte entries.
    // Entry: top 4 bits = type, bottom 12 bits = offset within the page.
    let reloc_dir = pe
        .header
        .optional_header
        .and_then(|oh| {
            let dd = oh.data_directories.get_base_relocation_table()?;
            Some((dd.virtual_address, dd.size))
        });

    if let Some((dir_rva, dir_size)) = reloc_dir {
        let reloc_size = dir_size as usize;

        if let Some(base_off) = sec_map.rva_to_file_offset(dir_rva) {
            let reloc_bytes = bytes.get(base_off..base_off + reloc_size).unwrap_or(&[]);
            let mut pos = 0usize;
            while pos + 8 <= reloc_bytes.len() {
                let page_rva =
                    u32::from_le_bytes(reloc_bytes[pos..pos + 4].try_into().unwrap());
                let block_size =
                    u32::from_le_bytes(reloc_bytes[pos + 4..pos + 8].try_into().unwrap())
                        as usize;
                if block_size < 8 || pos + block_size > reloc_bytes.len() {
                    break;
                }
                let mut entry_pos = pos + 8;
                while entry_pos + 2 <= pos + block_size {
                    let entry = u16::from_le_bytes(
                        reloc_bytes[entry_pos..entry_pos + 2].try_into().unwrap(),
                    );
                    let rel_type = entry >> 12;
                    let offset = entry & 0x0FFF;
                    if rel_type == IMAGE_REL_BASED_DIR64 {
                        let slot_rva = page_rva + offset as u32;
                        let slot_va = image_base + slot_rva as u64;
                        if let Some(ptr_val) = sec_map.read_u64_at_rva(bytes, slot_rva) {
                            if ptr_val != 0 && seg_set.contains(ptr_val) {
                                result.push((Va(slot_va), Va(ptr_val)));
                            }
                        }
                    }
                    entry_pos += 2;
                }
                pos += block_size;
            }
        }
    }

    result
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
    fn segment_vas(elf: &[u8], base: Option<u64>) -> Vec<Va> {
        let tmp = write_tmp(elf);
        let bin = LoadedBinary::load_with_base(tmp.path(), base).unwrap();
        let mut vas: Vec<Va> = bin.segments.iter().map(|s| s.va).collect();
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
            binary.segments.iter().all(|s| s.va >= Va(0x0040_0000)),
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
        let mut got: Vec<Va> = binary.segments.iter().map(|s| s.va).collect();
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
        let mut got: Vec<Va> = binary.segments.iter().map(|s| s.va).collect();
        got.sort_unstable();
        let expected: Vec<Va> = raw_vas.iter().map(|v| *v + custom_base).collect();
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
            assert_eq!(*b - *a, delta, "VA shift mismatch: {a:#x} vs {b:#x}");
        }
    }
}
