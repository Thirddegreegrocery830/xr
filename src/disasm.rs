//! Disassembly context helpers for the `xr` CLI.
//!
//! Given a virtual address and a loaded binary, produces a window of
//! disassembled instructions centred on that address — similar to
//! `grep -A / -B` for source code.

use crate::loader::{Arch, DecodeMode, Segment};

/// A single disassembled instruction line.
pub struct DisasmLine {
    /// Virtual address of this instruction.
    pub va: u64,
    /// Raw bytes.
    pub bytes: Vec<u8>,
    /// Formatted text (Intel syntax for x86, standard for ARM64).
    pub text: String,
    /// True when this is the "focus" instruction (the xref site).
    pub is_focus: bool,
}

/// Disassemble a window of instructions around `focus_va`.
///
/// Returns up to `before + 1 + after` lines centred on the instruction at
/// `focus_va`. Lines are in address order; the focus line has `is_focus=true`.
/// Returns an empty vec if `focus_va` is not in any segment or the arch is
/// unsupported.
pub fn context(
    arch: Arch,
    segments: &[Segment],
    focus_va: u64,
    before: usize,
    after: usize,
) -> Vec<DisasmLine> {
    let seg = match segments.iter().find(|s| s.contains(focus_va)) {
        Some(s) => s,
        None => return vec![],
    };

    // Only disassemble executable segments; return empty for data so callers
    // can fall back to a hex dump.
    if !seg.executable {
        return vec![];
    }

    match arch {
        Arch::X86_64 | Arch::X86 => disasm_x86(seg, focus_va, before, after),
        Arch::Arm64 => disasm_arm64(seg, focus_va, before, after),
        _ => vec![],
    }
}

// ── x86 / x86-64 ─────────────────────────────────────────────────────────────

fn disasm_x86(seg: &Segment, focus_va: u64, before: usize, after: usize) -> Vec<DisasmLine> {
    use iced_x86::{
        Decoder, DecoderOptions, Formatter, FormatterOutput, FormatterTextKind, IntelFormatter,
    };

    struct Buf(String);
    impl FormatterOutput for Buf {
        fn write(&mut self, text: &str, _kind: FormatterTextKind) {
            self.0.push_str(text);
        }
    }

    let bitness: u32 = if seg.mode == DecodeMode::Default {
        64
    } else {
        32
    };
    let seg_offset = (focus_va - seg.va) as usize;

    // Scan back enough bytes to accommodate `before` instructions.
    // Max x86 instruction length is 15 bytes; add one extra slot as margin.
    let scan_back = before.saturating_add(2) * 15;
    let scan_start_off = seg_offset.saturating_sub(scan_back);
    let scan_start_va = seg.va + scan_start_off as u64;

    // Forward scan window: enough for focus + after instructions.
    let scan_end_off = (seg_offset + (after + 2) * 15).min(seg.data.len());
    let data = &seg.data[scan_start_off..scan_end_off];

    let mut decoder = Decoder::with_ip(bitness, data, scan_start_va, DecoderOptions::NONE);
    let mut fmt = IntelFormatter::new();
    fmt.options_mut().set_uppercase_keywords(false);
    fmt.options_mut().set_space_after_operand_separator(true);

    let mut all: Vec<(u64, Vec<u8>, String)> = Vec::new();
    while decoder.can_decode() {
        let ip = decoder.ip();
        if ip > focus_va + (after + 1) as u64 * 15 {
            break;
        }
        let insn = decoder.decode();
        let len = insn.len();
        let off = (ip - scan_start_va) as usize;
        let raw = data[off..off + len].to_vec();
        let mut buf = Buf(String::new());
        fmt.format(&insn, &mut buf);
        all.push((ip, raw, buf.0));
    }

    build_window(all, focus_va, before, after)
}

// ── AArch64 ──────────────────────────────────────────────────────────────────

fn disasm_arm64(seg: &Segment, focus_va: u64, before: usize, after: usize) -> Vec<DisasmLine> {
    // AArch64 has fixed 4-byte instructions — no alignment ambiguity.
    let seg_offset = (focus_va - seg.va) as usize;

    // Align start to 4-byte boundary.
    let scan_back_bytes = before * 4;
    let scan_start_off = seg_offset.saturating_sub(scan_back_bytes) & !3;
    let scan_start_va = seg.va + scan_start_off as u64;

    let total = before + 1 + after;
    let scan_end_off = (scan_start_off + total * 4).min(seg.data.len());
    let data = &seg.data[scan_start_off..scan_end_off];

    let mut all: Vec<(u64, Vec<u8>, String)> = Vec::new();
    for (i, chunk) in data.chunks_exact(4).enumerate() {
        let va = scan_start_va + (i * 4) as u64;
        let word = u32::from_le_bytes(chunk.try_into().unwrap());
        let text = match bad64::decode(word, va) {
            Ok(insn) => insn.to_string(),
            Err(_) => format!(".word 0x{word:08x}"),
        };
        all.push((va, chunk.to_vec(), text));
    }

    build_window(all, focus_va, before, after)
}

// ── Shared window builder ─────────────────────────────────────────────────────

fn build_window(
    all: Vec<(u64, Vec<u8>, String)>,
    focus_va: u64,
    before: usize,
    after: usize,
) -> Vec<DisasmLine> {
    let focus_idx = match all.iter().position(|(va, _, _)| *va == focus_va) {
        Some(i) => i,
        // focus_va not cleanly decoded (e.g. mid-instruction on x86) — no output.
        None => return vec![],
    };

    let start = focus_idx.saturating_sub(before);
    let end = (focus_idx + after + 1).min(all.len());

    all[start..end]
        .iter()
        .map(|(va, bytes, text)| DisasmLine {
            va: *va,
            bytes: bytes.clone(),
            text: text.clone(),
            is_focus: *va == focus_va,
        })
        .collect()
}
