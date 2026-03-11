//! Output types and format-specific printers for the `xr` CLI.
//!
//! The pipeline is:
//!   1. Build a `Vec<XrefRecord>` (xref + optional disasm context) once.
//!   2. Pick a `Printer` impl based on `--format`.
//!   3. Call `printer.print(&records)`.

use crate::disasm::DisasmLine;
use crate::xref::{Confidence, XrefKind};
use serde::Serialize;
use std::fmt::Write as FmtWrite;
use std::io::Write as IoWrite;

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Build a space-separated lowercase hex string from raw bytes.
/// Single pre-allocated `String` — no intermediate `Vec<String>`.
fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 3);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        write!(s, "{b:02x}").unwrap();
    }
    s
}

// ── Data types ────────────────────────────────────────────────────────────────

/// A single line of disassembly or hex context around an xref site.
#[derive(Serialize)]
pub struct ContextLine {
    pub va: u64,
    /// Raw bytes as a lowercase hex string (space-separated, e.g. `"48 89 c7"`).
    pub hex: String,
    /// Formatted instruction text, or `"(data)"` for non-code regions.
    pub text: String,
    /// True for the instruction at the xref `from` address.
    pub focus: bool,
}

impl ContextLine {
    pub fn from_disasm(line: &DisasmLine) -> Self {
        Self {
            va: line.va,
            hex: bytes_to_hex(&line.bytes),
            text: line.text.clone(),
            focus: line.is_focus,
        }
    }

    pub fn data(va: u64, raw: &[u8]) -> Self {
        Self {
            va,
            hex: bytes_to_hex(raw),
            text: "(data)".to_string(),
            focus: true,
        }
    }
}

/// A fully resolved xref, optionally annotated with disasm context.
#[derive(Serialize)]
pub struct XrefRecord {
    pub from: u64,
    pub to: u64,
    /// Kind label (`"call"`, `"jump"`, `"data_read"`, `"data_write"`, `"data_ptr"`).
    #[serde(serialize_with = "serialize_kind")]
    pub kind: XrefKind,
    /// Confidence label (e.g. `"pair-resolved"`).
    #[serde(serialize_with = "serialize_confidence")]
    pub confidence: Confidence,
    /// Present when `--verbose` was requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<Vec<ContextLine>>,
}

fn serialize_kind<S: serde::Serializer>(k: &XrefKind, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(k.name())
}

fn serialize_confidence<S: serde::Serializer>(c: &Confidence, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(c.name())
}

// ── Printer trait ─────────────────────────────────────────────────────────────

/// Format and output xref records.
///
/// The hot path is:
///   1. `write_record` is called in parallel (one call per record, per thread)
///      appending into a caller-supplied `Vec<u8>`.  No per-record allocation.
///   2. Caller reduces thread-local buffers into one blob and calls `write_all`
///      once per batch, amortising syscall overhead.
///   3. `header_bytes` / `footer_bytes` are written once, serially.
pub trait Printer: Send + Sync {
    /// Bytes to write before the first batch (e.g. `[` for JSON). Empty by default.
    fn header_bytes(&self) -> Vec<u8> {
        vec![]
    }
    /// Append the formatted representation of `record` into `buf`.
    /// Called in parallel — must be pure (no interior mutability).
    fn write_record(&self, record: &XrefRecord, buf: &mut Vec<u8>);
    /// Bytes to write after the last batch (e.g. `]\n` for JSON). Empty by default.
    fn footer_bytes(&self) -> Vec<u8> {
        vec![]
    }
}

// ── Text printer ──────────────────────────────────────────────────────────────

pub struct TextPrinter;

impl Printer for TextPrinter {
    fn write_record(&self, r: &XrefRecord, buf: &mut Vec<u8>) {
        let _ = writeln!(
            buf,
            "{:#018x} -> {:#018x}  {}  [{}]",
            r.from,
            r.to,
            r.kind.name(),
            r.confidence.name(),
        );
        if let Some(ctx) = &r.context {
            for line in ctx {
                let marker = if line.focus { ">" } else { " " };
                let _ = writeln!(
                    buf,
                    "  {marker} {:#018x}  {:<24}  {}",
                    line.va, line.hex, line.text
                );
            }
            buf.push(b'\n');
        }
    }
}

// ── JSONL printer ─────────────────────────────────────────────────────────────

/// JSON Lines printer — one compact JSON object per line, no array wrapper.
///
/// Each record is serialised as a single line of JSON followed by `\n`.
/// No commas, no `[`/`]` delimiters. This format is trivially parallel-safe:
/// every `write_record` call is independent — no shared state needed.
pub struct JsonlPrinter;

impl Printer for JsonlPrinter {
    fn write_record(&self, r: &XrefRecord, buf: &mut Vec<u8>) {
        match serde_json::to_string(r) {
            Ok(s) => {
                buf.extend_from_slice(s.as_bytes());
                buf.push(b'\n');
            }
            Err(e) => eprintln!("json serialisation error: {e}"),
        }
    }
}

// ── CSV printer ───────────────────────────────────────────────────────────────

pub struct CsvPrinter;

impl Printer for CsvPrinter {
    fn header_bytes(&self) -> Vec<u8> {
        b"from,to,kind,confidence\n".to_vec()
    }

    fn write_record(&self, r: &XrefRecord, buf: &mut Vec<u8>) {
        let _ = writeln!(
            buf,
            "{:#x},{:#x},{},{}",
            r.from,
            r.to,
            r.kind.name(),
            r.confidence.name(),
        );
    }
}
