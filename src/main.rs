use anyhow::Result;
use clap::{Parser, ValueEnum};
use rayon::prelude::*;
use std::io::Write as _;
use std::ops::ControlFlow;
use std::path::PathBuf;
use xr::output::{ContextLine, CsvPrinter, JsonPrinter, Printer, TextPrinter, XrefRecord};
use xr::{Depth, LoadedBinary, PassConfig, XrefPass};

#[derive(Parser)]
#[command(name = "xr", about = "Fast multi-level xref extraction")]
struct Cli {
    /// Binary to analyze (ELF, single-arch Mach-O, PE, or raw).
    /// Fat (universal) Mach-O binaries are not supported — extract the
    /// desired slice first with `lipo -extract <arch> <input> -output <output>`.
    binary: PathBuf,

    /// Override the load base VA for PIE ELF binaries (hex or decimal).
    /// By default PIE ELFs (ET_DYN with first PT_LOAD at 0) are rebased to
    /// 0x400000. Use this to match a specific runtime load address or to
    /// reproduce IDA's layout for a different base.
    /// Ignored for non-PIE ELF, Mach-O, and PE.
    #[arg(long, value_parser = parse_va)]
    base: Option<u64>,

    /// Analysis depth
    #[arg(short, long, default_value = "paired")]
    depth: DepthArg,

    /// Number of worker threads (0 = all CPUs)
    #[arg(short = 'j', long, default_value = "0")]
    workers: usize,

    /// Output format
    #[arg(short, long, default_value = "text")]
    format: OutputFormat,

    /// Minimum target VA for emitted xrefs. Xrefs whose 'to' is below this
    /// are silently dropped. Default: auto-detect from binary (binary.min_va()).
    /// Set to 0 to disable filtering.
    #[arg(long)]
    min_ref_va: Option<u64>,

    /// Filter output to xrefs of this kind (call/jump/data_read/data_write/data_ptr).
    /// When omitted, all kinds are shown.
    #[arg(short = 'k', long)]
    kind: Option<String>,

    /// Instructions of disasm context BEFORE each xref site (like grep -B).
    /// When non-zero, enables context display for that xref.
    #[arg(short = 'B', long = "before-context", default_value = "0")]
    before: usize,

    /// Instructions of disasm context AFTER each xref site (like grep -A).
    /// When non-zero, enables context display for that xref.
    #[arg(short = 'A', long = "after-context", default_value = "0")]
    after: usize,

    /// Cap output at N xrefs (0 = unlimited).
    #[arg(long, default_value = "0")]
    limit: usize,

    /// Restrict scanning to `from` addresses >= this VA (hex or decimal).
    /// Segments entirely below this address are skipped — no decode work wasted.
    #[arg(long, value_parser = parse_va)]
    start: Option<u64>,

    /// Restrict scanning to `from` addresses < this VA (hex or decimal).
    #[arg(long, value_parser = parse_va)]
    end: Option<u64>,

    /// Retain only xrefs whose `to` address >= this VA (hex or decimal).
    #[arg(long, value_parser = parse_va)]
    ref_start: Option<u64>,

    /// Retain only xrefs whose `to` address < this VA (hex or decimal).
    #[arg(long, value_parser = parse_va)]
    ref_end: Option<u64>,
}

#[derive(Clone, ValueEnum)]
enum DepthArg {
    /// Byte scan of data sections only
    Scan,
    /// Linear disasm — immediate targets only
    Linear,
    /// ADRP pairing / register prop (recommended)
    Paired,
}

#[derive(Clone, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
    Csv,
}

/// Parse a VA from a string — accepts `0x`-prefixed hex or plain decimal.
fn parse_va(s: &str) -> Result<u64, String> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).map_err(|e| e.to_string())
    } else {
        s.parse::<u64>().map_err(|e| e.to_string())
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let depth = match cli.depth {
        DepthArg::Scan => Depth::ByteScan,
        DepthArg::Linear => Depth::Linear,
        DepthArg::Paired => Depth::Paired,
    };

    eprintln!("loading {}...", cli.binary.display());
    let binary = LoadedBinary::load_with_base(&cli.binary, cli.base)?;
    eprintln!(
        "arch={:?}  segments={}  entry_points={}",
        binary.arch,
        binary.segments.len(),
        binary.entry_points.len()
    );

    let min_ref_va = cli.min_ref_va.unwrap_or_else(|| binary.min_va());

    let from_range = match (cli.start, cli.end) {
        (Some(lo), Some(hi)) => Some((lo, hi)),
        (Some(lo), None) => Some((lo, u64::MAX)),
        (None, Some(hi)) => Some((0, hi)),
        (None, None) => None,
    };
    let to_range = match (cli.ref_start, cli.ref_end) {
        (Some(lo), Some(hi)) => Some((lo, hi)),
        (Some(lo), None) => Some((lo, u64::MAX)),
        (None, Some(hi)) => Some((0, hi)),
        (None, None) => None,
    };

    let config = PassConfig {
        depth,
        workers: cli.workers,
        min_ref_va,
        from_range,
        to_range,
        ..Default::default()
    };
    eprintln!(
        "running xref pass (depth={depth:?}, workers={})...",
        config.workers
    );

    // ── Streaming xref pass ───────────────────────────────────────────────────

    // Context is enabled whenever -A or -B is non-zero (like grep).
    let want_context = cli.before > 0 || cli.after > 0;

    let kind_filter = cli.kind.clone();
    let limit = cli.limit;
    let mut emitted = 0usize;

    let printer: Box<dyn Printer> = match cli.format {
        OutputFormat::Text => Box::new(TextPrinter),
        OutputFormat::Json => Box::new(JsonPrinter),
        OutputFormat::Csv => Box::new(CsvPrinter),
    };

    // Single BufWriter — batches are pre-formatted in parallel then written
    // here in one write_all call per batch.
    let mut stdout = std::io::BufWriter::with_capacity(4 * 1024 * 1024, std::io::stdout());

    let hdr = printer.header_bytes();
    if !hdr.is_empty() {
        let _ = stdout.write_all(&hdr);
    }

    let result = XrefPass::new(&binary, config).run(|batch| {
        if limit > 0 && emitted >= limit {
            return ControlFlow::Break(());
        }

        // Compute how many xrefs from this batch we actually need before
        // building context (disasm is expensive — don't render what we'll discard).
        let remaining = if limit > 0 {
            limit - emitted
        } else {
            usize::MAX
        };

        // Process in sub-chunks so output flushes incrementally.
        // Without chunking, the entire shard batch (potentially millions of
        // xrefs) folds into a blob before the first write — causing a hang
        // proportional to limit. CHUNK controls latency vs parallelism tradeoff.
        const CHUNK: usize = 8192;

        let format_chunk = |chunk: &[&xr::xref::Xref]| -> Vec<u8> {
            chunk
                .par_iter()
                .fold(Vec::new, |mut buf, x| {
                    let context = if want_context {
                        let lines = xr::disasm::context(
                            binary.arch,
                            &binary.segments,
                            x.from,
                            cli.before,
                            cli.after,
                        );
                        Some(if lines.is_empty() {
                            binary
                                .segments
                                .iter()
                                .find(|s| s.contains(x.from))
                                .map(|seg| {
                                    let off = (x.from - seg.va) as usize;
                                    let len = 8.min(seg.data.len().saturating_sub(off));
                                    vec![ContextLine::data(x.from, &seg.data[off..off + len])]
                                })
                                .unwrap_or_default()
                        } else {
                            lines.iter().map(ContextLine::from_disasm).collect()
                        })
                    } else {
                        None
                    };
                    let record = XrefRecord {
                        from: x.from,
                        to: x.to,
                        kind: x.kind,
                        confidence: x.confidence,
                        context,
                    };
                    printer.write_record(&record, &mut buf);
                    buf
                })
                .reduce(Vec::new, |mut a, b| {
                    a.extend_from_slice(&b);
                    a
                })
        };

        let candidates: Vec<_> = batch
            .iter()
            .filter(|x| kind_filter.as_deref().is_none_or(|k| x.kind.name() == k))
            .take(remaining)
            .collect();

        for chunk in candidates.chunks(CHUNK) {
            let blob = format_chunk(chunk);
            let _ = stdout.write_all(&blob);
            emitted += chunk.len();
        }

        if limit > 0 && emitted >= limit {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    });

    let ftr = printer.footer_bytes();
    if !ftr.is_empty() {
        let _ = stdout.write_all(&ftr);
    }
    let _ = stdout.flush();

    result.print_summary();

    Ok(())
}
