//! Benchmark xr against IDA ground-truth xrefs.
//!
//! Usage:
//!   cargo run --release --bin benchmark -- \
//!       --binary <binary> \
//!       --ground-truth <binary>.xrefs.json
//!
//! For each depth level (ByteScan, Linear, Paired) it reports:
//!   - Wall time (ms)
//!   - Total xrefs found
//!   - vs IDA: TP / FP / FN, precision / recall / F1
//!   - Breakdown by kind (call, jump, data_*)
//!
//! Kind mapping (xr → IDA):
//!   Call / CondJump → "call" or "jump"  (IDA uses call/jump by type)
//!   Jump            → "jump"
//!   DataRead        → "data_read"
//!   DataPointer     → "data_ptr"
//!
//! NOTE: IDA's "data_ptr" (dr_O) is an offset reference — xr emits these
//! as ByteScan DataPointer or PairResolved DataRead depending on depth.
//! The comparison uses a KIND-AGNOSTIC (from, to) match as the primary
//! signal, and also reports a strict (from, to, kind) match for reference.

use anyhow::Result;
use clap::Parser;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::ops::ControlFlow;
use std::path::PathBuf;
use std::time::Instant;
use xr::pass::PassConfig;
use xr::xref::{Xref, XrefKind};
use xr::{Depth, LoadedBinary, XrefPass};

#[derive(Parser)]
#[command(
    name = "benchmark",
    about = "Compare xr output against IDA ground truth"
)]
struct Cli {
    /// Binary to analyse
    #[arg(short, long)]
    binary: PathBuf,

    /// IDA ground-truth xrefs JSON
    #[arg(short, long)]
    ground_truth: PathBuf,

    /// Number of worker threads (0 = all CPUs)
    #[arg(short = 'j', long, default_value = "0")]
    workers: usize,

    /// How many times to repeat each run for timing stability
    #[arg(long, default_value = "3")]
    runs: usize,

    /// Dump all FP xrefs (xr has, IDA doesn't) to this JSON file (Paired depth only)
    #[arg(long)]
    dump_fps: Option<PathBuf>,

    /// Dump all FN xrefs (IDA has, xr doesn't) to this JSON file (Paired depth only)
    #[arg(long)]
    dump_fns: Option<PathBuf>,

    /// Dump all TP xrefs to this JSON file (Paired depth only)
    #[arg(long)]
    dump_tps: Option<PathBuf>,

    /// If set with dump_fps/dump_fns/dump_tps, filter to this kind (call/jump/data_read/data_write/data_ptr)
    #[arg(long)]
    dump_kind: Option<String>,

    /// Depth to run. If omitted, runs all three.
    #[arg(long)]
    depth: Option<Depth>,

    /// Minimum target VA for emitted xrefs. Xrefs whose 'to' is below this
    /// are silently dropped. Default: auto-detect from binary (binary.min_va()).
    /// Set to 0 to disable filtering.
    #[arg(long)]
    min_ref_va: Option<u64>,
}

// ── Ground-truth types ────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct IdaXref {
    #[serde(rename = "from")]
    from: u64,
    #[serde(rename = "to")]
    to: u64,
    kind: String,
}

/// Ground-truth JSON is either:
///   - Old format: a flat JSON array of xref objects
///   - New format: {"image_base": <u64>, "xrefs": [...]}
///
/// `image_base` is IDA's load address for the binary. When non-zero it is used
/// to rebase the IDA xrefs into xr's address space before comparison:
///   adjusted_va = ida_va - image_base + xr_pie_base
/// This makes PIE ELFs that IDA loaded at their natural base (e.g. 0x0) compare
/// correctly against xr's rebased output (e.g. 0x400000).
#[derive(Deserialize)]
#[serde(untagged)]
enum GroundTruth {
    WithMeta {
        image_base: u64,
        xrefs: Vec<IdaXref>,
    },
    Flat(Vec<IdaXref>),
}

impl GroundTruth {
    fn image_base(&self) -> u64 {
        match self {
            GroundTruth::WithMeta { image_base, .. } => *image_base,
            GroundTruth::Flat(_) => 0,
        }
    }
    fn xrefs(&self) -> &[IdaXref] {
        match self {
            GroundTruth::WithMeta { xrefs, .. } => xrefs,
            GroundTruth::Flat(v) => v,
        }
    }
}

/// A (from, to) pair — used for kind-agnostic matching.
type AddrPair = (u64, u64);

// ── Stats ─────────────────────────────────────────────────────────────────────

struct Stats {
    tp: usize,
    fp: usize,
    fn_: usize,
}

impl Stats {
    fn precision(&self) -> f64 {
        if self.tp + self.fp == 0 {
            0.0
        } else {
            self.tp as f64 / (self.tp + self.fp) as f64
        }
    }
    fn recall(&self) -> f64 {
        if self.tp + self.fn_ == 0 {
            0.0
        } else {
            self.tp as f64 / (self.tp + self.fn_) as f64
        }
    }
    fn f1(&self) -> f64 {
        let p = self.precision();
        let r = self.recall();
        if p + r == 0.0 {
            0.0
        } else {
            2.0 * p * r / (p + r)
        }
    }
}

fn compute_stats(xr: &HashSet<AddrPair>, ida: &HashSet<AddrPair>) -> Stats {
    let tp = xr.intersection(ida).count();
    Stats {
        tp,
        fp: xr.len() - tp,
        fn_: ida.len() - tp,
    }
}

fn print_stats(label: &str, s: &Stats, xr_total: usize, ida_total: usize) {
    println!(
        "  {label:<14}  xr={xr_total:>7}  ida={ida_total:>7}  \
         TP={:>6}  FP={:>6}  FN={:>6}  \
         prec={:.3}  rec={:.3}  F1={:.3}",
        s.tp,
        s.fp,
        s.fn_,
        s.precision(),
        s.recall(),
        s.f1()
    );
}

// ── Run one depth pass, return xrefs + wall time ──────────────────────────────

fn run_pass(
    binary: &LoadedBinary,
    depth: Depth,
    workers: usize,
    runs: usize,
    min_ref_va: xr::Va,
) -> (Vec<Xref>, u64) {
    let mut best_ms = u64::MAX;
    let mut last_xrefs = Vec::new();
    for _ in 0..runs {
        let t0 = Instant::now();
        let mut xrefs = Vec::new();
        let _result = XrefPass::new(
            binary,
            PassConfig {
                depth,
                workers,
                min_ref_va,
                ..Default::default()
            },
        )
        .run(|batch| {
            xrefs.extend_from_slice(batch);
            ControlFlow::Continue(())
        });
        let ms = t0.elapsed().as_millis() as u64;
        if ms < best_ms {
            best_ms = ms;
            last_xrefs = xrefs;
        }
    }
    (last_xrefs, best_ms)
}

// ── Main ──────────────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Load ground truth
    let gt_json = std::fs::read_to_string(&cli.ground_truth)?;
    let gt: GroundTruth = serde_json::from_str(&gt_json)?;
    let ida_image_base = gt.image_base();
    let ida_raw = gt.xrefs();

    // Load binary early so we can read xr's pie_base for VA alignment.
    let binary = LoadedBinary::load(&cli.binary)?;
    let xr_pie_base = binary.pie_base;

    // VA offset to apply to every IDA address before comparison.
    //
    // New format (with image_base field): IDA may have loaded a PIE ELF at a
    // different base than xr (e.g. IDA at 0x0, xr at 0x400000). We shift
    // IDA VAs: adjusted = ida_va - ida_image_base + xr_pie_base.
    // Only applied when the JSON has the image_base field (new format) AND
    // xr actually rebased (pie_base != 0).
    //
    // Old flat format / non-PIE: IDA xrefs are already in xr's address space.
    // No adjustment needed.
    let has_image_base = matches!(gt, GroundTruth::WithMeta { .. });
    let va_offset = if has_image_base && xr_pie_base != 0 {
        xr_pie_base.wrapping_sub(ida_image_base)
    } else {
        0
    };

    // Build IDA sets per kind and overall
    let mut ida_by_kind: HashMap<XrefKind, HashSet<AddrPair>> = HashMap::new();
    let mut ida_all: HashSet<AddrPair> = HashSet::new();
    for &k in XrefKind::SCORED_KINDS {
        ida_by_kind.insert(k, HashSet::new());
    }

    for x in ida_raw {
        let pair = (x.from.wrapping_add(va_offset), x.to.wrapping_add(va_offset));
        ida_all.insert(pair);
        if let Some(kind) = XrefKind::from_name(&x.kind) {
            if let Some(set) = ida_by_kind.get_mut(&kind) {
                set.insert(pair);
            }
        }
    }

    if va_offset != 0 {
        println!(
            "VA rebase    : ida_base={ida_image_base:#x}  xr_base={xr_pie_base:#x}  offset={va_offset:#x}"
        );
    }
    println!(
        "ground truth : {} xrefs from {}",
        ida_raw.len(),
        cli.ground_truth.display()
    );
    for &k in XrefKind::SCORED_KINDS {
        println!("  {:<12} {}", k.name(), ida_by_kind[&k].len());
    }
    println!();

    let min_ref_va = cli
        .min_ref_va
        .map(xr::Va)
        .unwrap_or_else(|| binary.min_va());
    println!(
        "binary       : {}  arch={:?}  segments={}",
        cli.binary.display(),
        binary.arch,
        binary.segments.len()
    );
    println!(
        "workers      : {}",
        if cli.workers == 0 {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4)
        } else {
            cli.workers
        }
    );
    println!("runs         : {} (reporting best)", cli.runs);
    println!();

    // Determine which depths to run
    let depths_to_run: Vec<Depth> = match cli.depth {
        Some(d) => vec![d],
        None => vec![Depth::ByteScan, Depth::Linear, Depth::Paired],
    };

    // Run at each depth and compare
    for depth in &depths_to_run {
        let depth = *depth;
        let (xrefs, ms) = run_pass(&binary, depth, cli.workers, cli.runs, min_ref_va);

        // Build xr sets per kind and overall
        let mut xr_by_kind: HashMap<XrefKind, HashSet<AddrPair>> = HashMap::new();
        for &k in XrefKind::SCORED_KINDS {
            xr_by_kind.insert(k, HashSet::new());
        }
        let mut xr_all: HashSet<AddrPair> = HashSet::new();

        for x in &xrefs {
            let pair = (x.from.raw(), x.to.raw());
            xr_all.insert(pair);
            let k = x.kind.scored_kind();
            if let Some(set) = xr_by_kind.get_mut(&k) {
                set.insert(pair);
            }
        }

        println!(
            "─── depth={depth:?}  time={ms}ms  xrefs={} ───",
            xrefs.len()
        );

        // Overall
        let s = compute_stats(&xr_all, &ida_all);
        print_stats("overall", &s, xr_all.len(), ida_all.len());

        // Per kind
        for &k in XrefKind::SCORED_KINDS {
            let xr_k = &xr_by_kind[&k];
            let ida_k = &ida_by_kind[&k];
            let s = compute_stats(xr_k, ida_k);
            print_stats(k.name(), &s, xr_k.len(), ida_k.len());
        }

        // Extra: show a sample of FPs and FNs for diagnosis (overall)
        let fp_sample: Vec<_> = xr_all.difference(&ida_all).take(5).collect();
        let fn_sample: Vec<_> = ida_all.difference(&xr_all).take(5).collect();
        if !fp_sample.is_empty() {
            print!("  FP sample  :");
            for (f, t) in &fp_sample {
                print!("  {f:#x}→{t:#x}");
            }
            println!();
        }
        if !fn_sample.is_empty() {
            print!("  FN sample  :");
            for (f, t) in &fn_sample {
                print!("  {f:#x}→{t:#x}");
            }
            println!();
        }
        println!();

        // Dump FP/FN/TP sets if requested (Paired depth only)
        if depth == Depth::Paired {
            // Helper: build full xref vec filtered by kind for a given pair set
            let xref_map: std::collections::HashMap<AddrPair, &Xref> =
                xrefs.iter().map(|x| ((x.from.raw(), x.to.raw()), x)).collect();

            let kind_filter = cli.dump_kind.as_deref().and_then(XrefKind::from_name);

            let matches_kind = |pair: &AddrPair, set: &HashSet<AddrPair>| -> bool {
                if let Some(k) = kind_filter {
                    // Check if xr has this pair with the right kind
                    if let Some(x) = xref_map.get(pair) {
                        return x.kind.scored_kind() == k;
                    }
                    // For FNs (in ida_all but not xr_all), check ida kind
                    if set.contains(pair) && !xr_all.contains(pair) {
                        return ida_by_kind.get(&k).is_some_and(|s| s.contains(pair));
                    }
                    return false;
                }
                true
            };

            #[derive(serde::Serialize)]
            struct DumpXref {
                from: u64,
                to: u64,
                kind: &'static str,
            }

            let make_dump = |pairs: Vec<&AddrPair>| -> Vec<DumpXref> {
                pairs
                    .into_iter()
                    .map(|(f, t)| {
                        let kind = xref_map
                            .get(&(*f, *t))
                            .map(|x| x.kind.scored_kind().name())
                            .unwrap_or_else(|| {
                                // FN: determine kind from IDA
                                for &k in XrefKind::SCORED_KINDS {
                                    if ida_by_kind[&k].contains(&(*f, *t)) {
                                        return k.name();
                                    }
                                }
                                "unknown"
                            });
                        DumpXref {
                            from: *f,
                            to: *t,
                            kind,
                        }
                    })
                    .collect()
            };

            if let Some(path) = &cli.dump_fps {
                let fps: Vec<&AddrPair> = xr_all
                    .difference(&ida_all)
                    .filter(|p| matches_kind(p, &xr_all))
                    .collect();
                let data = make_dump(fps);
                std::fs::write(path, serde_json::to_string_pretty(&data)?)?;
                eprintln!("Wrote {} FPs to {}", data.len(), path.display());
            }
            if let Some(path) = &cli.dump_fns {
                let fns: Vec<&AddrPair> = ida_all
                    .difference(&xr_all)
                    .filter(|p| matches_kind(p, &ida_all))
                    .collect();
                let data = make_dump(fns);
                std::fs::write(path, serde_json::to_string_pretty(&data)?)?;
                eprintln!("Wrote {} FNs to {}", data.len(), path.display());
            }
            if let Some(path) = &cli.dump_tps {
                let tps: Vec<&AddrPair> = xr_all
                    .intersection(&ida_all)
                    .filter(|p| matches_kind(p, &xr_all))
                    .collect();
                let data = make_dump(tps);
                std::fs::write(path, serde_json::to_string_pretty(&data)?)?;
                eprintln!("Wrote {} TPs to {}", data.len(), path.display());
            }
        }
    }

    Ok(())
}
