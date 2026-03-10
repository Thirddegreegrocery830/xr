use crate::arch::arm64;
use crate::arch::x86_64;
use crate::arch::{self, ScanRegion, SegmentDataIndex, SegmentIndex};
use crate::loader::{Arch, DecodeMode, LoadedBinary, Segment};
use crate::shard::split_range;
use crate::xref::Xref;
use rayon::prelude::*;
use std::ops::ControlFlow;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::Instant;

// Capacity of the bounded channel between the drain relay thread and the output
// thread.  Large enough that the output thread is rarely starved (scan batches
// arrive in bursts), but small enough that we don't buffer all 171M xrefs in
// memory if output falls behind.

/// Which analysis depth to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum)]
pub enum Depth {
    /// Depth 0: byte scan of data sections only (pointer-sized values).
    ByteScan = 0,
    /// Depth 1: linear disasm, immediate targets + RIP-relative / direct branches.
    Linear = 1,
    /// Depth 2: ADRP pairing (ARM64) or register prop (x86-64).
    Paired = 2,
}

pub struct PassConfig {
    pub depth: Depth,
    /// Number of parallel workers. 0 = use all logical CPUs.
    pub workers: usize,
    /// Bytes of lookahead overlap per shard boundary (for cross-shard pairs).
    pub boundary_overlap: u64,
    /// Drop any xref whose `to` address is below this threshold.
    /// 0 = no filtering (default, backward-compatible).
    /// Set to `binary.min_va()` for PIE ELF to eliminate tiny-immediate FPs
    /// (e.g. `CMP rax, 8` generating a spurious data_ptr xref to VA 0x8).
    ///
    /// Note: for non-PIE binaries `min_va()` returns the lowest segment VA
    /// (which may be 0x0 for firmware or flat images), causing this filter to
    /// become a no-op — no xrefs are incorrectly dropped in that case.
    pub min_ref_va: u64,
    /// Restrict scanning to xrefs whose `from` address falls in `[start, end)`.
    /// Applied at shard-generation time — segments outside the range are skipped
    /// entirely, so no decode work is wasted.
    /// `None` = no restriction (scan everything).
    pub from_range: Option<(u64, u64)>,
    /// Retain only xrefs whose `to` address falls in `[start, end)`.
    /// Applied as a post-filter after scanning.
    /// `None` = no restriction.
    pub to_range: Option<(u64, u64)>,
}

impl Default for PassConfig {
    fn default() -> Self {
        Self {
            depth: Depth::Paired,
            workers: 0,
            boundary_overlap: 64, // 16 ARM64 instructions of lookahead
            min_ref_va: 0,
            from_range: None,
            to_range: None,
        }
    }
}

/// Breakdown of emitted xrefs by confidence level.
#[derive(Debug, Default, Clone, Copy)]
pub struct ConfidenceCounts {
    pub byte_scan: usize,
    pub linear_immediate: usize,
    pub pair_resolved: usize,
    pub local_prop: usize,
    pub function_flow: usize,
}

impl ConfidenceCounts {
    fn add(&mut self, c: crate::xref::Confidence) {
        use crate::xref::Confidence::*;
        match c {
            ByteScan => self.byte_scan += 1,
            LinearImmediate => self.linear_immediate += 1,
            PairResolved => self.pair_resolved += 1,
            LocalProp => self.local_prop += 1,
            FunctionFlow => self.function_flow += 1,
        }
    }
}

pub struct PassResult {
    pub elapsed_ms: u64,
    pub segments_scanned: usize,
    pub bytes_scanned: u64,
    pub xref_count: usize,
    /// How many xrefs were emitted at each confidence level.
    pub confidence_counts: ConfidenceCounts,
}

impl PassResult {
    pub fn print_summary(&self) {
        let cc = &self.confidence_counts;
        eprintln!(
            "xrefs: {}  |  {:.1}s  |  {:.1} MB scanned  |  {} segments",
            self.xref_count,
            self.elapsed_ms as f64 / 1000.0,
            self.bytes_scanned as f64 / 1_048_576.0,
            self.segments_scanned,
        );
        eprintln!(
            "  byte-scan={} linear={} pair-resolved={} local-prop={} fn-flow={}",
            cc.byte_scan, cc.linear_immediate, cc.pair_resolved, cc.local_prop, cc.function_flow,
        );
    }
}

/// Run the xref pass over a loaded binary.
pub struct XrefPass<'a> {
    binary: &'a LoadedBinary,
    config: PassConfig,
}

impl<'a> XrefPass<'a> {
    pub fn new(binary: &'a LoadedBinary, config: PassConfig) -> Self {
        Self { binary, config }
    }

    /// Run the xref pass, calling `on_batch` for each completed shard's xrefs.
    /// Batches are deduplicated (boundary overlap trimmed by ownership) and
    /// filtered by `min_ref_va` before being passed to the callback.
    /// `on_batch` is called from the main thread, serially, so it can do I/O
    /// without any locking.
    ///
    /// `on_batch` returns `ControlFlow::Continue(())` to keep going or
    /// `ControlFlow::Break(())` to stop early.  When it breaks, in-flight
    /// shards finish but no new shards start, so the scan halts promptly
    /// (within one shard's worth of work).
    pub fn run<F>(self, mut on_batch: F) -> PassResult
    where
        F: FnMut(&[Xref]) -> ControlFlow<()> + Send,
    {
        let t0 = Instant::now();

        let n_workers = if self.config.workers == 0 {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4)
        } else {
            self.config.workers
        };

        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(n_workers)
            .build()
            .expect("failed to build thread pool");

        let all_segs = &self.binary.segments;
        let arch = self.binary.arch;
        let depth = self.config.depth;
        let overlap = self.config.boundary_overlap;
        let min_ref_va = self.config.min_ref_va;
        let from_range = self.config.from_range;
        let to_range = self.config.to_range;

        // Build the segment indices once — both shared across all shards via reference.
        // SegmentIndex: flags-only O(log n) membership/exec checks.
        // SegmentDataIndex: also carries data slices for O(log n) pointer reads
        //   (used in byte_scan_pointers and ADRP/LDR pointer-follow in scan_adrp).
        let seg_idx = SegmentIndex::build(all_segs);
        let data_idx = SegmentDataIndex::build(all_segs);

        // Instruction alignment for shard boundary snapping.
        // ARM64: 4-byte fixed. x86: 1 (variable length).
        let insn_align: u64 = match arch {
            Arch::Arm64 | Arch::Arm32 => 4,
            _ => 1,
        };

        let ptr_size: usize = match arch {
            Arch::X86_64 | Arch::Arm64 => 8,
            _ => 4,
        };

        // Channel: workers send completed shard batches; main thread drains.
        let (tx, rx) = mpsc::channel::<Vec<Xref>>();

        // Build the full shard list upfront so we know which is the last shard
        // per segment (last shard owns its overlap region too).
        // For each shard, compute (seg, scan_start, scan_end, owned_end).
        // owned_end = next shard's start (or seg_end for the last shard).
        // scan_end includes the overlap lookahead; owned_end does not.
        // Using next shard's start directly handles overlap >= chunk correctly.
        let code_shards: Vec<(&Segment, u64, u64, u64)> = self
            .binary
            .code_segments()
            .flat_map(|seg| {
                let seg_end = seg.va + seg.data.len() as u64;
                // Clamp to from_range before sharding — segments with no overlap
                // produce an empty shard list and are skipped entirely.
                let (scan_start, scan_end) = match from_range {
                    Some((lo, hi)) => (seg.va.max(lo), seg_end.min(hi)),
                    None => (seg.va, seg_end),
                };
                if scan_start >= scan_end {
                    return vec![];
                }
                let shards = split_range(scan_start, scan_end, n_workers, overlap, insn_align);
                let n = shards.len();
                let starts: Vec<u64> = shards.iter().map(|(s, _)| *s).collect();
                shards
                    .into_iter()
                    .enumerate()
                    .map(move |(i, (start, end))| {
                        let owned_end = if i + 1 < n { starts[i + 1] } else { scan_end };
                        (seg, start, end, owned_end)
                    })
                    .collect()
            })
            .collect();

        let data_shards: Vec<(&Segment, u64, u64)> = if depth >= Depth::ByteScan {
            self.binary
                .scannable_data_segments()
                .flat_map(|seg| {
                    let seg_end = seg.va + seg.data.len() as u64;
                    // Clamp to from_range (data pointers are emitted at their source VA).
                    let (scan_start, scan_end) = match from_range {
                        Some((lo, hi)) => (seg.va.max(lo), seg_end.min(hi)),
                        None => (seg.va, seg_end),
                    };
                    if scan_start >= scan_end {
                        return vec![];
                    }
                    let shards = split_range(
                        scan_start,
                        scan_end,
                        n_workers,
                        0,
                        // Align shard boundaries to pointer size so that
                        // byte_scan_pointers (which steps by ptr_size from
                        // offset 0 within each shard) always lands on
                        // ptr_size-aligned absolute addresses. Without this,
                        // non-aligned shard starts cause misaligned scans
                        // that systematically skip aligned pointer slots.
                        ptr_size as u64,
                    );
                    shards
                        .into_iter()
                        .map(move |(start, end)| (seg, start, end))
                        .collect()
                })
                .collect()
        } else {
            vec![]
        };

        let ctx = ScanCtx {
            all_segs,
            seg_idx: &seg_idx,
            data_idx: &data_idx,
            got_map: &self.binary.got_map,
        };

        // Cancellation flag: set by the drain thread when on_batch returns Break.
        // Workers check this before starting each shard — no new shards start once
        // set, but in-flight shards finish normally.
        // Wrapped in Arc so it can be shared between the drain thread and the workers
        // (which run inside pool.install on the current thread's stack).
        let stop = Arc::new(AtomicBool::new(false));
        let stop_workers = Arc::clone(&stop);

        // Run workers and drain concurrently inside a thread scope so the drain
        // thread can borrow non-'static locals (on_batch, stop) while the workers
        // run in the rayon pool. The scope blocks until both finish.
        // Second channel: drain relay → output thread.
        // Bounded to n_workers * 4: enough runway for the output thread to stay
        // busy across a burst of completed shards without buffering all results.
        let (out_tx, out_rx) = mpsc::sync_channel::<Vec<Xref>>(n_workers * 4);

        let (xref_count, confidence_counts) = std::thread::scope(|s| {
            // Output thread: owns on_batch — formats and writes results.
            // Runs concurrently with the scan workers.
            // on_batch may use par_iter; routing it through pool.install means
            // those tasks share the scan pool.  While scan is running they
            // work-steal alongside scan; once scan finishes they get all threads.
            // Returns (xref_count, confidence_counts) after all batches processed.
            let output = s.spawn(|| {
                let mut xref_count = 0usize;
                let mut confidence_counts = ConfidenceCounts::default();
                for batch in out_rx {
                    for x in &batch {
                        confidence_counts.add(x.confidence);
                        xref_count += 1;
                    }
                    let cf = pool.install(|| on_batch(&batch));
                    if cf.is_break() {
                        stop.store(true, Ordering::Relaxed);
                    }
                }
                (xref_count, confidence_counts)
            });

            // Drain thread: pure relay — receives scan batches and forwards to
            // the output thread without blocking on formatting or I/O.
            // This keeps the scan channel drained so workers never stall.
            let drain = s.spawn(|| {
                for batch in rx {
                    // Forward to output thread; blocks only when output_channel
                    // is full (backpressure), not on format/write work.
                    // If stop is set (output thread broke), drain silently to
                    // unblock any workers still trying to send.
                    if stop_workers.load(Ordering::Relaxed) {
                        // Discard — output is done, just drain the scan channel.
                        continue;
                    }
                    let _ = out_tx.send(batch);
                }
                // Drop out_tx so the output thread's channel closes.
                drop(out_tx);
            });

            pool.install(|| {
                let tx = tx.clone();
                // Code shards — owned_end is the next shard's start (or seg_end).
                // Xrefs with from >= owned_end are in the overlap lookahead and
                // will be emitted by the next shard instead.
                code_shards.into_par_iter().for_each_with(
                    tx.clone(),
                    |tx, (seg, start, end, owned_end)| {
                        if stop_workers.load(Ordering::Relaxed) {
                            return;
                        }
                        let mut batch = scan_shard(seg, start, end, arch, depth, &ctx);
                        batch.retain(|x| {
                            x.from < owned_end
                                && (min_ref_va == 0 || x.to >= min_ref_va)
                                && to_range.is_none_or(|(lo, hi)| x.to >= lo && x.to < hi)
                        });
                        if !batch.is_empty() {
                            let _ = tx.send(batch);
                        }
                    },
                );

                // Data shards (no overlap, no ownership trimming needed)
                data_shards
                    .into_par_iter()
                    .for_each_with(tx, |tx, (seg, start, end)| {
                        if stop_workers.load(Ordering::Relaxed) {
                            return;
                        }
                        let region = ScanRegion::new(seg, start, end);
                        let mut batch = arch::byte_scan_pointers(&region, ctx.data_idx, ptr_size);
                        batch.retain(|x| {
                            (min_ref_va == 0 || x.to >= min_ref_va)
                                && to_range.is_none_or(|(lo, hi)| x.to >= lo && x.to < hi)
                        });
                        if !batch.is_empty() {
                            let _ = tx.send(batch);
                        }
                    });
            });

            // Drop scan tx so scan channel closes → drain thread exits → drops
            // out_tx → output channel closes → output thread exits.
            drop(tx);
            drain.join().expect("drain thread panicked");
            output.join().expect("output thread panicked")
        });

        let bytes_scanned: u64 = self
            .binary
            .segments
            .iter()
            .map(|s| s.data.len() as u64)
            .sum();
        let segments_scanned = self.binary.segments.len();

        PassResult {
            elapsed_ms: t0.elapsed().as_millis() as u64,
            segments_scanned,
            bytes_scanned,
            xref_count,
            confidence_counts,
        }
    }
}

/// Shared read-only context threaded into every shard scanner.
/// Bundles the two indices so `scan_shard` stays under the clippy
/// `too_many_arguments` limit (7).
struct ScanCtx<'a> {
    all_segs: &'a [Segment],
    seg_idx: &'a SegmentIndex,
    data_idx: &'a SegmentDataIndex,
    /// GOT slot VA → extern VA (from `LoadedBinary::got_map`).
    got_map: &'a std::collections::HashMap<u64, u64>,
}

fn scan_shard(
    seg: &Segment,
    start_va: u64,
    end_va: u64,
    arch: Arch,
    depth: Depth,
    ctx: &ScanCtx<'_>,
) -> Vec<Xref> {
    let region = ScanRegion::new(seg, start_va, end_va);

    match (arch, seg.mode, depth) {
        // ARM64 — always Default mode at this point (Thumb handled separately)
        (Arch::Arm64, DecodeMode::Default, Depth::Linear) => {
            arm64::scan_linear(&region, ctx.all_segs, ctx.seg_idx, ctx.data_idx)
        }
        (Arch::Arm64, DecodeMode::Default, Depth::Paired)
        | (Arch::Arm64, DecodeMode::Default, Depth::ByteScan) => {
            // ByteScan on code segs still does linear (data scan handled separately)
            arm64::scan_adrp(&region, ctx.all_segs, ctx.seg_idx, ctx.data_idx)
        }
        // ARM32 / Thumb — stub for now
        (Arch::Arm32, _, _)
        | (Arch::Arm64, DecodeMode::Thumb, _)
        | (Arch::Arm64, DecodeMode::Arm32, _) => {
            vec![] // TODO: arm32 pass
        }
        // x86-64
        (Arch::X86_64, _, Depth::Linear) | (Arch::X86_64, _, Depth::ByteScan) => {
            x86_64::scan_linear(
                &region,
                ctx.all_segs,
                ctx.seg_idx,
                ctx.data_idx,
                ctx.got_map,
            )
        }
        (Arch::X86_64, _, Depth::Paired) => x86_64::scan_with_prop(
            &region,
            ctx.all_segs,
            ctx.seg_idx,
            ctx.data_idx,
            ctx.got_map,
        ),
        // x86 32-bit — stub
        (Arch::X86, _, _) => {
            vec![] // TODO: x86 32-bit pass
        }
        (Arch::Unknown, _, _) => vec![],
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loader::{Arch, DecodeMode, Segment};
    use crate::xref::XrefKind;
    use ahash::AHashSet;

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// Encode an ARM64 BL instruction: BL <target>.
    /// `pc` is the address of the instruction, `target` is the call target.
    /// Panics if target is out of the ±128 MiB BL range.
    fn arm64_bl(pc: u64, target: u64) -> u32 {
        let offset = (target as i64) - (pc as i64);
        assert!(offset % 4 == 0, "BL target must be 4-byte aligned");
        let imm26 = (offset >> 2) as i32;
        assert!(
            (-(1 << 25)..(1 << 25)).contains(&imm26),
            "BL offset out of range"
        );
        0x94000000u32 | (imm26 as u32 & 0x03ff_ffff)
    }

    /// Encode an ARM64 NOP.
    fn arm64_nop() -> u32 {
        0xd503201f
    }

    /// Build a synthetic code segment backed by a leaked Vec (so it's 'static).
    fn make_code_seg(va: u64, words: Vec<u32>) -> Segment {
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        let data: &'static [u8] = Box::leak(bytes.into_boxed_slice());
        Segment {
            va,
            data,
            executable: true,
            readable: true,
            writable: false,
            byte_scannable: false,
            mode: DecodeMode::Default,
            name: "test_code".to_string(),
        }
    }

    /// Build a synthetic data segment (pointer table) backed by leaked Vec.
    fn make_data_seg(va: u64, pointers: Vec<u64>) -> Segment {
        let bytes: Vec<u8> = pointers.iter().flat_map(|p| p.to_le_bytes()).collect();
        let data: &'static [u8] = Box::leak(bytes.into_boxed_slice());
        Segment {
            va,
            data,
            executable: false,
            readable: true,
            writable: true,
            byte_scannable: true,
            mode: DecodeMode::Default,
            name: "test_data".to_string(),
        }
    }

    /// Build a minimal LoadedBinary from a list of segments.
    fn make_binary(arch: Arch, segments: Vec<Segment>) -> LoadedBinary {
        LoadedBinary::from_segments(arch, segments)
    }

    /// Collect all xrefs from a streaming pass into a Vec.
    fn collect_xrefs(binary: &LoadedBinary, depth: Depth, workers: usize) -> Vec<Xref> {
        let mut all = Vec::new();
        XrefPass::new(
            binary,
            PassConfig {
                depth,
                workers,
                ..Default::default()
            },
        )
        .run(|batch| {
            all.extend_from_slice(batch);
            ControlFlow::Continue(())
        });
        all
    }

    /// Assert no duplicate (from, to, kind) triples exist in the xref list.
    fn assert_no_duplicates(xrefs: &[Xref]) {
        let mut seen: AHashSet<(u64, u64, u8)> = AHashSet::new();
        for x in xrefs {
            let key = (x.from, x.to, x.kind as u8);
            assert!(
                seen.insert(key),
                "duplicate xref: from={:#x} to={:#x} kind={:?}",
                x.from,
                x.to,
                x.kind
            );
        }
    }

    // ── Uniqueness tests ──────────────────────────────────────────────────────

    /// Basic: a handful of BL instructions, single worker.
    /// Baseline — no shard boundary interaction at all.
    #[test]
    fn test_no_duplicates_single_worker() {
        // Code at 0x1000: 8 BL instructions targeting 0x10000.
        let target_va = 0x10000u64;
        let base_va = 0x1000u64;
        let n = 8usize;
        let words: Vec<u32> = (0..n)
            .map(|i| arm64_bl(base_va + i as u64 * 4, target_va))
            .collect();

        let code_seg = make_code_seg(base_va, words);
        let tgt_seg = make_code_seg(target_va, vec![arm64_nop()]);
        let binary = make_binary(Arch::Arm64, vec![code_seg, tgt_seg]);

        let xrefs = collect_xrefs(&binary, Depth::Linear, 1);
        assert_no_duplicates(&xrefs);
        assert_eq!(xrefs.len(), n, "expected {n} xrefs, got {}", xrefs.len());
    }

    /// Multiple workers on a segment just large enough to be sharded.
    /// The overlap window is 64 bytes = 16 ARM64 instructions.
    /// We place BL instructions in and around the shard boundary.
    #[test]
    fn test_no_duplicates_multi_worker_boundary() {
        // 512 instructions = 2048 bytes. With 4 workers each shard is ~512 bytes.
        // Boundary at ~0x200, overlap=64 bytes = 16 instructions before that.
        let base_va = 0x4000u64;
        let target_va = 0x100000u64;
        let n = 512usize;
        let words: Vec<u32> = (0..n)
            .map(|i| arm64_bl(base_va + i as u64 * 4, target_va))
            .collect();

        let code_seg = make_code_seg(base_va, words);
        let tgt_seg = make_code_seg(target_va, vec![arm64_nop()]);
        let binary = make_binary(Arch::Arm64, vec![code_seg, tgt_seg]);

        // Run with several worker counts to stress different shard splits.
        for workers in [2, 4, 8, 16] {
            let xrefs = collect_xrefs(&binary, Depth::Linear, workers);
            assert_no_duplicates(&xrefs);
            assert_eq!(
                xrefs.len(),
                n,
                "workers={workers}: expected {n} xrefs, got {}",
                xrefs.len()
            );
        }
    }

    /// Adversarial: BL instruction placed exactly at the overlap boundary VA.
    /// It must appear exactly once — owned by exactly one shard.
    #[test]
    fn test_no_duplicates_xref_at_exact_boundary() {
        // With overlap=64 and 2 workers over 256 instructions (1024 bytes):
        // shard 0: [base, base+512+64) — owns [base, base+512)
        // shard 1: [base+512, base+1024) — owns [base+512, base+1024)
        // Place a BL exactly at base+512 (the boundary) — must appear once.
        let base_va = 0x8000u64;
        let target_va = 0x200000u64;
        let overlap: u64 = 64; // matches PassConfig default
        let shard_boundary = base_va + 512; // 128 instructions in

        let n = 256usize;
        let words: Vec<u32> = (0..n)
            .map(|i| {
                let va = base_va + i as u64 * 4;
                if va == shard_boundary {
                    arm64_bl(va, target_va)
                } else {
                    arm64_nop()
                }
            })
            .collect();

        let code_seg = make_code_seg(base_va, words);
        let tgt_seg = make_code_seg(target_va, vec![arm64_nop()]);
        let binary = make_binary(Arch::Arm64, vec![code_seg, tgt_seg]);

        let config = PassConfig {
            depth: Depth::Linear,
            workers: 2,
            boundary_overlap: overlap,
            ..Default::default()
        };
        let mut xrefs = Vec::new();
        XrefPass::new(&binary, config).run(|batch| {
            xrefs.extend_from_slice(batch);
            ControlFlow::Continue(())
        });

        assert_no_duplicates(&xrefs);
        assert_eq!(
            xrefs.len(),
            1,
            "expected exactly 1 xref at boundary, got {}",
            xrefs.len()
        );
        assert_eq!(xrefs[0].from, shard_boundary);
    }

    /// Adversarial: xref at `owned_end - 4` (last owned instruction).
    /// Must be emitted, not suppressed.
    #[test]
    fn test_xref_at_last_owned_instruction_emitted() {
        let base_va = 0xc000u64;
        let target_va = 0x300000u64;
        let overlap: u64 = 64;
        // 2 workers, 256 instructions: shard 0 owns [base, base+512)
        // Last owned instruction of shard 0: base + 512 - 4 = base + 508
        let last_owned = base_va + 512 - 4;

        let n = 256usize;
        let words: Vec<u32> = (0..n)
            .map(|i| {
                let va = base_va + i as u64 * 4;
                if va == last_owned {
                    arm64_bl(va, target_va)
                } else {
                    arm64_nop()
                }
            })
            .collect();

        let code_seg = make_code_seg(base_va, words);
        let tgt_seg = make_code_seg(target_va, vec![arm64_nop()]);
        let binary = make_binary(Arch::Arm64, vec![code_seg, tgt_seg]);

        let config = PassConfig {
            depth: Depth::Linear,
            workers: 2,
            boundary_overlap: overlap,
            ..Default::default()
        };
        let mut xrefs = Vec::new();
        XrefPass::new(&binary, config).run(|batch| {
            xrefs.extend_from_slice(batch);
            ControlFlow::Continue(())
        });

        assert_no_duplicates(&xrefs);
        assert_eq!(xrefs.len(), 1, "last owned instruction must be emitted");
        assert_eq!(xrefs[0].from, last_owned);
    }

    /// Single-shard segment: segment smaller than the overlap window.
    /// The one shard is also the last — must emit all instructions including
    /// those in the overlap tail (there is no next shard to own them).
    #[test]
    fn test_single_shard_emits_all() {
        // 4 instructions = 16 bytes, well below the 64-byte overlap window.
        // With 1 worker this is definitively a single shard.
        let base_va = 0x10000u64;
        let target_va = 0x400000u64;
        let n = 4usize;
        let words: Vec<u32> = (0..n)
            .map(|i| arm64_bl(base_va + i as u64 * 4, target_va))
            .collect();

        let code_seg = make_code_seg(base_va, words);
        let tgt_seg = make_code_seg(target_va, vec![arm64_nop()]);
        let binary = make_binary(Arch::Arm64, vec![code_seg, tgt_seg]);

        let xrefs = collect_xrefs(&binary, Depth::Linear, 1);
        assert_no_duplicates(&xrefs);
        assert_eq!(xrefs.len(), n, "single shard must emit all {n} xrefs");
    }

    /// Segment smaller than overlap with multiple workers: split_range will
    /// collapse to fewer shards than workers due to alignment snapping.
    /// Whatever shards are produced, no duplicates and no xrefs lost.
    #[test]
    fn test_tiny_segment_many_workers_no_duplicates() {
        let base_va = 0x20000u64;
        let target_va = 0x500000u64;
        // 16 instructions = 64 bytes, exactly equal to the default overlap.
        let n = 16usize;
        let words: Vec<u32> = (0..n)
            .map(|i| arm64_bl(base_va + i as u64 * 4, target_va))
            .collect();

        let code_seg = make_code_seg(base_va, words);
        let tgt_seg = make_code_seg(target_va, vec![arm64_nop()]);
        let binary = make_binary(Arch::Arm64, vec![code_seg, tgt_seg]);

        for workers in [1, 4, 8, 32] {
            let xrefs = collect_xrefs(&binary, Depth::Linear, workers);
            assert_no_duplicates(&xrefs);
            assert_eq!(
                xrefs.len(),
                n,
                "workers={workers}: tiny segment must emit all {n} xrefs"
            );
        }
    }

    /// Data segment pointer scan: zero overlap, no ownership trimming.
    /// Every pointer must appear exactly once regardless of worker count.
    #[test]
    fn test_no_duplicates_data_segment_pointers() {
        // Code segment must be above 0x0100_0000 — byte_scan_pointers filters
        // exec-segment targets below that threshold as ASCII-string false positives.
        let code_va = 0x0200_0000u64;
        let data_va = 0x0400_0000u64;
        let n = 128usize;

        // All pointers target the code segment — all should be emitted.
        let pointers: Vec<u64> = (0..n).map(|i| code_va + i as u64 * 4).collect();
        let code_words: Vec<u32> = (0..n).map(|_| arm64_nop()).collect();

        let code_seg = make_code_seg(code_va, code_words);
        let data_seg = make_data_seg(data_va, pointers);
        let binary = make_binary(Arch::Arm64, vec![code_seg, data_seg]);

        for workers in [1, 2, 4, 8] {
            let xrefs = collect_xrefs(&binary, Depth::ByteScan, workers);
            assert_no_duplicates(&xrefs);
            // Every pointer should land exactly once
            let data_ptr_count = xrefs
                .iter()
                .filter(|x| x.kind == XrefKind::DataPointer)
                .count();
            assert_eq!(
                data_ptr_count, n,
                "workers={workers}: expected {n} DataPointer xrefs, got {data_ptr_count}"
            );
        }
    }

    /// Stress: large segment, many workers, dense BL instructions everywhere.
    /// No duplicate should survive regardless of how shards are cut.
    #[test]
    fn test_no_duplicates_stress_large_segment() {
        let base_va = 0x40000u64;
        let target_va = 0x1000000u64;
        // 4096 instructions = 16 KiB
        let n = 4096usize;
        let words: Vec<u32> = (0..n)
            .map(|i| arm64_bl(base_va + i as u64 * 4, target_va))
            .collect();

        let code_seg = make_code_seg(base_va, words);
        let tgt_seg = make_code_seg(target_va, vec![arm64_nop()]);
        let binary = make_binary(Arch::Arm64, vec![code_seg, tgt_seg]);

        for workers in [1, 3, 7, 13, 32] {
            let xrefs = collect_xrefs(&binary, Depth::Linear, workers);
            assert_no_duplicates(&xrefs);
            assert_eq!(
                xrefs.len(),
                n,
                "workers={workers}: expected {n}, got {}",
                xrefs.len()
            );
        }
    }

    /// Coverage: xref exactly at the first instruction of the segment must appear.
    #[test]
    fn test_xref_at_segment_start_emitted() {
        let base_va = 0x50000u64;
        let target_va = 0x2000000u64;
        let n = 64usize;
        let mut words: Vec<u32> = vec![arm64_nop(); n];
        words[0] = arm64_bl(base_va, target_va); // first instruction

        let code_seg = make_code_seg(base_va, words);
        let tgt_seg = make_code_seg(target_va, vec![arm64_nop()]);
        let binary = make_binary(Arch::Arm64, vec![code_seg, tgt_seg]);

        for workers in [1, 2, 4, 8] {
            let xrefs = collect_xrefs(&binary, Depth::Linear, workers);
            assert_no_duplicates(&xrefs);
            assert_eq!(
                xrefs.len(),
                1,
                "workers={workers}: segment-start xref missing"
            );
            assert_eq!(xrefs[0].from, base_va);
        }
    }

    /// Coverage: xref at the very last instruction of the segment must appear.
    #[test]
    fn test_xref_at_segment_end_emitted() {
        let base_va = 0x60000u64;
        let target_va = 0x3000000u64;
        let n = 64usize;
        let mut words: Vec<u32> = vec![arm64_nop(); n];
        words[n - 1] = arm64_bl(base_va + (n as u64 - 1) * 4, target_va);

        let code_seg = make_code_seg(base_va, words);
        let tgt_seg = make_code_seg(target_va, vec![arm64_nop()]);
        let binary = make_binary(Arch::Arm64, vec![code_seg, tgt_seg]);

        for workers in [1, 2, 4, 8] {
            let xrefs = collect_xrefs(&binary, Depth::Linear, workers);
            assert_no_duplicates(&xrefs);
            assert_eq!(
                xrefs.len(),
                1,
                "workers={workers}: segment-end xref missing"
            );
        }
    }

    /// Multiple segments: uniqueness must hold across all segments combined.
    #[test]
    fn test_no_duplicates_multiple_segments() {
        let target_va = 0x5000000u64;
        let mut segs = vec![make_code_seg(target_va, vec![arm64_nop()])];

        // Three separate code segments, each with dense BL instructions.
        for s in 0..3u64 {
            let base = 0x100000u64 + s * 0x10000;
            let n = 256usize;
            let words: Vec<u32> = (0..n)
                .map(|i| arm64_bl(base + i as u64 * 4, target_va))
                .collect();
            segs.push(make_code_seg(base, words));
        }

        let binary = make_binary(Arch::Arm64, segs);
        for workers in [1, 4, 8] {
            let xrefs = collect_xrefs(&binary, Depth::Linear, workers);
            assert_no_duplicates(&xrefs);
            // 3 segments × 256 BL instructions = 768 unique (from, to, kind) triples
            assert_eq!(xrefs.len(), 768, "workers={workers}: got {}", xrefs.len());
        }
    }
}
