//! ARM64 xref extraction — three depth levels.
//!
//! Depth 0 (byte scan): handled by arch::byte_scan_pointers — not here.
//!
//! Depth 1 (linear immediate): decode each 4-byte word as an ARM64 instruction,
//! emit xrefs only for instructions with immediate targets (BL, B, Bcc, CBZ, TBZ).
//! Misses ADRP+completing pairs — that's depth 2.
//!
//! Depth 2 (ADRP pairing): sliding window that tracks pending ADRP page values
//! per register. When a completing instruction (ADD/LDR/STR with matching reg)
//! follows, resolve the full address. Also handles BLR/BR where the target
//! register was set by an ADRP+ADD.
//!
//! Thumb / ARM32: not implemented here — stub returns empty. Will be a separate
//! pass in arm32.rs when needed.

use super::{ScanRegion, SegmentDataIndex, SegmentIndex, XrefSet};
use crate::arch::arm64_decode::Arm64Insn;
use crate::va::Va;
use crate::xref::{Confidence, Xref, XrefKind};

// How many instructions back we look for an ADRP that feeds the current insn.
// 8 is generous — in practice ADRP+ADD are 1-3 instructions apart.
// Larger window catches more but also more false positives from dead registers.
const ADRP_WINDOW: usize = 8;

/// Depth 1: linear scan, immediate targets only.
/// No register tracking. Fast, no false positives on immediate targets.
pub(crate) fn scan_linear(
    region: &ScanRegion,
    idx: &SegmentIndex,
    _data_idx: &SegmentDataIndex,
) -> XrefSet {
    let mut xrefs = Vec::new();
    let data = region.data;
    let base = region.base_va.raw();

    // ARM64: all instructions are exactly 4 bytes, 4-byte aligned.
    // If base_va is not 4-byte aligned something is wrong with the loader.
    if !base.is_multiple_of(4) {
        return xrefs;
    }

    let n = data.len() / 4;
    for i in 0..n {
        let offset = i * 4;
        let va = base + offset as u64;
        let word = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
        let insn = Arm64Insn::decode(word);
        if let Some(xref) = immediate_xref(insn, va, idx) {
            xrefs.push(xref);
        }
    }
    xrefs
}

/// Depth 2: ADRP pairing + all depth-1 refs.
/// Returns combined set — superset of depth 1.
pub(crate) fn scan_adrp(
    region: &ScanRegion,
    idx: &SegmentIndex,
    data_idx: &SegmentDataIndex,
) -> XrefSet {
    let mut xrefs = Vec::new();
    let data = region.data;
    let base = region.base_va.raw();

    if !base.is_multiple_of(4) {
        return xrefs;
    }

    let n = data.len() / 4;

    // Sliding window: for each register, track the most recent ADRP or chained-LDR
    // value that set it.
    // Key: register number (0-30, 31=XZR/SP — we ignore XZR).
    // Value: (insn_index, origin_va, page_or_value, is_chain)
    //   - insn_index: instruction index when the value was set
    //   - origin_va: ADRP VA (for real ADRP entries) or LDR VA (for chained entries)
    //   - page_or_value: the resolved address/value
    //   - is_chain: true if this came from a LDR pointer-follow (NOT usable for BLR/BR)
    //
    // IDA records data_ptr xrefs with from=ADRP_VA (not the completing insn).
    // We store the origin VA so we can emit at the right address.
    let mut adrp_state: [Option<(usize, u64, u64, bool)>; 32] = [None; 32];

    for i in 0..n {
        let offset = i * 4;
        let va = base + offset as u64;
        let word = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());

        // Fast-path: most instructions are not in the tracked set (BL/B/ADRP/ADD/LDR/STR/…).
        // For those we only need to invalidate their destination register — skip full decode.
        if !Arm64Insn::is_tracked(word) {
            let rd = (word & 0x1F) as usize;
            if rd < 31 {
                adrp_state[rd] = None;
            }
            continue;
        }

        let insn = Arm64Insn::decode(word);

        // First: try immediate xref (depth 1 — included here too)
        if let Some(xref) = immediate_xref(insn, va, idx) {
            xrefs.push(xref);
        }

        // Second: ADRP tracking
        match insn {
            Arm64Insn::Adrp(_) => {
                // ADRP Xn, #imm
                // Sets Xn to (PC & ~0xFFF) + (imm << 12)
                // We store (insn_index, adrp_va, page_value) so the completing
                // instruction can emit from=ADRP_VA (matching IDA's convention).
                let rd = insn.rd() as usize;
                if rd < 31 {
                    let page = insn.adrp_page(va);
                    adrp_state[rd] = Some((i, va, page, false));
                }
            }

            Arm64Insn::Adr(_) => {
                // ADR Xn, #label — PC-relative precise address (not page-aligned).
                // No data_ptr is emitted (analysis: 3949 FPs, 0 TPs vs IDA).
                // We DO track the value in state so downstream stores/loads via
                // this register can be resolved (e.g. STLXR [x19] where ADR set x19).
                let rd = insn.rd() as usize;
                if rd < 31 {
                    let target = insn.adr_target(va);
                    // Store with adrp_va = va (the ADR instruction itself).
                    // is_chain=false so BLR/BR can use it.
                    adrp_state[rd] = Some((i, va, target, false));
                }
            }

            Arm64Insn::AddImm(_) => {
                // ADD Xd, Xn, #imm  — completes ADRP+ADD pairs.
                //
                // IDA records data_ptr at the ADRP VA (primary) and sometimes at the
                // ADD VA (secondary). Analysis shows that emitting the secondary ADD-VA
                // xref causes ~6981 FPs for only ~454 TPs gained. The FPs arise because
                // IDA only emits ADD-VA when the target is a named/symbolic address —
                // a condition we can't determine without IDA's symbol database. So we
                // emit ONLY at ADRP_VA (matching the primary convention), not at ADD_VA.
                let rd = insn.rd() as usize;
                let rn = insn.rn() as usize;
                if rn < 31 {
                    if let Some((adrp_i, adrp_va, page, _chain)) = adrp_state[rn] {
                        if i - adrp_i <= ADRP_WINDOW {
                            let offset_val = insn.add_imm();
                            let target = page.wrapping_add(offset_val);
                            if idx.contains(Va(target)) {
                                // Emit only at ADRP VA (IDA's primary convention).
                                // Do NOT emit at ADD VA — analysis shows this causes
                                // massive FPs (~6981) vs minimal TP gain (~454).
                                xrefs.push(Xref {
                                    from: Va(adrp_va),
                                    to: Va(target),
                                    kind: XrefKind::DataPointer,
                                    confidence: Confidence::PairResolved,
                                });
                            }
                            // Update state: dst_reg now holds the resolved addr.
                            if rd < 31 {
                                adrp_state[rd] = Some((i, adrp_va, target, false));
                            }
                            if rd != rn {
                                adrp_state[rn] = None;
                            }
                        }
                    }
                }
            }

            Arm64Insn::Ldr(_) => {
                // LDR Xt/Wt/Ht/Bt, [Xm, #imm]  — completes ADRP+LDR pairs.
                //
                // For 64-bit loads, IDA emits:
                //   1. data_ptr at ADRP_VA, to=addr  (the ADRP points to the page)
                //   2. data_read at LDR_VA, to=addr  (reading from the slot)
                //   3. data_ptr at LDR_VA, to=*(addr) (pointer-follow, 64-bit only)
                //
                // For sub-64-bit loads (LDRW/LDRH/LDRB), IDA emits data_ptr + data_read
                // but no pointer-follow (loaded value is not a valid 64-bit pointer).
                //
                // IMPORTANT: snapshot adrp_state[rn] BEFORE clearing adrp_state[rt],
                // because Rt == Rn is common (e.g. `ADRP X0, page; LDR X0, [X0, #off]`).

                let rt = insn.rd() as usize;
                let rn = insn.rn() as usize;
                let is_64bit = insn.ldr_str_size() == 3;

                // Snapshot the base register's ADRP state before any invalidation.
                let base_state = if rn < 31 { adrp_state[rn] } else { None };

                // Clear Rt — LDR overwrites the destination register.
                // (Refined to the loaded value inside the resolved branch below.)
                if rt < 31 {
                    adrp_state[rt] = None;
                }

                if let Some((adrp_i, adrp_va, page, _chain)) = base_state {
                    if i - adrp_i <= ADRP_WINDOW {
                        let addr = page.wrapping_add(insn.ldr_str_offset());
                        let addr_is_exec = idx.is_exec(Va(addr));

                        // ADRP → data_ptr to target address (matching IDA's data_ptr at ADRP)
                        if idx.contains(Va(addr)) {
                            xrefs.push(Xref {
                                from: Va(adrp_va),
                                to: Va(addr),
                                kind: XrefKind::DataPointer,
                                confidence: Confidence::PairResolved,
                            });
                        }

                        if idx.contains(Va(addr)) {
                            // data_read at LDR_va → resolved address (IDA dr_R).
                            xrefs.push(Xref {
                                from: Va(va),
                                to: Va(addr),
                                kind: XrefKind::DataRead,
                                confidence: Confidence::PairResolved,
                            });
                        }

                        // Pointer-follow: only for 64-bit loads from non-exec segments.
                        // Sub-64-bit loads produce truncated values, not valid pointers.
                        let stored_val: Option<u64> = if is_64bit && !addr_is_exec {
                            data_idx
                                .read_u64_at_nonexec(Va(addr))
                                .filter(|&v| v != 0 && idx.contains(Va(v)))
                        } else {
                            None
                        };

                        if let Some(v) = stored_val {
                            xrefs.push(Xref {
                                from: Va(va),
                                to: Va(v),
                                kind: XrefKind::DataPointer,
                                confidence: Confidence::PairResolved,
                            });
                        }

                        // Propagate loaded value for chained resolution (64-bit only).
                        if let Some(v) = stored_val {
                            if rt < 31 {
                                adrp_state[rt] = Some((i, va, v, true));
                            }
                        }
                    }
                }
            }

            Arm64Insn::Str(_) => {
                // STR Xn, [Xm, #imm]  — data write via ADRP-resolved address.
                // IDA classifies stores as data_write (dr_W).
                // Suppress if target is executable (IDA doesn't record these).
                let rn = insn.rn() as usize;
                if rn < 31 {
                    if let Some((adrp_i, _adrp_va, page, _chain)) = adrp_state[rn] {
                        if i - adrp_i <= ADRP_WINDOW {
                            let addr = page.wrapping_add(insn.ldr_str_offset());
                            // Suppress writes to exec or read-only segments: IDA doesn't record
                            // data_write to .text or .rodata. Only writable data segments matter.
                            // A segment is writable iff FLAG_WRITE is set and FLAG_EXEC is clear.
                            let is_writable_data = idx.flags_at(Va(addr)).is_some_and(|f| {
                                f & super::FLAG_WRITE != 0 && f & super::FLAG_EXEC == 0
                            });
                            if is_writable_data {
                                xrefs.push(Xref {
                                    from: Va(va),
                                    to: Va(addr),
                                    kind: XrefKind::DataWrite,
                                    confidence: Confidence::PairResolved,
                                });
                            }
                        }
                    }
                }
            }

            Arm64Insn::Blr(_) => {
                // BLR Xn — indirect call, try to resolve from ADRP state.
                // Only resolve if the register value came from a real ADRP (not a chain),
                // since chained values are data pointers, not callable addresses.
                //
                // Only emit if the target is an executable internal address.
                // Extern VA resolution (via got_map) is intentionally NOT done here:
                // IDA's extern VA assignment order does not match dynsym sequence order,
                // so got_map-derived extern VAs produce wrong targets and pure FPs.
                let rn = insn.rn() as usize;
                if rn < 31 {
                    if let Some((adrp_i, _adrp_va, target, is_chain)) = adrp_state[rn] {
                        if !is_chain && i - adrp_i <= ADRP_WINDOW && idx.is_exec(Va(target)) {
                            xrefs.push(Xref {
                                from: Va(va),
                                to: Va(target),
                                kind: XrefKind::Call,
                                confidence: Confidence::PairResolved,
                            });
                        }
                    }
                }
            }

            Arm64Insn::Br(_) => {
                // BR Xn — indirect jump, try to resolve (only non-chain values).
                // Require the target to be an executable internal address.
                // Extern VA resolution is intentionally NOT done here (same reason as BLR).
                let rn = insn.rn() as usize;
                if rn < 31 {
                    if let Some((adrp_i, _adrp_va, target, is_chain)) = adrp_state[rn] {
                        if !is_chain && i - adrp_i <= ADRP_WINDOW && idx.is_exec(Va(target)) {
                            xrefs.push(Xref {
                                from: Va(va),
                                to: Va(target),
                                kind: XrefKind::Jump,
                                confidence: Confidence::PairResolved,
                            });
                        }
                    }
                }
            }

            // Any instruction that writes to a register we're tracking
            // should invalidate that register's ADRP state.
            // We do a conservative invalidation: if the destination register
            // is in our table and this instruction isn't one we already handled,
            // clear it. ARM64 destination is bits[4:0] for most encodings.
            Arm64Insn::LdrLiteral(_)
            | Arm64Insn::Bl(_)
            | Arm64Insn::B(_)
            | Arm64Insn::BCond(_)
            | Arm64Insn::Cbz(_)
            | Arm64Insn::Cbnz(_)
            | Arm64Insn::Tbz(_)
            | Arm64Insn::Tbnz(_)
            | Arm64Insn::Other(_) => {
                let rd = insn.rd() as usize;
                if rd < 31 {
                    adrp_state[rd] = None;
                }
            }
        }
    }

    xrefs
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Extract an immediate xref from instructions with direct targets.
#[inline(always)]
fn immediate_xref(insn: Arm64Insn, va: u64, idx: &SegmentIndex) -> Option<Xref> {
    match insn {
        Arm64Insn::Bl(_) => {
            let target = insn.imm26_target(va);
            // IDA records calls only to executable addresses. Suppress BL to non-exec
            // (e.g. BL to .rodata in dead code regions — IDA never records these).
            if idx.contains(Va(target)) && idx.is_exec(Va(target)) {
                Some(Xref {
                    from: Va(va),
                    to: Va(target),
                    kind: XrefKind::Call,
                    confidence: Confidence::LinearImmediate,
                })
            } else {
                None
            }
        }
        Arm64Insn::B(_) => {
            let target = insn.imm26_target(va);
            if idx.contains(Va(target)) {
                Some(Xref {
                    from: Va(va),
                    to: Va(target),
                    kind: XrefKind::Jump,
                    confidence: Confidence::LinearImmediate,
                })
            } else {
                None
            }
        }
        Arm64Insn::BCond(_) => {
            let target = insn.imm19_target(va);
            if idx.contains(Va(target)) {
                Some(Xref {
                    from: Va(va),
                    to: Va(target),
                    kind: XrefKind::CondJump,
                    confidence: Confidence::LinearImmediate,
                })
            } else {
                None
            }
        }
        Arm64Insn::Cbz(_) | Arm64Insn::Cbnz(_) => {
            // CBZ/CBNZ Xn, #label — label is second operand
            let target = insn.cbz_target(va);
            if idx.contains(Va(target)) {
                Some(Xref {
                    from: Va(va),
                    to: Va(target),
                    kind: XrefKind::CondJump,
                    confidence: Confidence::LinearImmediate,
                })
            } else {
                None
            }
        }
        Arm64Insn::Tbz(_) | Arm64Insn::Tbnz(_) => {
            // TBZ/TBNZ Xn, #bit, #label — label is third operand
            let target = insn.imm14_target(va);
            if idx.contains(Va(target)) {
                Some(Xref {
                    from: Va(va),
                    to: Va(target),
                    kind: XrefKind::CondJump,
                    confidence: Confidence::LinearImmediate,
                })
            } else {
                None
            }
        }
        Arm64Insn::LdrLiteral(_) => {
            // LDR Xt/Wt, label — PC-relative literal load.
            // IDA records data_read at this VA to the literal pool address.
            let target = insn.ldr_literal_target(va);
            if idx.contains(Va(target)) {
                Some(Xref {
                    from: Va(va),
                    to: Va(target),
                    kind: XrefKind::DataRead,
                    confidence: Confidence::LinearImmediate,
                })
            } else {
                None
            }
        }
        Arm64Insn::Adr(_) => {
            // ADR Xn, #label — PC-relative, computes address (not page-aligned).
            //
            // IDA does NOT record ADR as data_ptr. Analysis of 3949 ADR-sourced
            // data_ptr emissions confirmed zero overlap with IDA ground truth —
            // IDA has no xrefs at any of those source addresses. Suppressing ADR
            // eliminates 3949 FPs with no TP loss.
            //
            // We do still track the value in ADRP state so downstream instructions
            // (e.g. STLXR w10, w30, [x19] where x19 was set by ADR) can resolve.
            None
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::{ScanRegion, SegmentDataIndex};
    use crate::loader::{DecodeMode, Segment};
    use crate::xref::{Confidence, XrefKind};

    /// Build a fake executable segment covering exactly the given bytes at `base_va`.
    fn fake_seg(base_va: u64, data: &'static [u8]) -> Segment {
        Segment {
            va: Va(base_va),
            data,
            executable: true,
            readable: true,
            writable: false,
            byte_scannable: true,
            mode: DecodeMode::Default,
            name: "test".to_string(),
        }
    }

    fn region_for<'a>(seg: &'a Segment) -> ScanRegion<'a> {
        ScanRegion::new(seg, seg.va, seg.va + seg.data.len() as u64)
    }

    // ── BL ────────────────────────────────────────────────────────────────────

    /// BL #0x1010 from PC 0x1000 (imm26=+4 words)
    /// Encoding: 0x94000004
    #[test]
    fn test_bl_call() {
        // Code lives at 0x1000 (4 bytes). Target 0x1010 must be in a segment too.
        // We fake two segments: code at 0x1000 and a target page at 0x1010.
        static CODE: [u8; 4] = [0x04, 0x00, 0x00, 0x94]; // BL +16
        static TARGET: [u8; 4] = [0x00, 0x00, 0x00, 0x00];
        let code_seg = fake_seg(0x1000, &CODE);
        let tgt_seg = fake_seg(0x1010, &TARGET);
        let segs = vec![fake_seg(0x1000, &CODE), tgt_seg];

        let region = region_for(&code_seg);
        let idx = SegmentIndex::build(&segs);
        let didx = SegmentDataIndex::build(&segs);
        let xrefs = scan_linear(&region, &idx, &didx);

        assert_eq!(xrefs.len(), 1);
        assert_eq!(xrefs[0].from, Va(0x1000));
        assert_eq!(xrefs[0].to, Va(0x1010));
        assert_eq!(xrefs[0].kind, XrefKind::Call);
        assert_eq!(xrefs[0].confidence, Confidence::LinearImmediate);
    }

    // ── B (unconditional jump) ────────────────────────────────────────────────

    /// B +8 from 0x1008 (imm26=+2 words) → target 0x1010
    /// Encoding: 0x14000002
    #[test]
    fn test_b_jump() {
        static CODE: [u8; 4] = [0x02, 0x00, 0x00, 0x14];
        static TARGET: [u8; 4] = [0x00, 0x00, 0x00, 0x00];
        let code_seg = fake_seg(0x1008, &CODE);
        let tgt_seg = fake_seg(0x1010, &TARGET);
        let segs = vec![fake_seg(0x1008, &CODE), tgt_seg];

        let idx = SegmentIndex::build(&segs);
        let didx = SegmentDataIndex::build(&segs);
        let xrefs = scan_linear(&region_for(&code_seg), &idx, &didx);
        assert_eq!(xrefs.len(), 1);
        assert_eq!(xrefs[0].from, Va(0x1008));
        assert_eq!(xrefs[0].to, Va(0x1010));
        assert_eq!(xrefs[0].kind, XrefKind::Jump);
    }

    // ── CBZ ───────────────────────────────────────────────────────────────────

    /// CBZ X1, -4 (1 insn back = 0x1004) from PC 0x1008.
    /// Encoding: 0xb4ffffe1
    #[test]
    fn test_cbz_cond_jump() {
        static CODE: [u8; 8] = [
            0x00, 0x00, 0x00, 0x00, // padding at 0x1004 (NOP-like, just zeroes)
            0xe1, 0xff, 0xff, 0xb4, // CBZ X1, -4  at 0x1008
        ];
        let seg = fake_seg(0x1004, &CODE);
        let segs = vec![fake_seg(0x1004, &CODE)];

        let idx = SegmentIndex::build(&segs);
        let didx = SegmentDataIndex::build(&segs);
        let xrefs = scan_linear(&region_for(&seg), &idx, &didx);
        // CBZ at 0x1008 → target 0x1004
        let cbz_xref = xrefs.iter().find(|x| x.from == Va(0x1008)).unwrap();
        assert_eq!(cbz_xref.to, Va(0x1004));
        assert_eq!(cbz_xref.kind, XrefKind::CondJump);
    }

    // ── ADRP + ADD pair ───────────────────────────────────────────────────────

    /// ADRP X0, #1 (page = 0x2000) at 0x1000
    /// ADD  X0, X0, #0x100        at 0x1004
    /// → PairResolved DataRead from 0x1000 to 0x2100
    #[test]
    fn test_adrp_add_pair() {
        static CODE: [u8; 8] = [
            0x00, 0x00, 0x00, 0xb0, // ADRP X0, #1   (page = base+0x1000 = 0x2000)
            0x00, 0x00, 0x04, 0x91, // ADD X0, X0, #0x100
        ];
        static TARGET_PAGE: [u8; 0x200] = [0u8; 0x200];
        let code_seg = fake_seg(0x1000, &CODE);
        let data_seg = fake_seg(0x2000, &TARGET_PAGE);
        let segs = vec![fake_seg(0x1000, &CODE), data_seg];

        let idx = SegmentIndex::build(&segs);
        let didx = SegmentDataIndex::build(&segs);
        let xrefs = scan_adrp(&region_for(&code_seg), &idx, &didx);
        let pair = xrefs
            .iter()
            .find(|x| x.confidence == Confidence::PairResolved)
            .expect("expected a PairResolved xref");
        assert_eq!(pair.from, Va(0x1000)); // ADRP va (IDA records at ADRP, not ADD)
        assert_eq!(pair.to, Va(0x2100)); // 0x2000 + 0x100
        assert_eq!(pair.kind, XrefKind::DataPointer);
    }

    // ── ADRP + LDR with Rt == Rn (regression test) ──────────────────────────

    /// ADRP X0, page → LDR X0, [X0, #8]  (Rt == Rn == 0)
    /// This is the most common ADRP+LDR pattern. The LDR handler must snapshot
    /// the base register's ADRP state BEFORE clearing the destination register,
    /// or the pair is silently dropped (regression: data_read F1 0.906 → 0.042).
    #[test]
    fn test_adrp_ldr_same_register() {
        // ADRP X0, #1  → page = 0x2000 (from pc 0x1000)
        // LDR  X0, [X0, #8]  → addr = 0x2000 + 8 = 0x2008
        //
        // ADRP X0, #1: encoded as 0xB000_0000 (immlo=1 → +1 page, Rd=0)
        // LDR  X0, [X0, #8]: unsigned offset, imm12 = 8/8 = 1
        //   word = 0xF940_0400 | Rn=0<<5 | Rt=0 = 0xF940_0400
        static CODE: [u8; 8] = [
            0x00, 0x00, 0x00, 0xb0, // ADRP X0, #1 page
            0x00, 0x04, 0x40, 0xf9, // LDR X0, [X0, #8]
        ];
        // Data segment at 0x2000 so target 0x2008 is valid.
        static DATA: [u8; 0x100] = [0u8; 0x100];
        let code_seg = fake_seg(0x1000, &CODE);
        let segs = vec![fake_seg(0x1000, &CODE), Segment {
            va: Va(0x2000),
            data: &DATA,
            executable: false,
            readable: true,
            writable: false,
            byte_scannable: false,
            mode: DecodeMode::Default,
            name: "data".to_string(),
        }];

        let idx = SegmentIndex::build(&segs);
        let didx = SegmentDataIndex::build(&segs);
        let xrefs = scan_adrp(&region_for(&code_seg), &idx, &didx);

        // Must emit data_read at LDR VA (0x1004) → 0x2008
        let dr = xrefs
            .iter()
            .find(|x| x.kind == XrefKind::DataRead)
            .expect("ADRP+LDR with Rt==Rn must emit data_read (regression: state cleared before read)");
        assert_eq!(dr.from, Va(0x1004));
        assert_eq!(dr.to, Va(0x2008));

        // Must also emit data_ptr at ADRP VA (0x1000) → 0x2008
        let dp = xrefs
            .iter()
            .find(|x| x.kind == XrefKind::DataPointer && x.from == Va(0x1000))
            .expect("ADRP+LDR must emit data_ptr at ADRP VA");
        assert_eq!(dp.to, Va(0x2008));
    }

    // ── Target outside all segments → no xref ────────────────────────────────

    /// BL to an address not in any segment should be suppressed.
    #[test]
    fn test_bl_out_of_range_filtered() {
        static CODE: [u8; 4] = [0x04, 0x00, 0x00, 0x94]; // BL +16 → 0x1010
        let code_seg = fake_seg(0x1000, &CODE);
        // No segment covers 0x1010
        let segs = vec![fake_seg(0x1000, &CODE)];

        let idx = SegmentIndex::build(&segs);
        let didx = SegmentDataIndex::build(&segs);
        let xrefs = scan_linear(&region_for(&code_seg), &idx, &didx);
        assert!(
            xrefs.is_empty(),
            "xref to unmapped target should be suppressed"
        );
    }
}
