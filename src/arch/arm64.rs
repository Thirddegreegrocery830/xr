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

/// Maximum entries in a recovered jump table.
const MAX_JUMP_TABLE_ENTRIES: usize = 8192;

/// How this register value was resolved — determines what xref kinds it can
/// produce downstream.
#[derive(Clone, Copy, PartialEq, Eq)]
enum RegSource {
    /// Set directly by ADRP/ADR/ADD — the value is a code or data address
    /// that may be called or jumped to.
    Direct,
    /// Set by a LDR pointer-follow (chained resolution).  The value is a
    /// data pointer loaded from memory — NOT callable/jumpable.  BLR/BR
    /// must not resolve through a chain.
    Chain,
}

/// State tracked per register during the ADRP sliding-window scan.
///
/// Populated when an ADRP/ADR/ADD/LDR sets a register to a known address,
/// consumed by completing instructions (ADD, LDR, STR, BLR, BR).
#[derive(Clone, Copy)]
struct AdrpRegState {
    /// Instruction index when this value was set (for window distance check).
    insn_index: usize,
    /// VA of the ADRP (or ADR/LDR for chained entries) — xrefs are emitted
    /// with `from = origin_va` to match IDA's convention.
    origin_va: Va,
    /// The resolved page address (ADRP) or full address (ADR/ADD/LDR chain).
    value: Va,
    /// How this value was resolved — controls what downstream xrefs are valid.
    source: RegSource,
}

/// Depth 1: linear scan, immediate targets only.
/// No register tracking. Fast, no false positives on immediate targets.
pub(crate) fn scan_linear(
    region: &ScanRegion,
    idx: &SegmentIndex,
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
        let word = u32::from_le_bytes(
            data[offset..offset + 4].try_into().expect("4-byte aligned word"),
        );
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

    let mut adrp_state: [Option<AdrpRegState>; 32] = [None; 32];
    // CMP bound per register: when we see `CMP wN, #imm` (followed by B.HI),
    // record cmp_bound[N] = imm+1 (exclusive upper bound for switch index).
    let mut cmp_bound: [Option<u32>; 32] = [None; 32];

    for i in 0..n {
        let offset = i * 4;
        let va = base + offset as u64;
        let word = u32::from_le_bytes(
            data[offset..offset + 4].try_into().expect("4-byte aligned word"),
        );

        // Fast-path: most instructions are not in the tracked set (BL/B/ADRP/ADD/LDR/STR/…).
        // For those we only need to invalidate their destination register — skip full decode.
        if !Arm64Insn::is_tracked(word) {
            let rd = (word & 0x1F) as usize;
            if rd < 31 {
                adrp_state[rd] = None;
                cmp_bound[rd] = None;
            }
            // CMP Wn, #imm (= SUBS WZR, Wn, #imm): 0111_0001_00xx_xxxx_xxxx_xxnn_nnn1_1111
            // CMP Xn, #imm (= SUBS XZR, Xn, #imm): 1111_0001_00xx_xxxx_xxxx_xxnn_nnn1_1111
            // Both have Rd=11111 (XZR/WZR), so rd==31 and we skip the invalidation above.
            // We detect CMP via: bits[30:24]=1110001 or 1110001, bit[31]=size, Rd=11111.
            if rd == 31 && word & 0x7F80_0000 == 0x7100_0000 {
                let rn = ((word >> 5) & 0x1F) as usize;
                let imm12 = (word >> 10) & 0xFFF;
                let shift = (word >> 22) & 1;
                if shift == 0 && rn < 31 {
                    // cmp_bound = imm + 1 (exclusive upper bound for table size)
                    cmp_bound[rn] = Some(imm12 + 1);
                }
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
                let rd = insn.rd() as usize;
                if rd < 31 {
                    let page = insn.adrp_page(va);
                    adrp_state[rd] = Some(AdrpRegState {
                        insn_index: i,
                        origin_va: Va::new(va),
                        value: Va::new(page),
                        source: RegSource::Direct,
                    });
                    cmp_bound[rd] = None;
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
                    adrp_state[rd] = Some(AdrpRegState {
                        insn_index: i,
                        origin_va: Va::new(va),
                        value: Va::new(target),
                        source: RegSource::Direct,
                    });
                    cmp_bound[rd] = None;
                }
            }

            Arm64Insn::AddImm(_) => {
                // ADD Xd, Xn, #imm  — completes ADRP+ADD pairs.
                // Emits data_ptr at ADRP VA only (not ADD VA — ~6981 FPs vs ~454 TPs).
                let rd = insn.rd() as usize;
                let rn = insn.rn() as usize;
                if rn < 31 {
                    if let Some(st) = adrp_state[rn] {
                        if i - st.insn_index <= ADRP_WINDOW {
                            let target = st.value + insn.add_imm();
                            if idx.contains(target) {
                                xrefs.push(Xref {
                                    from: st.origin_va,
                                    to: target,
                                    kind: XrefKind::DataPointer,
                                    confidence: Confidence::PairResolved,
                                });
                            }
                            if rd < 31 {
                                adrp_state[rd] = Some(AdrpRegState {
                                    insn_index: i,
                                    origin_va: st.origin_va,
                                    value: target,
                                    source: RegSource::Direct,
                                });
                                cmp_bound[rd] = None;
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
                // IMPORTANT: snapshot adrp_state[rn] BEFORE clearing adrp_state[rt],
                // because Rt == Rn is common (e.g. `ADRP X0, page; LDR X0, [X0, #off]`).

                let rt = insn.rd() as usize;
                let rn = insn.rn() as usize;
                let is_64bit = insn.ldr_str_size() == 3;

                let base_state = if rn < 31 { adrp_state[rn] } else { None };
                if rt < 31 {
                    adrp_state[rt] = None;
                }

                if let Some(st) = base_state {
                    if i - st.insn_index <= ADRP_WINDOW {
                        let addr = st.value + insn.ldr_str_offset();
                        let addr_is_exec = idx.is_exec(addr);

                        if idx.contains(addr) {
                            // data_ptr at ADRP VA
                            xrefs.push(Xref {
                                from: st.origin_va,
                                to: addr,
                                kind: XrefKind::DataPointer,
                                confidence: Confidence::PairResolved,
                            });
                            // data_read at LDR VA
                            xrefs.push(Xref {
                                from: Va::new(va),
                                to: addr,
                                kind: XrefKind::DataRead,
                                confidence: Confidence::PairResolved,
                            });
                        }

                        // Pointer-follow: only for 64-bit loads from non-exec segments.
                        let stored_val: Option<u64> = if is_64bit && !addr_is_exec {
                            data_idx
                                .read_u64_at_nonexec(addr)
                                .filter(|&v| v != 0 && idx.contains(Va::new(v)))
                        } else {
                            None
                        };

                        if let Some(v) = stored_val {
                            xrefs.push(Xref {
                                from: Va::new(va),
                                to: Va::new(v),
                                kind: XrefKind::DataPointer,
                                confidence: Confidence::PairResolved,
                            });
                            if rt < 31 {
                                adrp_state[rt] = Some(AdrpRegState {
                                    insn_index: i,
                                    origin_va: Va::new(va),
                                    value: Va::new(v),
                                    source: RegSource::Chain,
                                });
                            }
                        }
                    }
                }
            }

            Arm64Insn::Str(_) => {
                // STR Xn, [Xm, #imm]  — data write via ADRP-resolved address.
                let rn = insn.rn() as usize;
                if rn < 31 {
                    if let Some(st) = adrp_state[rn] {
                        if i - st.insn_index <= ADRP_WINDOW {
                            let addr = st.value + insn.ldr_str_offset();
                            let is_writable_data = idx.flags_at(addr).is_some_and(|f| {
                                f.contains(super::SegFlags::WRITE) && !f.contains(super::SegFlags::EXEC)
                            });
                            if is_writable_data {
                                xrefs.push(Xref {
                                    from: Va::new(va),
                                    to: addr,
                                    kind: XrefKind::DataWrite,
                                    confidence: Confidence::PairResolved,
                                });
                            }
                        }
                    }
                }
            }

            Arm64Insn::Blr(_) => {
                // BLR Xn — indirect call via ADRP-resolved address (non-chain only).
                let rn = insn.rn() as usize;
                if rn < 31 {
                    if let Some(st) = adrp_state[rn] {
                        if st.source == RegSource::Direct && i - st.insn_index <= ADRP_WINDOW && idx.is_exec(st.value) {
                            xrefs.push(Xref {
                                from: Va::new(va),
                                to: st.value,
                                kind: XrefKind::Call,
                                confidence: Confidence::PairResolved,
                            });
                        }
                    }
                }
            }

            Arm64Insn::Br(_) => {
                // BR Xn — indirect jump via ADRP-resolved address (non-chain only).
                let rn = insn.rn() as usize;
                if rn < 31 {
                    if let Some(st) = adrp_state[rn] {
                        if st.source == RegSource::Direct && i - st.insn_index <= ADRP_WINDOW && idx.is_exec(st.value) {
                            xrefs.push(Xref {
                                from: Va::new(va),
                                to: st.value,
                                kind: XrefKind::Jump,
                                confidence: Confidence::PairResolved,
                            });
                        }
                    }
                }
                // Attempt jump table recovery by scanning backward for the
                // ADR+LDR[BH]+ADD pattern.
                recover_arm64_jump_table(
                    Va::new(va),
                    i,
                    data,
                    base,
                    &adrp_state,
                    &cmp_bound,
                    data_idx,
                    idx,
                    &mut xrefs,
                );
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
                    cmp_bound[rd] = None;
                }
            }
        }
    }

    xrefs
}

// ── Jump table recovery ─────────────────────────────────────────────────────

/// Attempt to recover an ARM64 switch-table at a `BR Xn` instruction.
///
/// The canonical compiler pattern (GCC/Clang) is:
///
/// ```text
///   CMP    wIdx, #bound                    ; range check (sets cmp_bound)
///   B.HI   default                         ; skip if out of range
///   ADRP   Xtbl, table_page                ; table address (via adrp_state)
///   ADD    Xtbl, Xtbl, #off                ; table_base
///   ADR    Xbase, after_br                  ; target base (usually BR+4)
///   LDRB   Woff, [Xtbl, wIdx, UXTW]        ; load u8 offset (or LDRH for u16)
///   ADD    Xtgt, Xbase, Xoff [, SXTB/SXTH] ; compute target
///   BR     Xtgt                             ; indirect jump
/// ```
///
/// We scan backward from the BR to find ADR (target_base), the load
/// instruction (LDRB/LDRH with a register index into a known table address),
/// and the CMP bound.  Table entries are unsigned byte or halfword offsets
/// (sometimes sign-extended in the ADD) that are added to the ADR target.
#[allow(clippy::too_many_arguments)]
fn recover_arm64_jump_table(
    br_va: Va,
    br_index: usize,
    data: &[u8],
    base: u64,
    adrp_state: &[Option<AdrpRegState>; 32],
    cmp_bound: &[Option<u32>; 32],
    data_idx: &SegmentDataIndex,
    seg_idx: &SegmentIndex,
    xrefs: &mut Vec<Xref>,
) {
    // Scan up to 8 instructions before the BR looking for the pattern.
    let lookback = br_index.min(8);

    // We need three things:
    //   1. ADR Xbase, label      → target_base
    //   2. LDRB/LDRH Woff, [Xtbl, wIdx, ...]  → table_base (from adrp_state[Xtbl]),
    //      entry_size (1 or 2), index_reg
    //   3. CMP wIdx, #bound      → max_entries from cmp_bound[index_reg]
    //
    // The ADD between the load and BR is implicit — we don't need to verify it
    // because we derive target_base from the ADR.

    let mut target_base: Option<u64> = None;
    let mut table_base: Option<Va> = None;
    let mut entry_size: u32 = 0; // 1 = byte, 2 = halfword
    let mut index_reg: usize = 32; // invalid sentinel

    for back in 1..=lookback {
        let j = br_index - back;
        let offset = j * 4;
        if offset + 4 > data.len() {
            break;
        }
        let w = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
        let insn_va = base + offset as u64;

        // ADR Xd, label
        if (w & 0x9F00_0000) == 0x1000_0000 {
            let rd = (w & 0x1F) as usize;
            let immlo = (w >> 29) & 3;
            let immhi = (w >> 5) & 0x7_FFFF;
            let mut imm = ((immhi << 2) | immlo) as i64;
            if imm & (1 << 20) != 0 {
                imm -= 1 << 21;
            }
            let adr_target = (insn_va as i64 + imm) as u64;
            // Only accept if this feeds the BR target register chain.
            // We don't strictly verify register assignment — just record
            // the ADR value closest to the BR.
            if target_base.is_none() {
                target_base = Some(adr_target);
                // If ADR Rd == load Rd (register reuse), invalidate table_base
                // match since this ADR sets the base, not the table.
                let _ = rd; // rd is consumed by ADD chain
            }
        }

        // LDRB (register): 0011_1000_011m_mmmm_xxxx_xxnn_nnnt_tttt
        if (w & 0xFFE0_0C00) == 0x3860_0800 {
            let rn = ((w >> 5) & 0x1F) as usize;
            let rm = ((w >> 16) & 0x1F) as usize;
            if rn < 31 {
                if let Some(st) = adrp_state[rn] {
                    table_base = Some(st.value);
                    entry_size = 1;
                    index_reg = rm;
                }
            }
        }

        // LDRH (register): 0111_1000_011m_mmmm_xxxx_xxnn_nnnt_tttt
        if (w & 0xFFE0_0C00) == 0x7860_0800 {
            let rn = ((w >> 5) & 0x1F) as usize;
            let rm = ((w >> 16) & 0x1F) as usize;
            if rn < 31 {
                if let Some(st) = adrp_state[rn] {
                    table_base = Some(st.value);
                    entry_size = 2;
                    index_reg = rm;
                }
            }
        }
    }

    // Need all three pieces.
    let Some(tbase) = target_base else { return };
    let Some(tbl) = table_base else { return };
    if entry_size == 0 || index_reg >= 32 {
        return;
    }

    // Table size from CMP bound.  Without CMP bound, skip to avoid FP explosion.
    let Some(bound) = cmp_bound.get(index_reg).copied().flatten() else {
        return;
    };
    let limit = (bound as usize).min(MAX_JUMP_TABLE_ENTRIES);

    // Determine the shift applied to the loaded offset.  The ADD before BR
    // almost always uses `LSL #2` (shift=0, imm6=2) or an extended-register
    // form with `imm3=2` (e.g. SXTH #2, UXTB #2).  Both mean multiply by 4.
    // We extract this from the ADD instruction word at BR-1.
    let n_insns = data.len() / 4;
    let add_shift = {
        let add_idx = br_index.wrapping_sub(1);
        if add_idx < n_insns {
            let add_off = add_idx * 4;
            let aw = u32::from_le_bytes(data[add_off..add_off + 4].try_into().unwrap());
            // ADD (shifted register): 1000_1011_xx0x_xxxx_xxxx_xxxx_xxxx_xxxx
            if aw & 0xFF20_0000 == 0x8B00_0000 {
                (aw >> 10) & 0x3F // imm6 = shift amount
            }
            // ADD (extended register): 1000_1011_001x_xxxx_xxxx_xxxx_xxxx_xxxx
            else if aw & 0xFFE0_0000 == 0x8B20_0000 {
                (aw >> 10) & 7 // imm3 = shift amount
            } else {
                0
            }
        } else {
            0
        }
    };

    for k in 0..limit {
        let slot_va = tbl + (k as u64) * (entry_size as u64);
        let offset_val: i64 = match entry_size {
            1 => {
                let Some(val) = data_idx.read_u8_at(slot_va) else {
                    break;
                };
                val as i64 // unsigned byte offset
            }
            2 => {
                let Some(val) = data_idx.read_u16_at(slot_va) else {
                    break;
                };
                // Sign-extend if the ADD uses SXTH (option=5),
                // otherwise unsigned.  For simplicity, treat as signed
                // i16 → i64 (SXTH is the common case for halfword tables,
                // and unsigned values < 0x8000 are unaffected).
                (val as i16) as i64
            }
            _ => break,
        };

        let shifted = offset_val << add_shift;
        let target = Va::new((tbase as i64 + shifted) as u64);
        if !seg_idx.is_exec(target) {
            break;
        }
        xrefs.push(Xref {
            from: br_va,
            to: target,
            kind: XrefKind::Jump,
            confidence: Confidence::LocalProp,
        });
    }
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
            if idx.contains(Va::new(target)) && idx.is_exec(Va::new(target)) {
                Some(Xref {
                    from: Va::new(va),
                    to: Va::new(target),
                    kind: XrefKind::Call,
                    confidence: Confidence::LinearImmediate,
                })
            } else {
                None
            }
        }
        Arm64Insn::B(_) => {
            let target = insn.imm26_target(va);
            if idx.contains(Va::new(target)) {
                Some(Xref {
                    from: Va::new(va),
                    to: Va::new(target),
                    kind: XrefKind::Jump,
                    confidence: Confidence::LinearImmediate,
                })
            } else {
                None
            }
        }
        Arm64Insn::BCond(_) => {
            let target = insn.imm19_target(va);
            if idx.contains(Va::new(target)) {
                Some(Xref {
                    from: Va::new(va),
                    to: Va::new(target),
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
            if idx.contains(Va::new(target)) {
                Some(Xref {
                    from: Va::new(va),
                    to: Va::new(target),
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
            if idx.contains(Va::new(target)) {
                Some(Xref {
                    from: Va::new(va),
                    to: Va::new(target),
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
            if idx.contains(Va::new(target)) {
                Some(Xref {
                    from: Va::new(va),
                    to: Va::new(target),
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
            va: Va::new(base_va),
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
        let xrefs = scan_linear(&region, &idx);

        assert_eq!(xrefs.len(), 1);
        assert_eq!(xrefs[0].from, Va::new(0x1000));
        assert_eq!(xrefs[0].to, Va::new(0x1010));
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
        let xrefs = scan_linear(&region_for(&code_seg), &idx);
        assert_eq!(xrefs.len(), 1);
        assert_eq!(xrefs[0].from, Va::new(0x1008));
        assert_eq!(xrefs[0].to, Va::new(0x1010));
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
        let xrefs = scan_linear(&region_for(&seg), &idx);
        // CBZ at 0x1008 → target 0x1004
        let cbz_xref = xrefs.iter().find(|x| x.from == Va::new(0x1008)).unwrap();
        assert_eq!(cbz_xref.to, Va::new(0x1004));
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
        assert_eq!(pair.from, Va::new(0x1000)); // ADRP va (IDA records at ADRP, not ADD)
        assert_eq!(pair.to, Va::new(0x2100)); // 0x2000 + 0x100
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
            va: Va::new(0x2000),
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
        assert_eq!(dr.from, Va::new(0x1004));
        assert_eq!(dr.to, Va::new(0x2008));

        // Must also emit data_ptr at ADRP VA (0x1000) → 0x2008
        let dp = xrefs
            .iter()
            .find(|x| x.kind == XrefKind::DataPointer && x.from == Va::new(0x1000))
            .expect("ADRP+LDR must emit data_ptr at ADRP VA");
        assert_eq!(dp.to, Va::new(0x2008));
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
        let xrefs = scan_linear(&region_for(&code_seg), &idx);
        assert!(
            xrefs.is_empty(),
            "xref to unmapped target should be suppressed"
        );
    }
}
