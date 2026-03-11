//! x86-64 xref extraction — two depth levels.
//!
//! Depth 1 (linear immediate): decode each instruction, emit xrefs for
//! direct CALL/JMP/Jcc with immediate targets, and RIP-relative LEA/MOV/etc.
//! RIP-relative is x86-64's equivalent of ARM64's ADRP — almost all data
//! references use `[rip + disp32]` and are resolved directly during decode
//! since we know the instruction address.
//!
//! Depth 2 (local prop): track register assignments with simple constant
//! values and resolve indirect CALL/JMP where the target is a known constant.
//! This catches `mov rax, imm64; call rax` patterns.

use super::{ScanRegion, SegmentDataIndex, SegmentIndex, XrefSet};
use crate::va::Va;
use crate::xref::{Confidence, Xref, XrefKind};
use iced_x86::{
    Code, Decoder, DecoderOptions, FlowControl, Instruction, InstructionInfoFactory, OpAccess,
    OpKind, Register,
};
use std::collections::HashMap;

/// Returns true if the memory operand at `op_idx` in `insn` is written to (not just read).
/// Uses InstructionInfoFactory for accurate semantics (handles CMP, TEST, ADD [mem], etc.).
#[inline]
fn mem_op_is_write(
    insn: &Instruction,
    op_idx: u32,
    info_factory: &mut InstructionInfoFactory,
) -> bool {
    let info = info_factory.info(insn);
    let access = info.op_access(op_idx);
    matches!(
        access,
        OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite
    )
}

/// Depth 1: linear decode, immediate + RIP-relative targets.
/// Depth 1: linear disassembly. Delegates to `scan_with_prop` — the register
/// propagation adds negligible cost and the extra resolved xrefs are harmless
/// (they're correct, just not required at depth 1).
pub(crate) fn scan_linear(
    region: &ScanRegion,
    idx: &SegmentIndex,
    _data_idx: &SegmentDataIndex,
    got_map: &HashMap<Va, Va>,
) -> XrefSet {
    scan_with_prop(region, idx, _data_idx, got_map)
}

/// Depth 2: linear disassembly + simple register constant propagation.
/// Catches `mov rax, imm64 / call rax` and similar patterns.
pub(crate) fn scan_with_prop(
    region: &ScanRegion,
    idx: &SegmentIndex,
    _data_idx: &SegmentDataIndex,
    got_map: &HashMap<Va, Va>,
) -> XrefSet {
    let mut xrefs = Vec::new();
    let data = region.data;
    let base = region.base_va.raw();

    let region_is_exec = idx.is_exec(region.base_va);

    // Track known constant values per register (GPRs 0..16 for RAX..R15)
    let mut reg_vals: [Option<u64>; 16] = [None; 16];

    let mut decoder = Decoder::with_ip(64, data, base, DecoderOptions::NONE);
    let mut insn = Instruction::default();
    let mut info_factory = InstructionInfoFactory::new();

    while decoder.can_decode() {
        decoder.decode_out(&mut insn);
        if insn.is_invalid() {
            continue;
        }

        let va = insn.ip();

        // Depth-1 branch/call xrefs — only from executable regions.
        if region_is_exec {
            emit_direct_branches(&insn, va, idx, got_map, &mut xrefs);
        }

        emit_rip_relative(&insn, va, idx, &mut info_factory, &mut xrefs);

        // Indirect call/jmp via register — try to resolve from prop state
        match insn.code() {
            Code::Call_rm64 | Code::Jmp_rm64 => {
                if insn.op0_kind() == OpKind::Register {
                    let reg = insn.op0_register();
                    if let Some(ri) = gpr_index(reg) {
                        if let Some(known) = reg_vals[ri] {
                            if idx.contains(Va(known)) {
                                let kind = if insn.code() == Code::Call_rm64 {
                                    XrefKind::Call
                                } else {
                                    XrefKind::Jump
                                };
                                xrefs.push(Xref {
                                    from: Va(va),
                                    to: Va(known),
                                    kind,
                                    confidence: Confidence::LocalProp,
                                });
                            }
                        }
                    }
                }
            }
            _ => {}
        }

        // Immediate-as-pointer (same criteria as in scan_linear_with_index).
        if region_is_exec {
            if let Some(imm) = imm_as_address(&insn) {
                if idx.contains(Va(imm)) {
                    xrefs.push(Xref {
                        from: Va(va),
                        to: Va(imm),
                        kind: XrefKind::DataPointer,
                        confidence: Confidence::LinearImmediate,
                    });
                }
            }
        }

        // Update propagation state
        update_prop_state(&insn, &mut reg_vals);
    }

    xrefs
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Emit xrefs for all direct branch/call instructions and GOT-indirect calls.
///
/// This is the single source-of-truth for branch emission, shared by
/// `scan_linear_with_index` and `scan_with_prop`.  Both depth levels apply
/// identical branch-detection logic; the only difference between them is that
/// `scan_with_prop` additionally tracks register constants and resolves
/// indirect `CALL reg` / `JMP reg` targets.
///
/// Handles:
///   CALL rel32           → `Call`  (FlowControl::Call)
///   JMP rel32            → `Jump`  (FlowControl::UnconditionalBranch)
///   Jcc rel32/rel8       → `CondJump` (FlowControl::ConditionalBranch)
///   XBEGIN rel32         → `CondJump` (FlowControl::XbeginXabortXend)
///   CALL [RIP+disp32] }  → resolved via got_map → `Call`/`Jump` to extern VA
///   JMP  [RIP+disp32] }  (FlowControl::IndirectCall / IndirectBranch, FF 15 / FF 25)
#[inline]
fn emit_direct_branches(
    insn: &Instruction,
    va: u64,
    idx: &SegmentIndex,
    got_map: &HashMap<Va, Va>,
    xrefs: &mut Vec<Xref>,
) {
    match insn.flow_control() {
        iced_x86::FlowControl::Call
        | iced_x86::FlowControl::UnconditionalBranch
        | iced_x86::FlowControl::ConditionalBranch
        // XBEGIN encodes a NearBranch relative offset (the TSX abort handler)
        // but has FlowControl::XbeginXabortXend. Treat it as a conditional
        // jump — execution either enters the transaction or jumps to the handler.
        | iced_x86::FlowControl::XbeginXabortXend => {
            if let Some(target) = direct_target(insn) {
                if idx.contains(Va(target)) {
                    let kind = match insn.flow_control() {
                        iced_x86::FlowControl::Call => XrefKind::Call,
                        iced_x86::FlowControl::UnconditionalBranch => XrefKind::Jump,
                        iced_x86::FlowControl::ConditionalBranch
                        | iced_x86::FlowControl::XbeginXabortXend => XrefKind::CondJump,
                        // All cases are listed in the outer match arm — unreachable.
                        other => unreachable!(
                            "direct_target returned Some for non-branch flow {:?}",
                            other
                        ),
                    };
                    xrefs.push(Xref {
                        from: Va(va),
                        to: Va(target),
                        kind,
                        confidence: Confidence::LinearImmediate,
                    });
                }
            }
        }
        // Indirect call/jump through GOT (FF 15 / FF 25): resolve via got_map.
        // If the memory operand is [RIP+disp32] and the GOT slot is in got_map,
        // emit a Call or Jump xref to the extern VA.
        FlowControl::IndirectCall | FlowControl::IndirectBranch => {
            emit_got_indirect(insn, va, got_map, xrefs);
        }
        _ => {}
    }
}

/// Emit a Call or Jump xref for an indirect `CALL [RIP+disp32]` / `JMP [RIP+disp32]`
/// instruction (FF 15 / FF 25) when the resolved GOT slot is in `got_map`.
///
/// IDA records these as xrefs to the synthetic extern VA assigned to the imported
/// symbol.  We replicate this by looking up the GOT slot VA in `got_map` and
/// emitting a `LinearImmediate` xref with the extern VA as the target.
#[inline]
fn emit_got_indirect(
    insn: &Instruction,
    va: u64,
    got_map: &HashMap<Va, Va>,
    xrefs: &mut Vec<Xref>,
) {
    // Only applies when the single memory operand uses RIP-relative addressing.
    if insn.op_count() == 1
        && insn.op0_kind() == OpKind::Memory
        && insn.memory_base() == Register::RIP
    {
        let got_slot_va = Va(insn.memory_displacement64());
        if let Some(&extern_va) = got_map.get(&got_slot_va) {
            let kind = if insn.flow_control() == FlowControl::IndirectCall {
                XrefKind::Call
            } else {
                XrefKind::Jump
            };
            xrefs.push(Xref {
                from: Va(va),
                to: extern_va,
                kind,
                confidence: Confidence::LinearImmediate,
            });
        }
    }
}

/// Emit a RIP-relative data xref if the instruction has a `[RIP + disp32]` operand.
///
/// IDA distinguishes:
///   LEA r64, [rip+disp]  →  data_ptr   (takes the address; dr_O)
///   MOV reg, [rip+disp]  →  data_read  (loads from address; dr_R)
///   MOV [rip+disp], reg  →  data_write (stores to address; dr_W)
///   CMP/TEST [rip+disp]  →  data_read
///
/// Non-LEA instructions pointing into an executable segment are suppressed
/// (IDA does not record these).
///
/// This is the single source-of-truth for RIP-relative xref emission,
/// shared by `scan_linear_with_index` and `scan_with_prop`.
#[inline]
fn emit_rip_relative(
    insn: &Instruction,
    va: u64,
    idx: &SegmentIndex,
    info_factory: &mut InstructionInfoFactory,
    xrefs: &mut Vec<Xref>,
) {
    for op_idx in 0..insn.op_count() {
        if insn.op_kind(op_idx) == OpKind::Memory && insn.memory_base() == Register::RIP {
            let target = insn.memory_displacement64();
            if idx.contains(Va(target)) {
                let target_is_exec = idx.is_exec(Va(target));
                let is_lea = matches!(
                    insn.code(),
                    Code::Lea_r16_m | Code::Lea_r32_m | Code::Lea_r64_m
                );
                let is_write = !is_lea && mem_op_is_write(insn, op_idx, info_factory);
                let kind = if is_lea {
                    XrefKind::DataPointer
                } else if is_write {
                    XrefKind::DataWrite
                } else {
                    XrefKind::DataRead
                };
                // For non-LEA: suppress if target is exec (IDA doesn't record these)
                if is_lea || !target_is_exec {
                    xrefs.push(Xref {
                        from: Va(va),
                        to: Va(target),
                        kind,
                        confidence: Confidence::LinearImmediate,
                    });
                }
            }
            break; // at most one memory operand per instruction
        }
    }
}

/// Extract a 32-bit immediate operand as a potential address value, for
/// instruction types that IDA records as data_ptr when the immediate
/// resolves to a mapped address.
///
/// IDA records data_ptr for:
///   MOV r64, imm64 / MOV r/m64, imm32 / MOV r32, imm32
///   CMP r/m64, imm32 / CMP rAX, imm32  (0x81 /7 / 0x3d)
///   SUB r/m64, imm32 / SUB rAX, imm32  (0x81 /5 / 0x2d)
///
/// IDA does NOT record data_ptr for AND, OR, XOR, TEST, PUSH, ADD with imm32
/// (treated as bitmask/constant values, not address pointers).
///
/// Returns the address value if this instruction qualifies, None otherwise.
#[inline]
fn imm_as_address(insn: &Instruction) -> Option<u64> {
    match insn.code() {
        // MOV reg, imm64 — direct 64-bit pointer
        Code::Mov_r64_imm64 => {
            let v = insn.immediate64();
            if v > 0 {
                Some(v)
            } else {
                None
            }
        }
        // MOV r/m64, imm32 or MOV r32, imm32 — zero/sign-extended 32-bit address
        Code::Mov_rm64_imm32 | Code::Mov_r32_imm32 => {
            let v = insn.immediate32to64() as u64;
            if v > 0 && v < 0x1_0000_0000 {
                Some(v)
            } else {
                None
            }
        }
        // CMP r/m64, imm32  (0x81 /7 with REX.W)
        Code::Cmp_rm64_imm32 | Code::Cmp_rm64_imm8 => {
            let v = insn.immediate32to64() as u64;
            if v > 0 && v < 0x1_0000_0000 {
                Some(v)
            } else {
                None
            }
        }
        // CMP rAX, imm32  (0x3d with REX.W → Cmp_RAX_imm32)
        Code::Cmp_RAX_imm32 | Code::Cmp_EAX_imm32 => {
            let v = insn.immediate32to64() as u64;
            if v > 0 && v < 0x1_0000_0000 {
                Some(v)
            } else {
                None
            }
        }
        // SUB r/m64, imm32  (0x81 /5 with REX.W)
        Code::Sub_rm64_imm32 | Code::Sub_rm64_imm8 => {
            let v = insn.immediate32to64() as u64;
            if v > 0 && v < 0x1_0000_0000 {
                Some(v)
            } else {
                None
            }
        }
        // SUB rAX, imm32  (0x2d with REX.W)
        Code::Sub_RAX_imm32 | Code::Sub_EAX_imm32 => {
            let v = insn.immediate32to64() as u64;
            if v > 0 && v < 0x1_0000_0000 {
                Some(v)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Extract the direct branch/call target if the instruction has one.
fn direct_target(insn: &Instruction) -> Option<u64> {
    // iced-x86 provides NearBranch64 for direct calls/jumps
    match insn.op0_kind() {
        OpKind::NearBranch16 => Some(insn.near_branch16() as u64),
        OpKind::NearBranch32 => Some(insn.near_branch32() as u64),
        OpKind::NearBranch64 => Some(insn.near_branch64()),
        OpKind::FarBranch16 | OpKind::FarBranch32 => None, // segment-based, skip
        _ => None,
    }
}

/// Update register propagation state for MOV reg, imm64 and similar.
fn update_prop_state(insn: &Instruction, vals: &mut [Option<u64>; 16]) {
    // We only track: MOV r64, imm64
    // Everything else that writes to a register invalidates it.
    let op_count = insn.op_count();
    if op_count == 0 {
        return;
    }

    // Destination is op 0 for most x86-64 instructions
    if insn.op0_kind() != OpKind::Register {
        return;
    }
    let dst = insn.op0_register();
    let Some(dst_idx) = gpr_index(dst) else {
        return;
    };

    // MOV rN, imm — set the value
    match insn.code() {
        Code::Mov_r64_imm64 => {
            vals[dst_idx] = Some(insn.immediate64());
        }
        Code::Mov_rm64_imm32 => {
            vals[dst_idx] = Some(insn.immediate32to64() as u64);
        }
        Code::Mov_r32_imm32 => {
            // mov r32, imm32 zero-extends to 64 bits on x86-64
            vals[dst_idx] = Some(insn.immediate32() as u64);
        }
        Code::Mov_r16_imm16 => {
            vals[dst_idx] = Some(insn.immediate16() as u64);
        }
        // LEA r64, [rip+disp] — we know the value since RIP-relative is resolved
        Code::Lea_r64_m => {
            if insn.memory_base() == Register::RIP {
                vals[dst_idx] = Some(insn.memory_displacement64());
            } else {
                vals[dst_idx] = None;
            }
        }
        // Any other write — invalidate
        _ => {
            vals[dst_idx] = None;
        }
    }
}

/// Map a GPR (in any width) to an index 0..15.
/// Returns None for non-GPR registers (XMM, segment, etc.).
fn gpr_index(reg: Register) -> Option<usize> {
    match reg {
        Register::RAX | Register::EAX | Register::AX | Register::AL | Register::AH => Some(0),
        Register::RCX | Register::ECX | Register::CX | Register::CL | Register::CH => Some(1),
        Register::RDX | Register::EDX | Register::DX | Register::DL | Register::DH => Some(2),
        Register::RBX | Register::EBX | Register::BX | Register::BL | Register::BH => Some(3),
        Register::RSP | Register::ESP | Register::SP | Register::SPL => Some(4),
        Register::RBP | Register::EBP | Register::BP | Register::BPL => Some(5),
        Register::RSI | Register::ESI | Register::SI | Register::SIL => Some(6),
        Register::RDI | Register::EDI | Register::DI | Register::DIL => Some(7),
        Register::R8 | Register::R8D | Register::R8W | Register::R8L => Some(8),
        Register::R9 | Register::R9D | Register::R9W | Register::R9L => Some(9),
        Register::R10 | Register::R10D | Register::R10W | Register::R10L => Some(10),
        Register::R11 | Register::R11D | Register::R11W | Register::R11L => Some(11),
        Register::R12 | Register::R12D | Register::R12W | Register::R12L => Some(12),
        Register::R13 | Register::R13D | Register::R13W | Register::R13L => Some(13),
        Register::R14 | Register::R14D | Register::R14W | Register::R14L => Some(14),
        Register::R15 | Register::R15D | Register::R15W | Register::R15L => Some(15),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::{ScanRegion, SegmentDataIndex};
    use crate::loader::{DecodeMode, Segment};
    use crate::xref::{Confidence, XrefKind};
    use std::collections::HashMap;

    fn fake_seg(va: u64, data: &'static [u8]) -> Segment {
        Segment {
            va: Va(va),
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

    // ── CALL rel32 ────────────────────────────────────────────────────────────

    /// E8 fb0f0000 = CALL 0x2000 from 0x1000 (next_ip=0x1005, rel=0xffb)
    #[test]
    fn test_call_rel32() {
        static CODE: [u8; 5] = [0xe8, 0xfb, 0x0f, 0x00, 0x00];
        static TARGET: [u8; 4] = [0x00; 4];
        let code = fake_seg(0x1000, &CODE);
        let tgt = fake_seg(0x2000, &TARGET);
        let segs = vec![fake_seg(0x1000, &CODE), tgt];

        let idx = SegmentIndex::build(&segs);
        let didx = SegmentDataIndex::build(&segs);
        let xrefs = scan_linear(&region_for(&code), &idx, &didx, &HashMap::new());
        assert_eq!(xrefs.len(), 1);
        assert_eq!(xrefs[0].from, Va(0x1000));
        assert_eq!(xrefs[0].to, Va(0x2000));
        assert_eq!(xrefs[0].kind, XrefKind::Call);
        assert_eq!(xrefs[0].confidence, Confidence::LinearImmediate);
    }

    // ── JMP rel32 ─────────────────────────────────────────────────────────────

    /// E9 f60f0000 = JMP 0x2000 from 0x1005 (next_ip=0x100a, rel=0xff6)
    #[test]
    fn test_jmp_rel32() {
        static CODE: [u8; 10] = [
            0x90, 0x90, 0x90, 0x90, 0x90, // 5 NOPs at 0x1000..0x1005
            0xe9, 0xf6, 0x0f, 0x00, 0x00, // JMP 0x2000 at 0x1005
        ];
        static TARGET: [u8; 4] = [0x00; 4];
        let code = fake_seg(0x1000, &CODE);
        let tgt = fake_seg(0x2000, &TARGET);
        let segs = vec![fake_seg(0x1000, &CODE), tgt];

        let idx = SegmentIndex::build(&segs);
        let didx = SegmentDataIndex::build(&segs);
        let xrefs = scan_linear(&region_for(&code), &idx, &didx, &HashMap::new());
        let jmp = xrefs.iter().find(|x| x.kind == XrefKind::Jump).unwrap();
        assert_eq!(jmp.from, Va(0x1005));
        assert_eq!(jmp.to, Va(0x2000));
    }

    // ── JE rel32 (conditional) ────────────────────────────────────────────────

    /// 0F84 f00f0000 = JE 0x2000 from 0x100a (next_ip=0x1010)
    #[test]
    fn test_je_cond_jump() {
        static CODE: [u8; 16] = [
            0x90, 0x90, 0x90, 0x90, 0x90, // 5 NOPs 0x1000..0x1005
            0x90, 0x90, 0x90, 0x90, 0x90, // 5 NOPs 0x1005..0x100a
            0x0f, 0x84, 0xf0, 0x0f, 0x00, 0x00, // JE 0x2000 at 0x100a
        ];
        static TARGET: [u8; 4] = [0x00; 4];
        let code = fake_seg(0x1000, &CODE);
        let tgt = fake_seg(0x2000, &TARGET);
        let segs = vec![fake_seg(0x1000, &CODE), tgt];

        let idx = SegmentIndex::build(&segs);
        let didx = SegmentDataIndex::build(&segs);
        let xrefs = scan_linear(&region_for(&code), &idx, &didx, &HashMap::new());
        let je = xrefs.iter().find(|x| x.kind == XrefKind::CondJump).unwrap();
        assert_eq!(je.from, Va(0x100a));
        assert_eq!(je.to, Va(0x2000));
    }

    // ── LEA rax, [rip + disp32] ───────────────────────────────────────────────

    /// 48 8D 05 f91f0000 = LEA rax, [rip+0x1ff9] from 0x1000 → 0x3000
    /// (next_ip = 0x1007, disp = 0x3000 - 0x1007 = 0x1ff9)
    #[test]
    fn test_lea_rip_relative() {
        static CODE: [u8; 7] = [0x48, 0x8d, 0x05, 0xf9, 0x1f, 0x00, 0x00];
        static TARGET: [u8; 8] = [0x00; 8];
        let code = fake_seg(0x1000, &CODE);
        let tgt = fake_seg(0x3000, &TARGET);
        let segs = vec![fake_seg(0x1000, &CODE), tgt];

        let idx = SegmentIndex::build(&segs);
        let didx = SegmentDataIndex::build(&segs);
        let xrefs = scan_linear(&region_for(&code), &idx, &didx, &HashMap::new());
        // LEA = takes address → DataPointer (IDA dr_O), not DataRead
        let lea = xrefs
            .iter()
            .find(|x| x.kind == XrefKind::DataPointer)
            .unwrap();
        assert_eq!(lea.from, Va(0x1000));
        assert_eq!(lea.to, Va(0x3000));
        assert_eq!(lea.confidence, Confidence::LinearImmediate);
    }

    // ── MOV rax, imm64 / CALL rax → LocalProp ─────────────────────────────────

    /// 48 B8 <imm64> = MOV rax, 0x4000  (10 bytes at 0x1000)
    /// FF D0         = CALL rax          (2 bytes at 0x100a)
    #[test]
    fn test_mov_call_reg_prop() {
        static CODE: [u8; 12] = [
            0x48, 0xb8, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // MOV rax, 0x4000
            0xff, 0xd0, // CALL rax
        ];
        static TARGET: [u8; 4] = [0x00; 4];
        let code = fake_seg(0x1000, &CODE);
        let tgt = fake_seg(0x4000, &TARGET);
        let segs = vec![fake_seg(0x1000, &CODE), tgt];

        let idx = SegmentIndex::build(&segs);
        let didx = SegmentDataIndex::build(&segs);
        let xrefs = scan_with_prop(&region_for(&code), &idx, &didx, &HashMap::new());
        let prop = xrefs
            .iter()
            .find(|x| x.confidence == Confidence::LocalProp)
            .expect("expected a LocalProp xref");
        assert_eq!(prop.from, Va(0x100a));
        assert_eq!(prop.to, Va(0x4000));
        assert_eq!(prop.kind, XrefKind::Call);
    }

    // ── Target out of range → filtered ────────────────────────────────────────

    #[test]
    fn test_call_out_of_range_filtered() {
        static CODE: [u8; 5] = [0xe8, 0xfb, 0x0f, 0x00, 0x00]; // CALL 0x2000
                                                               // No segment at 0x2000
        let code = fake_seg(0x1000, &CODE);
        let segs = vec![fake_seg(0x1000, &CODE)];
        let idx = SegmentIndex::build(&segs);
        let didx = SegmentDataIndex::build(&segs);
        let xrefs = scan_linear(&region_for(&code), &idx, &didx, &HashMap::new());
        assert!(xrefs.is_empty());
    }
}
