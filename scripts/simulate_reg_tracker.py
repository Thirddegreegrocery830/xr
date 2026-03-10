#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.10"
# dependencies = ["capstone"]
# ///
"""
Simulate a simple register value tracker for ARM64 data_write.

Track: when we see ADRP Xn, #page -> reg_vals[n] = page
       when we see ADD  Xn, Xm, #off -> if m in reg_vals: reg_vals[n] = reg_vals[m] + off
       when we see MOV  Xn, Xm -> if m in reg_vals: reg_vals[n] = reg_vals[m]
       when we see any other write to Xn -> del reg_vals[n]
       when we see STR/STRB/etc [Xn, #off] -> if n in reg_vals: emit xref at reg_vals[n]+off

This simulates what xr could do with a forward pass instead of a backward ADRP scan.
We count how many GT data_write xrefs would be hit correctly vs FP/FN.
"""
import json
from dataclasses import dataclass

import capstone


BINARY = 'testcases/curl-aarch64'
GROUND_TRUTH = 'testcases/curl-aarch64.xrefs.json'


@dataclass
class Xref:
    src: int
    dst: int
    kind: str


def load_ground_truth(path: str) -> list[Xref]:
    with open(path) as f:
        data = json.load(f)
    return [Xref(src=e['from'], dst=e['to'], kind=e['kind']) for e in data]


def load_binary(path: str) -> bytes:
    with open(path, 'rb') as f:
        return f.read()


def parse_elf_segments(binary: bytes) -> list[tuple[int, int, int, bool]]:
    """Returns list of (vaddr, filesz, fileoff, executable) for PT_LOAD segments."""
    e_phoff = int.from_bytes(binary[0x20:0x28], 'little')
    e_phentsize = int.from_bytes(binary[0x36:0x38], 'little')
    e_phnum = int.from_bytes(binary[0x38:0x3a], 'little')
    segs = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type = int.from_bytes(binary[off:off+4], 'little')
        if p_type != 1:
            continue
        p_offset = int.from_bytes(binary[off+8:off+16], 'little')
        p_vaddr = int.from_bytes(binary[off+16:off+24], 'little')
        p_filesz = int.from_bytes(binary[off+32:off+40], 'little')
        p_flags = int.from_bytes(binary[off+4:off+8], 'little')
        exec_flag = bool(p_flags & 1)
        segs.append((p_vaddr, p_filesz, p_offset, exec_flag))
    return segs


def va_to_bytes(binary: bytes, segs: list, va: int, length: int) -> bytes | None:
    for (vaddr, filesz, fileoff, _) in segs:
        if vaddr <= va < vaddr + filesz:
            off = fileoff + (va - vaddr)
            end = off + length
            if end <= len(binary):
                return binary[off:end]
    return None


STORE_MNEMS = {'str', 'strb', 'strh', 'stur', 'sturb', 'sturh', 'stlr', 'stlxr', 'stxr', 'stp'}


def reg_idx(reg_name: str) -> int | None:
    """Convert 'x0'..'x30', 'xzr' to integer index 0..31."""
    r = reg_name.lower()
    if r == 'xzr' or r == 'wzr':
        return 31  # zero register, never tracked
    if r.startswith('x') or r.startswith('w'):
        try:
            n = int(r[1:])
            if 0 <= n <= 30:
                return n
        except ValueError:
            pass
    if r == 'sp':
        return 31  # don't track sp
    return None


def dest_reg_of(insn: capstone.CsInsn) -> int | None:
    """Return the destination register index for instructions that write a register."""
    mnem = insn.mnemonic.lower()
    op_str = insn.op_str

    # Instructions that write to first operand register
    writers = {
        'adrp', 'adr', 'add', 'sub', 'orr', 'and', 'eor', 'mov', 'movz', 'movk',
        'movn', 'ldr', 'ldrb', 'ldrh', 'ldrsw', 'ldrsh', 'ldrsb', 'ldur',
        'ldp',  # ldp writes first two registers
        'csel', 'csinc', 'csinv', 'csneg',
        'madd', 'msub', 'mul', 'udiv', 'sdiv',
        'lsl', 'lsr', 'asr', 'ror',
        'ubfx', 'sbfx', 'ubfiz', 'bfi', 'bfxil',
        'extr', 'umulh', 'smulh',
        'neg', 'negs', 'ngc', 'ngcs', 'mvn',
        'sxtw', 'sxth', 'sxtb', 'uxtw', 'uxth', 'uxtb',
        'rbit', 'rev', 'rev16', 'rev32', 'clz', 'cls',
        'bl', 'blr',  # writes x30 (lr), but we don't care
    }

    if mnem not in writers:
        return None

    # Extract first operand as register
    first_op = op_str.split(',')[0].strip()
    return reg_idx(first_op)


def simulate_reg_tracker(binary: bytes, segs: list, md: capstone.Cs) -> set[tuple[int, int]]:
    """
    Do a linear pass over all executable segments, tracking register values.
    Return set of (src_va, dst_va) data_write xrefs emitted.
    We use skipdata mode to handle non-decodable bytes (ELF header, data in text, etc.).
    """
    emitted: set[tuple[int, int]] = set()

    # Enable skipdata so capstone skips 4-byte chunks it can't decode
    md.skipdata = True

    for (vaddr, filesz, fileoff, is_exec) in segs:
        if not is_exec:
            continue

        seg_bytes = binary[fileoff: fileoff + filesz]
        reg_vals: dict[int, int] = {}  # reg_idx -> page_value

        for insn in md.disasm(seg_bytes, vaddr):
            mnem = insn.mnemonic.lower()
            op_str = insn.op_str
            parts = [p.strip() for p in op_str.split(',')]

            # ADRP: set register to page
            if mnem == 'adrp':
                dst = reg_idx(parts[0]) if parts else None
                if dst is not None and len(parts) >= 2:
                    imm_str = parts[1].lstrip('#')
                    try:
                        reg_vals[dst] = int(imm_str, 0)
                    except ValueError:
                        reg_vals.pop(dst, None)
                continue

            # ADD Xd, Xn, #imm  (ADRP+ADD pattern propagation)
            if mnem == 'add' and len(parts) >= 3:
                dst = reg_idx(parts[0])
                src = reg_idx(parts[1])
                imm_str = parts[2].lstrip('#')
                if dst is not None and src is not None and src in reg_vals:
                    try:
                        reg_vals[dst] = reg_vals[src] + int(imm_str, 0)
                    except ValueError:
                        reg_vals.pop(dst, None)
                elif dst is not None:
                    reg_vals.pop(dst, None)
                continue

            # MOV Xd, Xn (register copy)
            if mnem in ('mov', 'orr') and len(parts) >= 2:
                dst = reg_idx(parts[0])
                src_r = reg_idx(parts[-1])  # last operand
                if dst is not None:
                    if src_r is not None and src_r in reg_vals and mnem == 'mov':
                        reg_vals[dst] = reg_vals[src_r]
                    else:
                        reg_vals.pop(dst, None)
                continue

            # Store instructions: emit xref if base reg is tracked
            if mnem in STORE_MNEMS:
                # Find memory operand [Xn, #off]
                bracket_start = op_str.find('[')
                bracket_end = op_str.find(']')
                if bracket_start != -1 and bracket_end != -1:
                    mem = op_str[bracket_start+1:bracket_end]
                    mem_parts = [p.strip() for p in mem.split(',')]
                    base = reg_idx(mem_parts[0]) if mem_parts else None
                    offset = 0
                    if len(mem_parts) > 1:
                        off_str = mem_parts[1].lstrip('#')
                        try:
                            offset = int(off_str, 0)
                        except ValueError:
                            offset = 0
                    if base is not None and base in reg_vals:
                        target = reg_vals[base] + offset
                        if target != 0:
                            emitted.add((insn.address, target))
                            # STP emits TWO xrefs (second operand is at +8)
                            if mnem == 'stp' and len(mem_parts) == 1:
                                emitted.add((insn.address, target + 8))
                            elif mnem == 'stp' and len(mem_parts) > 1:
                                # already offset for first; second goes to offset+ptr_size
                                reg_size = 8  # assume 64-bit
                                emitted.add((insn.address, target + reg_size))
                continue

            # All other instructions that write to a register: invalidate
            dst = dest_reg_of(insn)
            if dst is not None:
                reg_vals.pop(dst, None)

    return emitted


def main() -> None:
    print('Loading ground truth...')
    gt_xrefs = load_ground_truth(GROUND_TRUTH)
    dw_gt: set[tuple[int, int]] = {(x.src, x.dst) for x in gt_xrefs if x.kind == 'data_write'}
    print(f'GT data_write: {len(dw_gt)}')

    binary = load_binary(BINARY)
    segs = parse_elf_segments(binary)
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)

    print('Running register tracker simulation...')
    emitted = simulate_reg_tracker(binary, segs, md)
    print(f'Emitted: {len(emitted)} data_write xrefs')

    tp = emitted & dw_gt
    fp = emitted - dw_gt
    fn = dw_gt - emitted

    prec = len(tp) / len(emitted) if emitted else 0
    rec = len(tp) / len(dw_gt) if dw_gt else 0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0

    print(f'\nTP={len(tp)}  FP={len(fp)}  FN={len(fn)}')
    print(f'Precision={prec:.3f}  Recall={rec:.3f}  F1={f1:.3f}')
    print(f'\n(Current xr: TP=222 FP=16 FN=360 Prec=0.933 Rec=0.381 F1=0.541)')

    if fp:
        fp_sample = list(fp)[:5]
        print(f'\nFP sample:')
        for src, dst in fp_sample:
            print(f'  0x{src:x} -> 0x{dst:x}')


if __name__ == '__main__':
    main()
