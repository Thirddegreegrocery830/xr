#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.10"
# dependencies = ["capstone"]
# ///
"""
Detailed analysis of ARM64 data_write FNs vs TPs.

We need to know WHICH of the 582 GT data_write xrefs xr currently catches
(TP=222) and which it misses (FN=360).

xr catches data_write when it sees STR/STRB/STRH/STUR + ADRP pair where
the ADRP is within the previous 4 instructions and the combined immediate
gives the target address.

Strategy: replicate xr's ADRP-pair logic in Python and classify each
GT xref as TP (xr would emit it) or FN (xr misses it), then report
instruction breakdowns for FNs specifically.
"""
import json
from collections import Counter
from dataclasses import dataclass

import capstone


BINARY = 'testcases/curl-aarch64'
GROUND_TRUTH = 'testcases/curl-aarch64.xrefs.json'

# How many instructions back to look for ADRP partner
ADRP_WINDOW = 4


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


def va_to_file_offset(binary: bytes, va: int) -> int | None:
    """Convert VA to file offset via ELF PT_LOAD segments."""
    e_phoff = int.from_bytes(binary[0x20:0x28], 'little')
    e_phentsize = int.from_bytes(binary[0x36:0x38], 'little')
    e_phnum = int.from_bytes(binary[0x38:0x3a], 'little')

    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type = int.from_bytes(binary[off:off+4], 'little')
        if p_type != 1:
            continue
        p_offset = int.from_bytes(binary[off+8:off+16], 'little')
        p_vaddr = int.from_bytes(binary[off+16:off+24], 'little')
        p_filesz = int.from_bytes(binary[off+32:off+40], 'little')
        if p_vaddr <= va < p_vaddr + p_filesz:
            return p_offset + (va - p_vaddr)
    return None


STORE_MNEMS = {'str', 'strb', 'strh', 'stur', 'sturb', 'sturh', 'stlr', 'stlxr', 'stxr', 'stp'}


def adrp_imm(insn: capstone.CsInsn) -> int | None:
    """Extract ADRP page-aligned immediate if this is an ADRP instruction."""
    if insn.mnemonic.lower() != 'adrp':
        return None
    # op_str is like "x8, #0x741000"
    parts = insn.op_str.split(',')
    if len(parts) < 2:
        return None
    imm_str = parts[1].strip()
    if imm_str.startswith('#'):
        imm_str = imm_str[1:]
    try:
        return int(imm_str, 0)
    except ValueError:
        return None


def store_base_reg_and_offset(insn: capstone.CsInsn) -> tuple[str, int] | None:
    """
    For a store instruction, return (base_reg, offset) from the memory operand.
    e.g. "str w8, [x19, #0x10]" -> ("x19", 0x10)
         "str w8, [x19]"         -> ("x19", 0)
         "stp x0, x1, [x8, #8]" -> ("x8", 8)
    Returns None if we can't parse it.
    """
    op_str = insn.op_str
    # Find the memory operand [....]
    bracket_start = op_str.find('[')
    bracket_end = op_str.find(']')
    if bracket_start == -1 or bracket_end == -1:
        return None
    mem = op_str[bracket_start+1:bracket_end]
    parts = [p.strip() for p in mem.split(',')]
    base = parts[0]
    # Normalize: x8 -> x8, but w8 -> x8 doesn't apply here (base is always Xn)
    offset = 0
    if len(parts) > 1:
        off_str = parts[1]
        if off_str.startswith('#'):
            off_str = off_str[1:]
        try:
            offset = int(off_str, 0)
        except ValueError:
            offset = 0
    return (base, offset)


def simulate_xr_adrp_str(binary: bytes, src_va: int, md: capstone.Cs) -> int | None:
    """
    Simulate what xr does: look back up to ADRP_WINDOW instructions for
    an ADRP that sets the base register used by the store at src_va.
    Returns the computed target VA if found, None otherwise.
    """
    # Read enough bytes for ADRP_WINDOW+1 instructions before src + the src itself
    window_bytes = (ADRP_WINDOW + 1) * 4
    start_va = src_va - window_bytes
    file_off = va_to_file_offset(binary, start_va)
    if file_off is None:
        return None
    chunk = binary[file_off: file_off + window_bytes + 4]
    insns = list(md.disasm(chunk, start_va))

    # Find the store instruction at src_va
    src_idx = None
    for i, insn in enumerate(insns):
        if insn.address == src_va:
            src_idx = i
            break
    if src_idx is None:
        return None

    src_insn = insns[src_idx]
    if src_insn.mnemonic.lower() not in STORE_MNEMS:
        return None

    mem = store_base_reg_and_offset(src_insn)
    if mem is None:
        return None
    base_reg, offset = mem

    # Search backwards for ADRP setting base_reg
    for j in range(src_idx - 1, max(-1, src_idx - ADRP_WINDOW - 1), -1):
        if j < 0:
            break
        candidate = insns[j]
        imm = adrp_imm(candidate)
        if imm is None:
            continue
        # Check that ADRP destination register matches base_reg
        parts = candidate.op_str.split(',')
        if not parts:
            continue
        dest_reg = parts[0].strip()
        # Normalize: ADRP always uses 64-bit regs
        if dest_reg == base_reg:
            target = imm + offset
            return target

    return None


def main() -> None:
    print(f'Loading ground truth...')
    gt_xrefs = load_ground_truth(GROUND_TRUTH)
    dw_xrefs = [x for x in gt_xrefs if x.kind == 'data_write']
    print(f'Total GT data_write: {len(dw_xrefs)}')

    binary = load_binary(BINARY)
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = True

    # Build GT set as (src, dst) pairs for quick lookup
    gt_set = {(x.src, x.dst) for x in dw_xrefs}

    # For each GT data_write, simulate xr to classify as TP or FN
    tp_mnems: Counter[str] = Counter()
    fn_mnems: Counter[str] = Counter()
    fn_pair_mnems: Counter[str] = Counter()
    fn_examples: dict[str, list] = {}

    for xref in dw_xrefs:
        xr_target = simulate_xr_adrp_str(binary, xref.src, md)
        is_tp = xr_target is not None and xr_target == xref.dst

        # Disassemble the store instruction for classification
        file_off = va_to_file_offset(binary, xref.src)
        if file_off is None:
            continue
        chunk = binary[file_off: file_off + 4]
        insns = list(md.disasm(chunk, xref.src))
        mnem = insns[0].mnemonic.upper() if insns else '(unknown)'

        # Also get prev insn
        prev_off = va_to_file_offset(binary, xref.src - 4)
        prev_mnem = '(none)'
        if prev_off is not None:
            prev_chunk = binary[prev_off: prev_off + 4]
            prev_insns = list(md.disasm(prev_chunk, xref.src - 4))
            prev_mnem = prev_insns[0].mnemonic.upper() if prev_insns else '(none)'

        if is_tp:
            tp_mnems[mnem] += 1
        else:
            fn_mnems[mnem] += 1
            pair = f'{prev_mnem}+{mnem}'
            fn_pair_mnems[pair] += 1
            if mnem not in fn_examples:
                fn_examples[mnem] = []
            if len(fn_examples[mnem]) < 5:
                insn_str = f'{insns[0].mnemonic} {insns[0].op_str}' if insns else '?'
                fn_examples[mnem].append((xref.src, xref.dst, insn_str, prev_mnem, xr_target))

    total_tp = sum(tp_mnems.values())
    total_fn = sum(fn_mnems.values())
    print(f'\nSimulated TP={total_tp}  FN={total_fn}  (real benchmark: TP=222 FN=360)')

    print(f'\n=== TP instruction breakdown ===')
    for mnem, count in tp_mnems.most_common():
        print(f'  {mnem:20s}  {count}')

    print(f'\n=== FN instruction breakdown ===')
    for mnem, count in fn_mnems.most_common():
        pct = 100 * count / total_fn if total_fn else 0
        print(f'  {mnem:20s}  {count:4d}  ({pct:.1f}%)')

    print(f'\n=== FN top instruction pairs (prev+src) ===')
    for pair, count in fn_pair_mnems.most_common(20):
        pct = 100 * count / total_fn if total_fn else 0
        print(f'  {pair:40s}  {count:4d}  ({pct:.1f}%)')

    print(f'\n=== FN examples per mnemonic ===')
    for mnem, exs in sorted(fn_examples.items()):
        print(f'\n  --- {mnem} (FN) ---')
        for src, dst, insn_str, prev_mnem, xr_tgt in exs:
            print(f'    src=0x{src:x}  gt_dst=0x{dst:x}  xr_computed={hex(xr_tgt) if xr_tgt else None}')
            print(f'      prev: {prev_mnem}')
            print(f'      insn: {insn_str}')


if __name__ == '__main__':
    main()
