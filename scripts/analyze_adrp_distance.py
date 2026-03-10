#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.10"
# dependencies = ["capstone"]
# ///
"""
For each GT data_write FN (base-register stores), find the ADRP that
set the base register and measure how many instructions back it is.
This tells us whether extending the ADRP window would help.
"""
import json
from collections import Counter
from dataclasses import dataclass

import capstone


BINARY = 'testcases/curl-aarch64'
GROUND_TRUTH = 'testcases/curl-aarch64.xrefs.json'
# Search up to this many instructions back for ADRP
MAX_SEARCH = 200


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


def store_base_reg(insn: capstone.CsInsn) -> str | None:
    op_str = insn.op_str
    bracket_start = op_str.find('[')
    bracket_end = op_str.find(']')
    if bracket_start == -1 or bracket_end == -1:
        return None
    mem = op_str[bracket_start+1:bracket_end]
    parts = [p.strip() for p in mem.split(',')]
    return parts[0]


def store_offset(insn: capstone.CsInsn) -> int:
    op_str = insn.op_str
    bracket_start = op_str.find('[')
    bracket_end = op_str.find(']')
    if bracket_start == -1 or bracket_end == -1:
        return 0
    mem = op_str[bracket_start+1:bracket_end]
    parts = [p.strip() for p in mem.split(',')]
    if len(parts) > 1:
        off_str = parts[1].lstrip('#')
        try:
            return int(off_str, 0)
        except ValueError:
            pass
    return 0


def main() -> None:
    gt_xrefs = load_ground_truth(GROUND_TRUTH)
    dw_xrefs = [x for x in gt_xrefs if x.kind == 'data_write']
    binary = load_binary(BINARY)
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)

    distance_counter: Counter[str] = Counter()  # "N" or "not_found" or "mismatch"
    not_found_examples = []
    mismatch_examples = []

    for xref in dw_xrefs:
        file_off = va_to_file_offset(binary, xref.src)
        if file_off is None:
            distance_counter['no_file_offset'] += 1
            continue

        # Read from far back
        window_bytes = MAX_SEARCH * 4
        start_va = xref.src - window_bytes
        start_off = va_to_file_offset(binary, start_va)
        if start_off is None:
            start_va = xref.src - 20 * 4
            start_off = va_to_file_offset(binary, start_va)
        if start_off is None:
            distance_counter['no_start_offset'] += 1
            continue

        read_len = file_off - start_off + 4
        if start_off + read_len > len(binary):
            distance_counter['out_of_bounds'] += 1
            continue

        chunk = binary[start_off: start_off + read_len]
        insns = list(md.disasm(chunk, start_va))

        # Find src instruction
        src_idx = None
        for i, insn in enumerate(insns):
            if insn.address == xref.src:
                src_idx = i
                break

        if src_idx is None:
            distance_counter['src_not_decoded'] += 1
            continue

        src_insn = insns[src_idx]
        if src_insn.mnemonic.lower() not in STORE_MNEMS:
            distance_counter['not_a_store'] += 1
            continue

        base_reg = store_base_reg(src_insn)
        offset = store_offset(src_insn)
        if base_reg is None:
            distance_counter['no_base_reg'] += 1
            continue

        # Search backwards for ADRP setting base_reg
        found_at = None
        found_target = None
        for j in range(src_idx - 1, -1, -1):
            candidate = insns[j]
            if candidate.mnemonic.lower() != 'adrp':
                continue
            parts = candidate.op_str.split(',')
            if not parts:
                continue
            dest_reg = parts[0].strip()
            if dest_reg != base_reg:
                continue
            # Found ADRP for base_reg
            dist = src_idx - j
            imm_str = parts[1].strip().lstrip('#')
            try:
                page = int(imm_str, 0)
            except ValueError:
                continue
            found_at = dist
            found_target = page + offset
            break

        if found_at is None:
            distance_counter['adrp_not_found'] += 1
            if len(not_found_examples) < 10:
                src_str = f'{src_insn.mnemonic} {src_insn.op_str}'
                not_found_examples.append((xref.src, xref.dst, src_str, base_reg))
        elif found_target != xref.dst:
            distance_counter[f'mismatch@{found_at}'] += 1
            if len(mismatch_examples) < 5:
                src_str = f'{src_insn.mnemonic} {src_insn.op_str}'
                mismatch_examples.append((xref.src, xref.dst, found_target, found_at, src_str, base_reg))
        else:
            bucket = found_at if found_at <= 20 else (f'{(found_at//10)*10}+')
            distance_counter[f'found@{bucket}'] += 1

    print(f'=== ADRP distance distribution for all {len(dw_xrefs)} GT data_write xrefs ===')
    for key, count in sorted(distance_counter.items(), key=lambda x: x[0]):
        pct = 100 * count / len(dw_xrefs)
        print(f'  {key:40s}  {count:4d}  ({pct:.1f}%)')

    print(f'\n=== "adrp_not_found" examples (base reg never set by ADRP in {MAX_SEARCH} insns back) ===')
    for src, dst, insn_str, base_reg in not_found_examples:
        print(f'  src=0x{src:x}  gt_dst=0x{dst:x}  base={base_reg}  insn: {insn_str}')

    print(f'\n=== "mismatch" examples (ADRP found but computed target != GT dst) ===')
    for src, dst, computed, dist, insn_str, base_reg in mismatch_examples:
        print(f'  src=0x{src:x}  gt_dst=0x{dst:x}  computed=0x{computed:x}  dist={dist}  base={base_reg}  insn: {insn_str}')


if __name__ == '__main__':
    main()
