#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.10"
# dependencies = ["capstone"]
# ///
"""
Analyze ARM64 data_write false-negatives (xrefs IDA has that xr misses).

Runs the benchmark binary in a special mode — we invoke the xr benchmark
and parse its output to get FN addresses, then disassemble each with capstone
to see what instruction patterns IDA records.

Usage:
    uv run scripts/analyze_fn_datawrite.py
"""
import json
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass

import capstone


BINARY = 'testcases/TARGET_BINARY'
GROUND_TRUTH = 'testcases/TARGET_BINARY.xrefs.json'


@dataclass
class Xref:
    src: int
    dst: int
    kind: str


def load_ground_truth(path: str) -> list[Xref]:
    with open(path) as f:
        data = json.load(f)
    xrefs = []
    for entry in data:
        xrefs.append(Xref(
            src=entry['from'],
            dst=entry['to'],
            kind=entry['kind'],
        ))
    return xrefs


def load_binary(path: str) -> bytes:
    with open(path, 'rb') as f:
        return f.read()


def find_load_address(binary: bytes) -> int:
    """Parse ELF to find the base load address (lowest PT_LOAD vaddr)."""
    # ELF magic check
    if binary[:4] != b'\x7fELF':
        return 0
    # 64-bit ELF
    e_phoff = int.from_bytes(binary[0x20:0x28], 'little')
    e_phentsize = int.from_bytes(binary[0x36:0x38], 'little')
    e_phnum = int.from_bytes(binary[0x38:0x3a], 'little')

    min_vaddr = None
    min_offset = None
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type = int.from_bytes(binary[off:off+4], 'little')
        if p_type != 1:  # PT_LOAD
            continue
        p_offset = int.from_bytes(binary[off+8:off+16], 'little')
        p_vaddr = int.from_bytes(binary[off+16:off+24], 'little')
        if min_vaddr is None or p_vaddr < min_vaddr:
            min_vaddr = p_vaddr
            min_offset = p_offset

    return 0  # PIE: actual load address is in the binary itself, not rebased


def va_to_file_offset(binary: bytes, va: int) -> int | None:
    """Convert a virtual address to a file offset using ELF PT_LOAD segments."""
    e_phoff = int.from_bytes(binary[0x20:0x28], 'little')
    e_phentsize = int.from_bytes(binary[0x36:0x38], 'little')
    e_phnum = int.from_bytes(binary[0x38:0x3a], 'little')

    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type = int.from_bytes(binary[off:off+4], 'little')
        if p_type != 1:  # PT_LOAD
            continue
        p_offset = int.from_bytes(binary[off+8:off+16], 'little')
        p_vaddr = int.from_bytes(binary[off+16:off+24], 'little')
        p_filesz = int.from_bytes(binary[off+32:off+40], 'little')

        if p_vaddr <= va < p_vaddr + p_filesz:
            return p_offset + (va - p_vaddr)
    return None


def get_xr_xrefs() -> list[Xref]:
    """Run the xr benchmark binary and parse its JSON output."""
    # Check if there's a --json flag or similar; if not, we'll parse the text output
    # Actually, let's just load the ground truth and run xr in a separate way.
    # For now, use a Rust helper or parse the text. Let's use cargo run directly.
    result = subprocess.run(
        ['cargo', 'run', '--release', '--bin', 'benchmark', '--',
         '--binary', BINARY, '--ground-truth', GROUND_TRUTH,
         '--depth', 'Paired'],
        capture_output=True, text=True, cwd='.'
    )
    # The benchmark doesn't output xrefs as JSON, so we'll need another approach.
    # Let's instead use a different approach: parse GT xrefs, run xr binary
    # directly to get xrefs, compare.
    return []


def main() -> None:
    print(f'Loading ground truth from {GROUND_TRUTH}...')
    gt_xrefs = load_ground_truth(GROUND_TRUTH)
    dw_xrefs = [x for x in gt_xrefs if x.kind == 'data_write']
    print(f'Total GT data_write: {len(dw_xrefs)}')

    print(f'Loading binary {BINARY}...')
    binary = load_binary(BINARY)

    # We need to know which ones xr misses.
    # Let's build xr's xrefs by running the CLI tool if there's one,
    # or we can look at the benchmark output. Since we can't easily get
    # xr's xrefs as a list without modifying the code, let's instead
    # look at ALL GT data_write xrefs and disassemble 2 instructions at
    # each source to categorize the patterns.

    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = True

    # Categorize all GT data_write by instruction at src
    src_insn_counter: Counter[str] = Counter()
    prev_insn_counter: Counter[str] = Counter()  # instruction BEFORE src (for pair detection)

    print('\nDisassembling GT data_write source addresses...')
    unknown_count = 0
    examples: dict[str, list[tuple[int, int, str, str]]] = {}  # mnemonic -> [(src, dst, insn, prev_insn)]

    for xref in dw_xrefs:
        file_off = va_to_file_offset(binary, xref.src)
        if file_off is None or file_off + 8 > len(binary):
            unknown_count += 1
            continue

        # Disassemble 2 instructions: the one before (for ADRP) and the one at src
        prev_off = file_off - 4
        chunk = binary[max(0, prev_off): file_off + 8]

        insns = list(md.disasm(chunk, xref.src - 4 if prev_off >= 0 else xref.src))

        src_insn = None
        prev_insn = None
        for i, insn in enumerate(insns):
            if insn.address == xref.src:
                src_insn = insn
                if i > 0:
                    prev_insn = insns[i - 1]
                break

        if src_insn is None:
            unknown_count += 1
            src_insn_counter['(decode_failed)'] += 1
            continue

        mnem = src_insn.mnemonic.upper()
        src_insn_counter[mnem] += 1
        prev_mnem = prev_insn.mnemonic.upper() if prev_insn else '(none)'
        pair_key = f'{prev_mnem}+{mnem}'
        prev_insn_counter[pair_key] += 1

        if mnem not in examples:
            examples[mnem] = []
        if len(examples[mnem]) < 5:
            prev_str = f'{prev_insn.mnemonic} {prev_insn.op_str}' if prev_insn else '(none)'
            src_str = f'{src_insn.mnemonic} {src_insn.op_str}'
            examples[mnem].append((xref.src, xref.dst, src_str, prev_str))

    print(f'\n=== GT data_write source instruction breakdown ({len(dw_xrefs)} total) ===')
    for mnem, count in src_insn_counter.most_common():
        pct = 100 * count / len(dw_xrefs)
        print(f'  {mnem:20s}  {count:4d}  ({pct:.1f}%)')
    if unknown_count:
        print(f'  (unmapped/failed)      {unknown_count:4d}')

    print(f'\n=== Top instruction pairs (prev+src) ===')
    for pair, count in prev_insn_counter.most_common(20):
        pct = 100 * count / len(dw_xrefs)
        print(f'  {pair:40s}  {count:4d}  ({pct:.1f}%)')

    print(f'\n=== Examples per mnemonic ===')
    for mnem, exs in sorted(examples.items()):
        print(f'\n  --- {mnem} ---')
        for src, dst, insn_str, prev_str in exs:
            print(f'    src=0x{src:x}  dst=0x{dst:x}')
            print(f'      prev: {prev_str}')
            print(f'      insn: {insn_str}')


if __name__ == '__main__':
    main()
