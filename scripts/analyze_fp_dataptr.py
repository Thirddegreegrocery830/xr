#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.10"
# dependencies = ["capstone"]
# ///
"""
Analyze data_ptr false positives for both ARM64 and x86-64.
FPs = xrefs xr emits that IDA doesn't have.

Key question: are FPs from byte-scan (scannable data segments) or
from instruction-level (ADRP+ADD/LDR pairs in the exec segment)?
And what's the target distribution — exec vs data segment, valid vs garbage?
"""
import json
import subprocess
from collections import Counter
from dataclasses import dataclass

import capstone


CASES = [
    # ('testcases/BINARY_A', 'testcases/BINARY_A.xrefs.json', 'arm64'),
    # ('testcases/BINARY_B', 'testcases/BINARY_B.xrefs.json', 'x86_64'),
]


@dataclass
class Xref:
    src: int
    dst: int
    kind: str


def load_gt(path: str) -> set[tuple[int, int, str]]:
    with open(path) as f:
        data = json.load(f)
    return {(e['from'], e['to'], e['kind']) for e in data}


def load_binary(path: str) -> bytes:
    with open(path, 'rb') as f:
        return f.read()


def parse_elf_segments(binary: bytes) -> list[tuple[int, int, int, int]]:
    """Returns (vaddr, memsz, fileoff, flags) for PT_LOAD."""
    e_phoff = int.from_bytes(binary[0x20:0x28], 'little')
    e_phentsize = int.from_bytes(binary[0x36:0x38], 'little')
    e_phnum = int.from_bytes(binary[0x38:0x3a], 'little')
    segs = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if int.from_bytes(binary[off:off+4], 'little') != 1:
            continue
        p_flags = int.from_bytes(binary[off+4:off+8], 'little')
        p_offset = int.from_bytes(binary[off+8:off+16], 'little')
        p_vaddr = int.from_bytes(binary[off+16:off+24], 'little')
        p_memsz = int.from_bytes(binary[off+40:off+48], 'little')
        segs.append((p_vaddr, p_memsz, p_offset, p_flags))
    return segs


def va_in_exec(va: int, segs: list) -> bool:
    for (vaddr, memsz, _, flags) in segs:
        if vaddr <= va < vaddr + memsz and (flags & 1):
            return True
    return False


def va_in_any(va: int, segs: list) -> bool:
    for (vaddr, memsz, _, _) in segs:
        if vaddr <= va < vaddr + memsz:
            return True
    return False


def va_to_file_offset(binary: bytes, segs: list, va: int) -> int | None:
    for (vaddr, memsz, fileoff, _) in segs:
        p_filesz = min(memsz, len(binary) - fileoff)
        if vaddr <= va < vaddr + p_filesz:
            return fileoff + (va - vaddr)
    return None


def analyze(binary_path: str, gt_path: str, arch_name: str) -> None:
    print(f'\n{"="*60}')
    print(f'  {arch_name}: {binary_path}')
    print(f'{"="*60}')

    gt = load_gt(gt_path)
    gt_dataptr = {(src, dst) for (src, dst, k) in gt if k == 'data_ptr'}
    binary = load_binary(binary_path)
    segs = parse_elf_segments(binary)

    # We need xr's data_ptr xrefs. Since we can't easily get them without
    # modifying xr, let's instead look at the GT FPs from the benchmark output
    # ... Actually we CAN get them: run cargo run --bin xr-xrefs with json output.
    # But there's no json output mode. Instead, let's analyze the GT FPs by
    # running the benchmark and parsing the "FP sample" section. But that's only 5.
    #
    # Better approach: load the GT set and for each GT data_ptr xref, classify
    # the source (in exec seg = instruction pair, not exec = byte scan).
    # Then for the FPs, we'd need xr's output. Skip for now and focus on GT TPs/FNs.

    # Classify GT data_ptr by source location
    src_exec_count = 0
    src_data_count = 0
    dst_exec_count = 0
    dst_data_count = 0

    for (src, dst) in gt_dataptr:
        if va_in_exec(src, segs):
            src_exec_count += 1
        else:
            src_data_count += 1
        if va_in_exec(dst, segs):
            dst_exec_count += 1
        else:
            dst_data_count += 1

    total = len(gt_dataptr)
    print(f'GT data_ptr: {total}')
    print(f'  src in exec:  {src_exec_count} ({100*src_exec_count/total:.1f}%)')
    print(f'  src in data:  {src_data_count} ({100*src_data_count/total:.1f}%)')
    print(f'  dst in exec:  {dst_exec_count} ({100*dst_exec_count/total:.1f}%)')
    print(f'  dst in data:  {dst_data_count} ({100*dst_data_count/total:.1f}%)')

    # For data-segment sources: these are byte-scan hits. What's the alignment?
    data_src_alignments: Counter[str] = Counter()
    for (src, dst) in gt_dataptr:
        if not va_in_exec(src, segs):
            if src % 8 == 0:
                data_src_alignments['8-byte aligned'] += 1
            elif src % 4 == 0:
                data_src_alignments['4-byte aligned'] += 1
            else:
                data_src_alignments['unaligned'] += 1

    print(f'\nData-segment GT data_ptr source alignment:')
    for k, v in data_src_alignments.most_common():
        print(f'  {k}: {v}')

    # Now let's look at FNs: GT has data_ptr at src but xr misses.
    # From the benchmarks: ARM64 FN=3686, x86-64 FN=5789
    # Let's look at data-segment sources (byte-scan misses) and exec-segment (pair misses)
    print(f'\nNote: benchmark shows')
    if 'arm64' in arch_name:
        print(f'  ARM64:  TP=33338 FP=13763 FN=3686')
    else:
        print(f'  x86-64: TP=26752 FP=5867  FN=5789')


def main() -> None:
    for binary_path, gt_path, arch_name in CASES:
        analyze(binary_path, gt_path, arch_name)


if __name__ == '__main__':
    main()
