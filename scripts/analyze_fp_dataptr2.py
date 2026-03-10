#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.10"
# dependencies = ["capstone"]
# ///
"""
Analyze actual data_ptr FPs from xr benchmark dumps.
Classifies FPs by:
  1. Source location (exec segment = instruction pair, data segment = byte scan)
  2. Destination validity (in segment vs not)
  3. For exec-source FPs: what instruction at src, what's the ADRP pattern
"""
import json
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

import capstone


CASES = [
    ('testcases/curl-aarch64', '/tmp/arm64_fp_dataptr.json', '/tmp/arm64_fn_dataptr.json', 'arm64'),
    ('testcases/curl-amd64',   '/tmp/x86_fp_dataptr.json',   '/tmp/x86_fn_dataptr.json',   'x86_64'),
]


@dataclass
class Xref:
    src: int
    dst: int
    kind: str


def load_xrefs(path: str) -> list[Xref]:
    with open(path) as f:
        data = json.load(f)
    return [Xref(src=e['from'], dst=e['to'], kind=e['kind']) for e in data]


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
    return any(vaddr <= va < vaddr + memsz and bool(flags & 1) for (vaddr, memsz, _, flags) in segs)


def va_in_any(va: int, segs: list) -> bool:
    return any(vaddr <= va < vaddr + memsz for (vaddr, memsz, _, _) in segs)


def va_to_file_offset(binary: bytes, segs: list, va: int) -> int | None:
    for (vaddr, memsz, fileoff, _) in segs:
        filesz = min(memsz, max(0, len(binary) - fileoff))
        if vaddr <= va < vaddr + filesz:
            return fileoff + (va - vaddr)
    return None


def analyze(binary_path: str, fp_path: str, fn_path: str, arch_name: str) -> None:
    print(f'\n{"="*60}')
    print(f'  {arch_name}: {binary_path}')
    print(f'{"="*60}')

    fps = load_xrefs(fp_path)
    fns = load_xrefs(fn_path)
    binary = load_binary(binary_path)
    segs = parse_elf_segments(binary)

    print(f'FPs: {len(fps)}  FNs: {len(fns)}')

    # Classify FPs by source location
    exec_fps = [x for x in fps if va_in_exec(x.src, segs)]
    data_fps  = [x for x in fps if not va_in_exec(x.src, segs)]
    print(f'\nFP source breakdown:')
    print(f'  In exec segment (instruction pairs): {len(exec_fps)} ({100*len(exec_fps)/len(fps):.1f}%)')
    print(f'  In data segment (byte scan):         {len(data_fps)} ({100*len(data_fps)/len(fps):.1f}%)')

    # Classify FP destinations
    dst_in_exec = sum(1 for x in fps if va_in_exec(x.dst, segs))
    dst_not_mapped = sum(1 for x in fps if not va_in_any(x.dst, segs))
    dst_in_data = len(fps) - dst_in_exec - dst_not_mapped
    print(f'\nFP destination breakdown:')
    print(f'  Target in exec:      {dst_in_exec} ({100*dst_in_exec/len(fps):.1f}%)')
    print(f'  Target in data:      {dst_in_data} ({100*dst_in_data/len(fps):.1f}%)')
    print(f'  Target not mapped:   {dst_not_mapped} ({100*dst_not_mapped/len(fps):.1f}%)')

    # For data-segment FPs (byte scan): what are the source alignments?
    if data_fps:
        align_counter: Counter[str] = Counter()
        for x in data_fps:
            if x.src % 8 == 0:
                align_counter['8B aligned'] += 1
            elif x.src % 4 == 0:
                align_counter['4B aligned'] += 1
            else:
                align_counter['unaligned'] += 1
        print(f'\nData-segment FP source alignments:')
        for k, v in align_counter.most_common():
            print(f'  {k}: {v} ({100*v/len(data_fps):.1f}%)')

        # For byte-scan FPs: are target addresses word-aligned pointers?
        tgt_align: Counter[str] = Counter()
        for x in data_fps:
            if x.dst % 8 == 0:
                tgt_align['8B aligned'] += 1
            elif x.dst % 4 == 0:
                tgt_align['4B aligned'] += 1
            else:
                tgt_align['unaligned'] += 1
        print(f'\nData-segment FP target alignments (FPs from byte scan):')
        for k, v in tgt_align.most_common():
            print(f'  {k}: {v} ({100*v/len(data_fps):.1f}%)')

    # Disassemble exec-source FPs to see what instructions are there
    if exec_fps and arch_name == 'arm64':
        md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        mnem_counter: Counter[str] = Counter()
        prev_mnem_counter: Counter[str] = Counter()
        examples: dict[str, list] = {}

        for x in exec_fps:
            foff = va_to_file_offset(binary, segs, x.src)
            if foff is None or foff + 8 > len(binary):
                mnem_counter['(unmapped)'] += 1
                continue
            insns = list(md.disasm(binary[foff:foff+4], x.src))
            mnem = insns[0].mnemonic.upper() if insns else '(fail)'
            mnem_counter[mnem] += 1

            prev_foff = va_to_file_offset(binary, segs, x.src - 4)
            prev_mnem = '(none)'
            if prev_foff is not None:
                prev_insns = list(md.disasm(binary[prev_foff:prev_foff+4], x.src - 4))
                prev_mnem = prev_insns[0].mnemonic.upper() if prev_insns else '(fail)'
            prev_mnem_counter[f'{prev_mnem}+{mnem}'] += 1

            if mnem not in examples:
                examples[mnem] = []
            if len(examples[mnem]) < 3:
                insn_str = f'{insns[0].mnemonic} {insns[0].op_str}' if insns else '?'
                examples[mnem].append((x.src, x.dst, insn_str, prev_mnem))

        print(f'\nExec-source FP instruction breakdown (ARM64):')
        for mnem, count in mnem_counter.most_common(15):
            print(f'  {mnem:20s}  {count:5d}  ({100*count/len(exec_fps):.1f}%)')

        print(f'\nExec-source FP top pairs (prev+src):')
        for pair, count in prev_mnem_counter.most_common(15):
            print(f'  {pair:40s}  {count:5d}  ({100*count/len(exec_fps):.1f}%)')

        print(f'\nExec-source FP examples per mnemonic:')
        for mnem, exs in sorted(examples.items()):
            print(f'\n  --- {mnem} ---')
            for src, dst, insn_str, prev_mnem in exs:
                print(f'    src=0x{src:x}  fp_dst=0x{dst:x}')
                print(f'      prev: {prev_mnem}')
                print(f'      insn: {insn_str}')

    elif exec_fps and arch_name == 'x86_64':
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        mnem_counter: Counter[str] = Counter()
        for x in exec_fps[:200]:  # sample
            foff = va_to_file_offset(binary, segs, x.src)
            if foff is None:
                continue
            insns = list(md.disasm(binary[foff:foff+15], x.src))
            mnem = insns[0].mnemonic.upper() if insns else '(fail)'
            mnem_counter[mnem] += 1
        print(f'\nExec-source FP instruction breakdown (x86-64, sample of {min(200, len(exec_fps))}):')
        for mnem, count in mnem_counter.most_common(10):
            print(f'  {mnem:20s}  {count}')

    # FN analysis: classify by source location too
    exec_fns = [x for x in fns if va_in_exec(x.src, segs)]
    data_fns  = [x for x in fns if not va_in_exec(x.src, segs)]
    print(f'\nFN source breakdown:')
    print(f'  In exec segment (missed instruction pairs): {len(exec_fns)} ({100*len(exec_fns)/len(fns):.1f}%)')
    print(f'  In data segment (missed byte scan):         {len(data_fns)} ({100*len(data_fns)/len(fns):.1f}%)')

    if data_fns:
        # For data-seg FNs: source alignment
        align_counter2: Counter[str] = Counter()
        for x in data_fns:
            if x.src % 8 == 0:
                align_counter2['8B aligned'] += 1
            elif x.src % 4 == 0:
                align_counter2['4B aligned'] += 1
            else:
                align_counter2['unaligned'] += 1
        print(f'\nData-segment FN source alignments (byte-scan misses):')
        for k, v in align_counter2.most_common():
            print(f'  {k}: {v} ({100*v/len(data_fns):.1f}%)')


def main() -> None:
    for binary_path, fp_path, fn_path, arch_name in CASES:
        if not Path(fp_path).exists():
            print(f'Skipping {arch_name}: {fp_path} not found')
            continue
        analyze(binary_path, fp_path, fn_path, arch_name)


if __name__ == '__main__':
    main()
