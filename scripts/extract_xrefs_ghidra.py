#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "pyghidra",
# ]
# ///
"""Extract cross-references from a binary using Ghidra and write them
as a JSON array compatible with the xr benchmark format.

Usage:
    uv run scripts/extract_xrefs_ghidra.py <binary> <output.json>

Kind mapping (Ghidra RefType -> xr):
    UNCONDITIONAL_CALL / COMPUTED_CALL / CALL_TERMINATOR  -> call
    UNCONDITIONAL_JUMP / COMPUTED_JUMP / CONDITIONAL_JUMP -> jump
    READ / READ_INDIRECT / READ_IND / READ_WRITE           -> data_read
    WRITE / WRITE_INDIRECT / WRITE_IND                     -> data_write
    DATA / PARAM / INDIRECTION / OFFSET_REFERENCE          -> data_ptr
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


GHIDRA_INSTALL = Path(os.environ.get('GHIDRA_INSTALL', str(Path.home() / 'ghidra')))


def reftype_to_kind(rt) -> str | None:
    """Map a Ghidra RefType to an xr kind string, or None to skip."""
    name = str(rt)
    # Call
    if name in (
        'UNCONDITIONAL_CALL',
        'COMPUTED_CALL',
        'COMPUTED_CALL_TERMINATOR',
        'CALL_TERMINATOR',
        'CONDITIONAL_CALL',
        'CONDITIONAL_CALL_TERMINATOR',
    ):
        return 'call'
    # Jump
    if name in (
        'UNCONDITIONAL_JUMP',
        'COMPUTED_JUMP',
        'CONDITIONAL_JUMP',
        'CONDITIONAL_COMPUTED_JUMP',
        'JUMP_TERMINATOR',
        'CONDITIONAL_JUMP_TERMINATOR',
    ):
        return 'jump'
    # Data read
    if name in ('READ', 'READ_INDIRECT', 'READ_IND', 'READ_WRITE', 'READ_WRITE_INDIRECT'):
        return 'data_read'
    # Data write
    if name in ('WRITE', 'WRITE_INDIRECT', 'WRITE_IND'):
        return 'data_write'
    # Data pointer / offset reference
    if name in ('DATA', 'PARAM', 'INDIRECTION', 'POINTER_INDIRECT_RELATIVE', 'OFFSET_REFERENCE'):
        return 'data_ptr'
    # Everything else (FALL_THROUGH, FLOW, EXTERNAL_REF, etc.) — skip
    return None


def ghidra_image_base(program) -> int:
    """Return the image base Ghidra applied to this program."""
    return program.getImageBase().getOffset()


def extract(binary_path: Path, out_path: Path, ghidra_install: Path) -> None:
    import pyghidra

    print(f'[ghidra] launching for {binary_path.name} ...', flush=True)
    pyghidra.start(install_dir=ghidra_install)
    with pyghidra.open_program(
        binary_path,
        project_location='/tmp/ghidra_proj',
        project_name=binary_path.name + '_proj',
        analyze=True,
    ) as flat_api:
        program = flat_api.getCurrentProgram()
        ref_mgr = program.getReferenceManager()

        # Detect and subtract Ghidra's applied image base so addresses match
        # the raw virtual addresses xr-xrefs reads from ELF/PE/Mach-O headers.
        # For PIE ELF shared libs Ghidra defaults to 0x100000; PE and Mach-O
        # binaries have their own preferred base baked in.
        image_base = ghidra_image_base(program)
        print(f'[ghidra] image_base={hex(image_base)}', flush=True)

        xrefs: list[dict] = []
        it = ref_mgr.getReferenceIterator(program.getMinAddress())
        count_skipped = 0

        while it.hasNext():
            ref = it.next()
            # Only memory-to-memory refs (skip stack, register, external)
            if not ref.isMemoryReference():
                count_skipped += 1
                continue

            kind = reftype_to_kind(ref.getReferenceType())
            if kind is None:
                count_skipped += 1
                continue

            from_va = ref.getFromAddress().getOffset() - image_base
            to_va = ref.getToAddress().getOffset() - image_base

            # Filter sentinel/invalid addresses (e.g. Ghidra stub sentinels)
            if from_va < 0 or to_va < 0:
                count_skipped += 1
                continue

            xrefs.append({'from': from_va, 'to': to_va, 'kind': kind})

        print(
            f'[ghidra] {binary_path.name}: {len(xrefs)} xrefs extracted '
            f'({count_skipped} skipped)',
            flush=True,
        )

    out_path.write_text(json.dumps(xrefs, indent=2))
    print(f'[ghidra] wrote {out_path}', flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(
        description='Extract xrefs from a binary via Ghidra headless analysis'
    )
    parser.add_argument('binary', type=Path, help='Binary to analyse')
    parser.add_argument('output', type=Path, help='Output JSON path')
    parser.add_argument(
        '--ghidra',
        type=Path,
        default=GHIDRA_INSTALL,
        help='Ghidra installation directory',
    )
    args = parser.parse_args()

    if not args.binary.exists():
        print(f'error: binary not found: {args.binary}', file=sys.stderr)
        sys.exit(1)

    if not args.ghidra.exists():
        print(f'error: Ghidra install dir not found: {args.ghidra}', file=sys.stderr)
        sys.exit(1)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    extract(args.binary, args.output, args.ghidra)


if __name__ == '__main__':
    main()
