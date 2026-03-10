#!/usr/bin/env -S uv run --with idapro
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Extract cross-references from a binary (or IDB) using IDA Pro idalib.

For a raw binary: IDA creates a temporary IDB, runs full auto-analysis,
then xrefs are extracted and the temp IDB is discarded.

For an existing .i64/.idb: opened read-only (no analysis run).

Usage:
    uv run --with idapro scripts/ida_extract_xrefs_binary.py <binary_or_idb> <output.json>

Kind mapping (IDA xref type -> xr):
    fl_CF (16) / fl_CN (17)  -> call
    fl_JF (18) / fl_JN (19)  -> jump
    dr_R  (3)                -> data_read
    dr_W  (2)                -> data_write
    dr_O  (1)                -> data_ptr
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import idapro
import ida_auto
import ida_nalt
import ida_xref
import idautils
import idc


_IDB_SUFFIXES = {'.i64', '.idb', '.id0'}


def kind_str(xref_type: int, is_code: bool) -> str | None:
    """Map an IDA xref type to an xr kind string, or None to skip."""
    if is_code:
        if xref_type in (16, 17):   # fl_CF, fl_CN
            return 'call'
        if xref_type in (18, 19):   # fl_JF, fl_JN
            return 'jump'
        return None                 # fl_F (flow), fl_U (user), etc. — skip
    # Data refs
    match xref_type:
        case 1: return 'data_ptr'   # dr_O offset
        case 2: return 'data_write' # dr_W
        case 3: return 'data_read'  # dr_R
        case _: return None         # dr_T (enum), dr_I (struct), etc.


def extract_xrefs() -> dict:
    """Extract all non-flow xrefs from the currently open IDA database.

    Returns a dict with:
      image_base  — IDA's load address for the binary (from ida_nalt.get_image_base()).
                    The benchmark uses this to rebase xr's output before comparison,
                    so PIE ELFs loaded at a non-standard address score correctly.
      xrefs       — list of {from, to, kind} dicts.
    """
    image_base = ida_nalt.get_imagebase()
    min_ea = idc.get_inf_attr(idc.INF_MIN_EA)
    max_ea = idc.get_inf_attr(idc.INF_MAX_EA)
    print(f'  image_base : {image_base:#x}', flush=True)
    print(f'  range      : {min_ea:#x} .. {max_ea:#x}', flush=True)

    # IDA encodes type-system xrefs (struct fields, enum values) as refs
    # whose 'to' address has the upper byte set (0xff...). These are not
    # real memory addresses and must be excluded from ground-truth data.
    IDA_MAX_REAL_VA = 0x00ff_ffff_ffff_ffff

    xrefs: list[dict] = []
    ea = min_ea
    visited = 0

    while ea < max_ea:
        for xr in idautils.XrefsFrom(ea, ida_xref.XREF_NOFLOW):
            if not xr.frm or not xr.to:
                continue
            if xr.frm > IDA_MAX_REAL_VA or xr.to > IDA_MAX_REAL_VA:
                continue  # synthetic type-system address
            kind = kind_str(xr.type, bool(xr.iscode))
            if kind is None:
                continue
            xrefs.append({'from': xr.frm, 'to': xr.to, 'kind': kind})

        visited += 1
        ea = idc.next_head(ea, max_ea)
        if visited % 100_000 == 0:
            print(f'  {visited} heads scanned, {len(xrefs)} xrefs so far ...', flush=True)

    return {'image_base': image_base, 'xrefs': xrefs}


def main() -> None:
    parser = argparse.ArgumentParser(
        description='Extract IDA xrefs from a binary or IDB to JSON'
    )
    parser.add_argument('input', type=Path, help='Binary or .i64/.idb to analyse')
    parser.add_argument('output', type=Path, help='Output JSON path')
    args = parser.parse_args()

    inp: Path = args.input.resolve()
    if not inp.exists():
        sys.exit(f'error: {inp} not found')

    out: Path = args.output
    out.parent.mkdir(parents=True, exist_ok=True)

    is_idb = inp.suffix.lower() in _IDB_SUFFIXES
    run_analysis = not is_idb

    print(f'input  : {inp}', flush=True)
    print(f'output : {out}', flush=True)
    print(f'mode   : {"open IDB (no re-analysis)" if is_idb else "import binary + full analysis"}', flush=True)

    rc = idapro.open_database(str(inp), run_auto_analysis=run_analysis)
    if rc != 0:
        sys.exit(f'open_database failed rc={rc}')

    try:
        # Ensure analysis is fully complete (no-op if already done)
        ida_auto.auto_wait()

        t0 = time.perf_counter()
        result = extract_xrefs()
        elapsed = time.perf_counter() - t0

        print(f'  extracted {len(result["xrefs"])} xrefs in {elapsed:.1f}s', flush=True)
        print(f'  image_base : {result["image_base"]:#x}', flush=True)

    finally:
        idapro.close_database(save=False)

    out.write_text(json.dumps(result, separators=(',', ':')))
    print(f'wrote  : {out}  ({out.stat().st_size // 1024} KB)', flush=True)


if __name__ == '__main__':
    main()
