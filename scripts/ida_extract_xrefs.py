#!/usr/bin/env -S uv run --with idapro
"""
Open a raw binary with IDA idalib, run full auto-analysis, decompile all
functions (which resolves indirect calls via type propagation), then dump
every non-flow xref to JSON.

Usage:
    uv run --with idapro scripts/ida_extract_xrefs.py <binary> [--out <json>]

The IDB is created next to the binary in the same directory (testcases/).
Existing IDBs are removed first so we always start fresh.

Output JSON: [{"from": <int>, "to": <int>, "kind": <str>}, ...]

kind values:
    "call"       fl_CF / fl_CN
    "jump"       fl_JF / fl_JN
    "data_read"  dr_R
    "data_write" dr_W
    "data_ptr"   dr_O (offset/pointer)
    "data"       other dr_*
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import idapro  # must be first — initialises libidalib


def kind_str(xref_type: int, is_code: bool) -> str:
    if is_code:
        if xref_type in (16, 17):   # fl_CF, fl_CN
            return 'call'
        if xref_type in (18, 19):   # fl_JF, fl_JN
            return 'jump'
        return 'code'               # fl_F and others (shouldn't appear with NOFLOW)
    # Data: dr_O=1 dr_R=3 dr_W=2 dr_T=4 dr_I=5 dr_S=6
    if xref_type == 3:
        return 'data_read'
    if xref_type == 2:
        return 'data_write'
    if xref_type == 1:
        return 'data_ptr'
    return 'data'


def dump_xrefs() -> list[dict]:
    import ida_xref
    import idautils
    import idc

    xrefs: list[dict] = []
    min_ea = idc.get_inf_attr(idc.INF_MIN_EA)
    max_ea = idc.get_inf_attr(idc.INF_MAX_EA)
    print(f'  range: {min_ea:#x} .. {max_ea:#x}')

    visited = 0
    ea = min_ea
    while ea < max_ea:
        for xr in idautils.XrefsFrom(ea, ida_xref.XREF_NOFLOW):
            if xr.to == 0 or xr.frm == 0:
                continue
            xrefs.append({
                'from': xr.frm,
                'to': xr.to,
                'kind': kind_str(xr.type, bool(xr.iscode)),
            })
        visited += 1
        ea = idc.next_head(ea, max_ea)
        if visited % 100_000 == 0:
            print(f'    {visited} heads visited, {len(xrefs)} xrefs so far')

    return xrefs


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('binary', help='Raw binary to analyse')
    parser.add_argument('--out', help='Output JSON (default: <binary>.xrefs.json)')
    parser.add_argument('--skip-decompile', action='store_true',
                        help='Skip hexrays batch decompilation (faster, fewer xrefs)')
    parser.add_argument('--reuse-idb', action='store_true',
                        help='Open existing IDB instead of re-analysing the binary')
    args = parser.parse_args()

    binary = Path(args.binary).resolve()
    if not binary.exists():
        sys.exit(f'error: {binary} not found')

    idb = binary.with_suffix('.i64')
    out = Path(args.out) if args.out else binary.with_suffix('.xrefs.json')

    print(f'binary : {binary}')
    print(f'idb    : {idb}')
    print(f'output : {out}')

    if args.reuse_idb:
        if not idb.exists():
            sys.exit(f'error: --reuse-idb set but {idb} does not exist')
        print('reusing existing idb, skipping analysis...')
        t0 = time.time()
        rc = idapro.open_database(str(idb), run_auto_analysis=False)
    else:
        if idb.exists():
            print('removing existing idb...')
            idb.unlink()
        print('opening + auto-analysis...')
        t0 = time.time()
        rc = idapro.open_database(str(binary), run_auto_analysis=True)
    if rc != 0:
        sys.exit(f'open_database failed: rc={rc} {idapro.error_description(rc)}')
    t1 = time.time()
    print(f'auto-analysis done in {t1-t0:.1f}s')

    if not args.skip_decompile:
        import ida_hexrays
        if ida_hexrays.init_hexrays_plugin():
            import ida_pro
            fns = ida_pro.uint64vec_t()  # empty = all non-lib functions
            outfile = str(out.with_suffix('.decomp.c'))
            print(f'batch decompiling all functions -> {outfile} ...')
            # DECOMP_GXREFS_FORCE: update global xrefs from decompiled output
            flags = ida_hexrays.DECOMP_GXREFS_FORCE
            ok = ida_hexrays.decompile_many(outfile, fns, flags)
            t2 = time.time()
            print(f'decompile_many done in {t2-t1:.1f}s  ok={ok}')
        else:
            print('warning: hexrays not available, skipping decompilation')

    print('dumping xrefs...')
    t3 = time.time()
    xrefs = dump_xrefs()
    t4 = time.time()
    print(f'extracted {len(xrefs)} xrefs in {t4-t3:.1f}s')

    idapro.close_database()

    out.write_text(json.dumps(xrefs, separators=(',', ':')))
    print(f'wrote {out}  ({out.stat().st_size // 1024} KB)')


if __name__ == '__main__':
    main()
