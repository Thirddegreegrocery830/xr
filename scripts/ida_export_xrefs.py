#!/usr/bin/env -S uv run --with idapro
"""
Export all non-flow xrefs from an existing IDB to JSON.
Usage: uv run --with idapro scripts/ida_export_xrefs.py <path/to/file.i64> [--out <json>]
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import idapro


def kind_str(xref_type: int, is_code: bool) -> str:
    if is_code:
        if xref_type in (16, 17):  # fl_CF, fl_CN
            return 'call'
        if xref_type in (18, 19):  # fl_JF, fl_JN
            return 'jump'
        return 'code'
    if xref_type == 3:
        return 'data_read'
    if xref_type == 2:
        return 'data_write'
    if xref_type == 1:
        return 'data_ptr'
    return 'data'


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('idb', help='Path to .i64 / .idb file')
    parser.add_argument('--out', help='Output JSON (default: <idb>.xrefs.json)')
    args = parser.parse_args()

    idb = Path(args.idb).resolve()
    if not idb.exists():
        sys.exit(f'error: {idb} not found')

    out = Path(args.out) if args.out else idb.with_suffix('.xrefs.json')

    print(f'idb    : {idb}')
    print(f'output : {out}')

    rc = idapro.open_database(str(idb), run_auto_analysis=False)
    if rc != 0:
        sys.exit(f'open_database failed rc={rc}')

    try:
        import ida_xref
        import idautils
        import idc

        min_ea = idc.get_inf_attr(idc.INF_MIN_EA)
        max_ea = idc.get_inf_attr(idc.INF_MAX_EA)
        print(f'range  : {min_ea:#x} .. {max_ea:#x}')

        xrefs: list[dict] = []
        t0 = time.time()
        ea = min_ea
        visited = 0
        while ea < max_ea:
            for xr in idautils.XrefsFrom(ea, ida_xref.XREF_NOFLOW):
                if xr.frm and xr.to:
                    xrefs.append({
                        'from': xr.frm,
                        'to': xr.to,
                        'kind': kind_str(xr.type, bool(xr.iscode)),
                    })
            visited += 1
            ea = idc.next_head(ea, max_ea)
            if visited % 100_000 == 0:
                print(f'  {visited} heads, {len(xrefs)} xrefs ...')

        t1 = time.time()
        print(f'extracted {len(xrefs)} xrefs in {t1-t0:.1f}s')

    finally:
        idapro.close_database()

    out.write_text(json.dumps(xrefs, separators=(',', ':')))
    print(f'wrote {out}  ({out.stat().st_size // 1024} KB)')


if __name__ == '__main__':
    main()
