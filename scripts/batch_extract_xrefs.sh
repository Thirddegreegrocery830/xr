#!/usr/bin/env bash
#
# Batch-extract IDA ground-truth xrefs for testcases that are missing them.
#
# Requirements:
#   - Python with `idapro` package (pip install idapro / uv pip install idapro)
#   - IDA Pro licence (idalib)
#   - Hex-Rays decompiler licence (for --skip-decompile to be optional)
#
# Usage:
#   ./scripts/batch_extract_xrefs.sh                  # process all missing
#   ./scripts/batch_extract_xrefs.sh --skip-decompile # faster, fewer xrefs
#   ./scripts/batch_extract_xrefs.sh testcases/foo.dll testcases/bar.exe  # specific files
#
set -euo pipefail
cd "$(dirname "$0")/.."

EXTRACT="scripts/ida_extract_xrefs.py"
EXTRA_FLAGS=()
TARGETS=()

for arg in "$@"; do
    case "$arg" in
        --skip-decompile|--reuse-idb)
            EXTRA_FLAGS+=("$arg")
            ;;
        *)
            TARGETS+=("$arg")
            ;;
    esac
done

# If no explicit targets, find all testcases missing ground truth.
if [ ${#TARGETS[@]} -eq 0 ]; then
    for f in testcases/*; do
        # Skip non-binary files
        [[ "$f" == *.xrefs.json ]] && continue
        [[ "$f" == *.decomp.c ]]  && continue
        [[ "$f" == *.i64 ]]       && continue

        gt="${f}.xrefs.json"
        if [ ! -f "$gt" ]; then
            TARGETS+=("$f")
        fi
    done
fi

if [ ${#TARGETS[@]} -eq 0 ]; then
    echo "All testcases already have ground truth. Nothing to do."
    exit 0
fi

echo "Will extract xrefs for ${#TARGETS[@]} binaries:"
for t in "${TARGETS[@]}"; do
    echo "  $t"
done
echo

PASS=0
FAIL=0

for binary in "${TARGETS[@]}"; do
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  $(basename "$binary")"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    if uv run --with idapro "$EXTRACT" "$binary" "${EXTRA_FLAGS[@]+"${EXTRA_FLAGS[@]}"}"; then
        PASS=$((PASS + 1))
    else
        echo "  *** FAILED: $binary ***"
        FAIL=$((FAIL + 1))
    fi
    echo
done

echo "Done: $PASS succeeded, $FAIL failed out of ${#TARGETS[@]} total."
[ "$FAIL" -eq 0 ]
