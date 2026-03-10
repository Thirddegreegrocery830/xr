# xr — fast binary cross-reference extractor

`xr` is a standalone Rust CLI tool for ultra-fast, parallel extraction of
cross-references from stripped binaries (ELF, Mach-O, PE).  It emits
`(from_va, to_va, kind)` tuples and targets IDA Pro ground-truth fidelity at
orders-of-magnitude faster speed.

## Quick Start

```sh
cargo build --release

# Analyse a binary at the recommended depth
./target/release/xr /path/to/binary --depth paired

# Output as JSON or CSV
./target/release/xr /path/to/binary --depth paired --format json
./target/release/xr /path/to/binary --depth paired --format csv

# Filter to a specific xref kind
./target/release/xr /path/to/binary --depth paired --kind call

# Show disasm context around each xref site (like grep -A/-B)
./target/release/xr /path/to/binary --depth paired -A 3 -B 2

# Evaluate against IDA ground truth
python3 scripts/eval.py /path/to/binary --depth 2
```

## Analysis Depths

| Flag | Name | What it does |
|------|------|-------------|
| `--depth scan` | ByteScan | Pointer-sized byte scan of data sections |
| `--depth linear` | Linear | Linear disasm — immediate targets + RIP-relative |
| `--depth paired` | Paired | ADRP+ADD/LDR pairs (ARM64) or register prop (x86-64) — **recommended** |

## Current F1 Scores (paired depth)

| Binary | Overall F1 |
|--------|------------|
| curl (ARM64 ELF) | 0.944 |
| curl (x86-64 ELF) | 0.961 |
| libharlem-shake.so (x86-64 PIE ELF) | 0.862 |
| libziggy.so (AArch64 PIE ELF) | 0.818 |
| hello (Mach-O AArch64) | 0.950 |
| hello (PE x86-64) | 0.847 |

Call xref precision is near-perfect (F1 ~1.000) on all tested binaries.

## Supported Formats

- ELF (x86-64, AArch64, x86, ARM32) — including PIE (ET_DYN)
- Single-arch Mach-O (x86-64, AArch64) — fat binaries require `lipo -extract` first
- PE / COFF (x86-64, x86, AArch64, ARM32)
- Apple dyld shared cache
- Raw flat binary (treated as single executable segment)

## Options

```
USAGE:
    xr [OPTIONS] <BINARY>

OPTIONS:
    -d, --depth <DEPTH>         Analysis depth: scan | linear | paired [default: paired]
    -j, --workers <N>           Worker threads; 0 = all CPUs [default: 0]
    -f, --format <FORMAT>       Output format: text | json | csv [default: text]
    -k, --kind <KIND>           Filter by kind: call | jump | data_read | data_write | data_ptr
        --base <VA>             Override PIE ELF load base (hex or decimal)
        --min-ref-va <VA>       Drop xrefs whose 'to' VA is below this value
        --start <VA>            Scan only 'from' addresses >= VA
        --end <VA>              Scan only 'from' addresses < VA
        --ref-start <VA>        Retain only xrefs with 'to' >= VA
        --ref-end <VA>          Retain only xrefs with 'to' < VA
        --limit <N>             Cap output at N xrefs (0 = unlimited)
    -A, --after-context <N>     Show N instructions after each xref site
    -B, --before-context <N>    Show N instructions before each xref site
```

## Architecture

See [STATUS.md](STATUS.md) for a detailed description of the architecture, design
decisions, empirical benchmark history, and known gaps.

## Benchmarking Against IDA Ground Truth

```sh
# Build the benchmark binary
cargo build --release --bin benchmark

# Run against a testcase (requires <binary>.xrefs.json ground-truth file)
./target/release/benchmark \
    --binary testcases/curl-amd64 \
    --ground-truth testcases/curl-amd64.xrefs.json \
    --depth paired

# Quick eval via Python (no rebuild needed)
python3 scripts/eval.py testcases/curl-aarch64 --depth 2
```

Ground-truth JSON files are generated with `scripts/ida_extract_xrefs_binary.py`
(requires IDA Pro with idalib).
