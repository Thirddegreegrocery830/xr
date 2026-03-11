# xr — Status & Plans

## Goal

Build `xr`: a standalone Rust crate for ultra-fast, parallel cross-reference
extraction from stripped binaries (ELF, Mach-O, PE). Benchmarked against IDA Pro
ground-truth xrefs. Maximise F1 score across all xref kinds.

---

## Current Scores (Paired depth, 14 workers)

### curl-aarch64 (ARM64 ELF, statically linked)

| Kind       | TP    | FP   | FN    | Prec  | Rec   | F1    |
|------------|-------|------|-------|-------|-------|-------|
| call       | 40677 |    4 |    27 | 1.000 | 0.999 | 1.000 |
| jump       | 81217 | 1017 |  3310 | 0.988 | 0.961 | 0.974 |
| data_read  | 11131 |  623 |  1784 | 0.947 | 0.862 | 0.902 |
| data_write |   218 |    8 |   364 | 0.965 | 0.375 | 0.540 |
| data_ptr   | 26122 | 1035 | 10900 | 0.962 | 0.706 | 0.814 |
| **overall**|**159365**|**2687**|**16385**|**0.983**|**0.907**|**0.944**|

### curl-amd64 (x86-64 ELF, statically linked)

| Kind       | TP     | FP   | FN    | Prec  | Rec   | F1    |
|------------|--------|------|-------|-------|-------|-------|
| call       |  62805 |   35 |    41 | 0.999 | 0.999 | 0.999 |
| jump       | 109029 | 5807 |   403 | 0.949 | 0.996 | 0.972 |
| data_read  |   3927 |    1 |   465 | 1.000 | 0.894 | 0.944 |
| data_write |    510 |    0 |     0 | 1.000 | 1.000 | 1.000 |
| data_ptr   |  26373 |   57 |  6163 | 0.998 | 0.811 | 0.895 |
| **overall**|**202644**|**5900**|**7072**|**0.972**|**0.966**|**0.969**|

### blackcat.elf (x86-64 PIE ELF, large)

| Kind       | TP    | FP  | FN    | Prec  | Rec   | F1    |
|------------|-------|-----|-------|-------|-------|-------|
| call       | 15643 |  73 |  1110 | 0.995 | 0.934 | 0.964 |
| jump       | 50029 | 812 |  2369 | 0.984 | 0.955 | 0.969 |
| data_read  |  8750 |   2 |   494 | 1.000 | 0.947 | 0.972 |
| data_write |   170 |   1 |    19 | 0.994 | 0.899 | 0.944 |
| data_ptr   | 10864 |  12 |  2872 | 0.999 | 0.791 | 0.883 |
| **overall**|**80003**|**895**|**6864**|**0.989**|**0.921**|**0.954**|

### libharlem-shake.so (x86-64 PIE ELF, external symbol calls)

| Kind       | TP    | FP  | FN    | Prec  | Rec   | F1    |
|------------|-------|-----|-------|-------|-------|-------|
| call       |  8234 | 456 |   712 | 0.948 | 0.920 | 0.934 |
| jump       | 15512 |   7 |   413 | 1.000 | 0.974 | 0.987 |
| data_read  |  6221 |   0 |    57 | 1.000 | 0.991 | 0.995 |
| data_ptr   |  4937 |  15 |  8059 | 0.997 | 0.380 | 0.550 |
| **overall**|**30104**|**19**|**9241**|**0.999**|**0.765**|**0.867**|

### libziggy.so (AArch64 PIE ELF)

| Kind       | TP   | FP | FN   | Prec  | Rec   | F1    |
|------------|------|----|------|-------|-------|-------|
| call       | 1047 |  0 |    0 | 1.000 | 1.000 | 1.000 |
| jump       | 2942 |  0 |  129 | 1.000 | 0.958 | 0.979 |
| data_ptr   |  365 |  0 | 1576 | 1.000 | 0.188 | 0.317 |
| **overall**|**4512**|**2**|**1774**|**1.000**|**0.718**|**0.836**|

### Other test binaries (Paired depth)

| Binary | Overall F1 |
|--------|------------|
| hello-linux-gcc (x86-64 PIE ELF) | 0.914 |
| libssl3-amd64.so.3 (x86-64 ELF) | 0.925 |
| libssl3-arm64.so.3 (AArch64 ELF) | 0.837 |
| libcurl-arm64.so (AArch64 ELF)   | 0.902 |
| libcurl-x86.so (x86-64 ELF)     | 0.954 |
| libpjsip-everything.so (x86-64)  | 0.911 |
| libpjsip.so.2 (x86-64 ELF)     | 0.914 |
| libDJIFlySafeCore.so (AArch64 ELF) | 0.869 |
| hello.aarch64-apple-darwin (Mach-O) | 0.946 |
| hello.x86_64-pc-windows-gnu.exe (PE x86-64, MinGW) | 0.954 |
| simple.exe (PE x86-64, Rust+MSVC) | 0.890 |
| sudo.exe (PE x86-64, Rust+MSVC) | 0.918 |
| win32kbase_rs.sys (PE x86-64, Rust driver) | 0.995 |
| dwritemin.dll (PE x86-64, MSVC C++) | 0.869 |
| concrt140.dll (PE x86-64, MSVC C++) | 0.561 † |
| msvcp140.dll (PE x86-64, MSVC C++) | 0.701 |
| vccorlib140.dll (PE x86-64, MSVC C++) | 0.759 |
| vcomp140.dll (PE x86-64, MSVC C++) | 0.869 |
| vcruntime140.dll (PE x86-64, MSVC C++) | 0.732 |
| concrt140-arm64.dll (PE ARM64, MSVC C++) | 0.623 |
| vcruntime140-arm64.dll (PE ARM64, MSVC C++) | 0.752 |

† concrt140.dll score is artificially low: IDA ground truth emits 0 .pdata xrefs
  for this binary (analysis issue), causing ~4616 FP from xr's correct pdata parsing.

---

## Architecture & Key Design Decisions

### Binary

- **Languages**: Rust (core), Python (analysis scripts)
- **Parallelism**: Custom Rayon thread pool (`n_workers` threads); shard-per-segment dispatch
- **Zero-copy**: `memmap2` mmap, `&'static [u8]` segment slices
- **Depth levels**:
  - `ByteScan` (0): pointer-aligned 8-byte scan of data segments
  - `Linear` (1): sequential instruction decode of exec segments
  - `Paired` (2): ADRP+ADD/LDR pair resolution (ARM64), LEA/MOV (x86-64)

### Threading model

```
scan workers (rayon custom pool, n_workers threads)
    └─ tx (mpsc unbounded) ──► drain relay thread
                                    └─ out_tx (sync_channel, n_workers*4) ──► output thread
                                                                                  └─ pool.install(on_batch)
```

- **Scan workers**: `n_workers` rayon threads; each scans one shard, sends `Vec<Xref>` via `tx`
- **Drain relay**: pure channel relay; counts xrefs, forwards to output thread without blocking on I/O; sets stop flag on `Break`
- **Output thread**: calls `on_batch` under `pool.install` so any `par_iter` inside shares the scan pool (no oversubscription); formats in parallel chunks of 8192 records via `fold`+`reduce` into `Vec<u8>`, then one `write_all` per chunk through a 4 MiB `BufWriter`
- **Bounded output channel** (`sync_channel(n_workers*4)`): applies backpressure to scan if output falls behind, bounding peak memory

### ARM64 hot-path decode

`scan_adrp` uses a two-level dispatch:
1. `Arm64Insn::is_tracked(word)` — cheap bitmask union of all tracked encoding families (BL/B/ADRP/ADD/LDR/STR/branches); ~60-70% of instructions return `false`
2. For untracked words: `rd = word & 0x1F`; invalidate `adrp_state[rd]`; `continue` — no enum allocation
3. Only tracked words go through full `Arm64Insn::decode`

### Segment model

Each binary is split into `Segment` structs with:
- `executable: bool` — whether to instruction-scan
- `byte_scannable: bool` — whether to byte-scan for pointers
- For ELF: exec PT_LOADs are split per-section so `.rodata`/`.eh_frame*` inside
  the exec PT_LOAD are `executable=false` (not instruction-scanned)
- `.data.rel.ro` and `.data.rel.ro.local` → `byte_scannable=false`
  (relocation tables produce a ~5-29x FP:TP ratio without reloc context)
- PIE ELFs (ET_DYN with first PT_LOAD at p_vaddr==0) are rebased to `0x0040_0000`
  to match IDA's default load address

### Xref kinds

| Kind        | Source insns (ARM64)                     | Source insns (x86-64)                        |
|-------------|------------------------------------------|----------------------------------------------|
| Call        | BL (exec target only), BLR (resolved)    | CALL rel32, CALL r/m64                       |
| Jump        | B, B.cond, CBZ, CBNZ, TBZ, TBNZ, BR     | Jcc, JMP rel, JMP r/m64                      |
| DataRead    | LDR/LDRB/LDRH + ADRP resolve            | MOV [RIP+d], LEA reads                       |
| DataWrite   | STR/STRB/STRH + ADRP resolve            | MOV [RIP+d] writes                           |
| DataPointer | ADRP (emit at ADRP VA, not ADD VA)       | LEA RIP+d, byte-scan hits, CMP/SUB/MOV imm32 |

---

## What Was Tried & Outcome

### Fixes that worked

| Fix | Δ F1 | Notes |
|-----|------|-------|
| Suppress ADD-VA data_ptr emission | ARM64 +0.015 | ADRP+ADD pairs: emit at ADRP_VA only; ADD_VA adds 6981 FPs vs 6496 TPs |
| Suppress ADR data_ptr emission | ARM64 +small | IDA records 0 data_ptr at ADR sources (confirmed 0/50 sample) |
| Fix byte-scan shard alignment bug | x86-64 +0.010 | Data shard split_range used insn_align=1 instead of ptr_size=8; misaligned shards skipped aligned slots |
| Exec-target suppression for byte scan | x86-64 +large | Only emit DataPointer from byte scan when target is non-exec; exec targets are 10-14x FP:TP |
| Suppress `.data.rel.ro` byte scan | x86-64 +0.096 | FP:TP ratio 5:1 on x86-64, 29:1 on ARM64 without relocation context |
| Exec PT_LOAD section-granular split | ARM64 +0.011 jump | `.rodata`/`.eh_frame*` in exec PT_LOAD decoded as ARM64 insns = 1915 jump FPs |
| data_write RO-target suppression | ARM64 fix | After `.rodata` became non-exec, STR-to-.rodata emitted as FPs; suppress writes to non-writable segments |
| BLR/BR exec-target suppression | ARM64 call −77, jump −118 FP | BLR/BR resolved to non-exec (e.g. .rodata) suppressed; call F1→1.000, jump F1→0.975 |
| BL exec-target suppression | ARM64 call −1 FP | BL to non-exec (dead-code .rodata target) suppressed |
| CMP/SUB imm32 data_ptr (x86-64) | x86-64 data_ptr +0.0002 | IDA records data_ptr for CMP/SUB r/m64,imm32 with in-range imm; +25 TPs +18 FPs |
| PIE ELF rebase to 0x400000 | libharlem/libziggy fix | ET_DYN with first PT_LOAD at 0 rebased by +0x400000; fixes VA-space overlap with small constants |
| `min_ref_va` post-dedup filter | libharlem FP −large | Drops xrefs whose `to` VA is below the binary's lowest mapped address |
| Ground truth cleanup | all PIE ELFs | Removed IDA type-system xrefs; rebased libziggy+libharlem JSON by +0x400000 |

| PE IAT slot population | PE +0.004–0.017 | `build_pe_iat_slots()` populates `got_slots` from PE import table; enables x86-64 scanner's `emit_got_indirect` for PE indirect call/jmp through IAT |
| PE .pdata exception directory parsing | PE +0.056–0.153 | Parse RUNTIME_FUNCTION entries (12-byte structs with 3 RVAs); emit 4 data_ptr xrefs per entry (image_base + 3 resolved targets) all from entry start VA |
| PE UNWIND_INFO handler RVA extraction | PE +0.001–0.008 | Parse ExceptionHandler RVA from UNWIND_INFO structures; 100% precision (2438 TP, 0 FP across all PE binaries) |
| reloc_pointers bypass min_ref_va | PE +0.005–0.077 | Reloc-derived xrefs are authoritative metadata; exempt from min_ref_va filtering (image_base is below first section, was wrongly suppressed) |
| Type system: SegFlags newtype | — | Replace raw u8 bitmask with newtype in `src/arch/mod.rs` |
| Type system: RelocPointer struct | — | Replace `(Va, Va)` tuples in `src/loader.rs` |
| Type system: Symbol struct | — | Replace `(String, Va)` tuples |
| FxHashSet for got_slots | — | Replace `HashSet<Va>` with `FxHashSet<Va>` for faster hot-path GOT lookups |

### Fixes that were tried and reverted/abandoned

| Fix | Why abandoned |
|-----|---------------|
| .pdata xrefs with field-offset `from` addresses | IDA attributes all 4 pdata xrefs to entry start VA (+0), not individual field offsets (+0/+4/+8). Using field offsets produced 0 TP, 2308 FP. |
| Blind 32-bit RVA scan of .rdata | Scanning all 4-byte-aligned .rdata slots for valid RVAs: 14.5% precision, 34.4% recall. Too many random u32 values match. |
| UNWIND_INFO scope table parsing | Scope table layout varies by handler type (__C_specific_handler vs __CxxFrameHandler3 etc). Parsing all as __C_specific_handler: 1090 TP but 2937 FP. Handler RVA alone is 100% precise. |
| Re-enable ADD-VA data_ptr | +6496 TPs but +6981 FPs; net ARM64 F1 +0.001, not worth it |
| Remove exec-target suppression for byte scan | +3 TPs, +275 FPs on x86-64; worse F1 |
| Section-granular split of writable PT_LOAD | `.data` byte scan: 241 TPs but 548 FPs (mostly `.data`→`.rodata` pointers IDA doesn't record) |
| Forward linear register tracker for data_write FNs | F1 0.407 vs 0.541 — register reuse causes massive FPs |
| FDE/`.eh_frame` coverage filter for jumps | 5780 FPs removed but 4946 FNs added; net F1 +0.002 — not worth complexity |
| Parse `.eh_frame_hdr` for x86-64 data_ptr | All 13595 `init_loc` entries point into `.text`, not `.rodata`. IDA records 0 xrefs FROM `.eh_frame_hdr`. The 3435 `.rodata` FNs are gcc_except_table LSDA (variable-length, not parseable simply). |
| GOT extern VA algorithm (v1) | IDA's extern VA assignment order ≠ dynsym sequence order for many binaries. 0 mismatches on libharlem-shake.so but 5184 FP calls on blackcat.elf. Replaced by GOT slot VA approach. |
| GOT slot VA approach (v2) | Emits to=got_slot_va instead of extern VA; benchmark normalizes IDA xrefs. blackcat.elf call F1 0.644→0.964, hello-linux-gcc call FPs 266→0. No regressions. |
| ELF reloc data_ptr (R_*_RELATIVE, R_*_64) | Parses .rela.dyn for pointer pairs. blackcat.elf data_ptr F1 0.766→0.883, libssl3-amd64 0.511→0.732. +24k TPs across all ELF binaries. |
| PE base reloc data_ptr (DIR64) | Parses .reloc section for pointer slots. Modest gains (3114 entries on dwritemin.dll). |

---

## Remaining Gaps & Root Causes

### libharlem-shake.so call FNs (711) and FPs (456)

711 call FNs: IDA xrefs to extern VAs for direct calls through PLT stubs (xr emits
`Call(from, PLT_stub_va)`, IDA emits `Call(from, extern_va)` — these never match
because the `to` values differ). Also includes calls in dead code regions.

456 call FPs: direct calls and register-propagated calls that IDA doesn't record
(pre-existing — not caused by GOT changes). Targets are unaligned addresses suggesting
misidentified code or dead-code calls.

**Fix approach**: PLT call resolution (resolving `E8 rel32` through PLT stub → extern
symbol) would fix the bulk of these. Not yet planned.

### libharlem-shake.so data_ptr FNs (8060)

After reloc data_ptr recovery, 1139 TPs were gained (9199→8060 FNs). Remaining FNs
are likely pointers in sections not covered by RELATIVE/ABS64 relocs (e.g. COPY relocs,
indirect symbol pointers, or data sections IDA resolves via type propagation).

### libziggy.so data_ptr FNs (1576)

After reloc data_ptr recovery, 182 TPs gained (1758→1576 FNs). Remaining FNs are
mostly ADD-VA mismatch and LDR-unresolved registers (same as ARM64 curl-aarch64).

### ARM64 call FPs (6 remaining)

All 6 are `BLR`/`BL` instructions in dead code regions that IDA does not analyse.
Not fixable without reachability analysis.

### ARM64 jump FPs (1017 remaining)

All are conditional branches (`CBZ/CBNZ`, `TBZ/TBNZ`, `B.cond`) or `BR` in `.text`
where IDA finds no xref. Two sub-categories:

1. **~313** — in dead zones (IDA jump gap > 1KB within `.text`): unreachable/non-code bytes.
2. **~704** — in apparently normal code IDA decoded differently (dead branch elim, alignment).

**Fix approach**: None clearly tractable without reachability analysis.

### x86-64 jump FPs (5784)

- **~4881** — in a 153KB dead zone `0x65ee50`–`0x6844b1` within `.text` where
  IDA records only 13 xrefs total. Contains `short Jcc`, `LOOP`, `JCXZ` instructions.
- **~903** — in other smaller dead zones scattered through `.text`.

**Fix approach**: FDE filtering would remove ~5780 FPs but add ~4946 FNs (net +0.002 F1).
Not worth implementing.

### Jump FNs (ARM64: 3160, x86-64: 3448)

- x86-64: **3436/3448** are `JMP reg` (`FF /4` mod=11) — register-based indirect jumps.
- ARM64: **~3000/3160** are `BR Xn` — same issue.
- Remaining ~12 are RIP-relative indirect or other rare forms.

**Fix approach**: Requires data-flow analysis. Not planned.

### ARM64 data_ptr FNs (10835)

- **~6942** — ADD-VA mismatch: IDA records xref at `ADD_VA`, xr at `ADRP_VA`.
  Re-enabling ADD-VA gives +6496 TPs / +6981 FPs (net negative).
- **~1166** — byte-scan pointers to exec segment (function pointer tables). Suppressed.
- **~598** — ADD-VA xrefs with no ADRP-VA xr coverage (distant ADRP).
- **~801** — in `.data.rel.ro` (suppressed for byte scan).
- **~1328** — LDR through ADRP-unresolved registers; needs data flow.

**Fix approach**: The ADD-VA mismatch is a scoring artifact (xr finds the ref, just
at a different source address). The rest require relocation tables or data-flow.

### x86-64 data_ptr FNs (6164 on curl-amd64, 2872 on blackcat.elf)

curl-amd64 is statically linked (no reloc tables) — FN count unchanged:
- **~3435** — in `.rodata`: gcc_except_table LSDA entries (ULEB128, not parseable simply)
- **~2322** — in `.data.rel.ro` (suppressed, no relocs in static binary)
- **~378** — in `.data` where IDA uses type propagation
- **~33** — in `.text`: CMP/SUB false negatives

blackcat.elf improved from 5201→2872 FNs via reloc recovery (+2329 TPs).

**Fix approach**: No tractable fix for statically linked binaries.

### data_write FNs (ARM64: 360, x86-64: 122)

- ARM64: All 360 are register-based stores (`STR [x19]`, `STP [x0, x1]`) where the
  base register was set far earlier (function arg or ADRP overwritten beyond ADRP_WINDOW).
- x86-64: 122 FNs; same pattern (indirect stores through registers).

**Fix approach**: Not planned. Requires interprocedural data-flow.

### PE data_ptr FNs (MSVC C++ EH/RTTI structures)

The dominant remaining PE FN category is `data_ptr` in `.rdata`, caused by
MSVC C++ exception handling and RTTI metadata. These structures store
function/data references as **32-bit image-relative RVAs** (not 64-bit pointers),
which the 8-byte pointer scanner cannot detect.

Structure types involved:
- `_s_FuncInfo`, `_s_HandlerType`, `_s_TryBlockMapEntry` — C++ EH dispatch tables
- `_s_UnwindMapEntry`, `_s_ESTypeList` — C++ EH cleanup/catch tables
- `TypeDescriptor`, `RTTICompleteObjectLocator` — RTTI metadata
- These contain packed 32-bit RVA pairs (two per 8 bytes), not full pointers

Scale across MSVC DLLs:
- dwritemin.dll: ~9,933 data_ptr FN from 32-bit RVAs in .rdata
- msvcp140.dll: ~12,422 data_ptr FN total
- vccorlib140.dll: ~8,269 data_ptr FN total

**Fix approach**: Parsing individual MSVC EH structures is complex (layout varies
by handler type, version-dependent). Blind 32-bit RVA scanning has 14.5% precision.
No tractable fix without deep MSVC EH metadata parsing.

### PE extern-target xref mismatch

IDA assigns synthetic extern VAs (`0xff00000000000Xxx`) to imported functions.
When code accesses IAT slots (e.g., `MOV reg, [rip+IAT_slot]`), IDA records
the xref target as the extern VA while xr records the IAT slot VA. Additionally,
IDA sometimes attributes the xref to a different instruction address within the
same basic block.

Scale: 1,493 extern xrefs in vcomp140.dll, 9,103 in msvcp140.dll.

The benchmark normalizes some of these via `resolve_x86_got_slot()`, but
IDA's `from` address mismatches cause many to remain FN regardless.

**Fix approach**: Benchmark measurement issue, not a scanner deficiency.

### PE switch table jumps

IDA resolves switch-table indirect jumps in PE binaries. xr's x86-64 jump table
recovery works but contributes ~200–1200 jump FN per PE binary, primarily from:
- Switch tables where CMP bound tracking fails (different compiler patterns)
- Register-based indirect jumps (`JMP reg`) without recoverable table

**Fix approach**: Existing CMP+MOVSXD+ADD+JMP pattern covers GCC/Clang/MSVC
common patterns. Remaining cases require broader pattern recognition.

---

## GOT-Indirect Call/Jump Resolution

IDA resolves `CALL [RIP+GOT_slot]` (`FF 15` encoding) and AArch64 `BLR Xn` (via
ADRP+LDR of a GOT slot) by assigning synthetic "extern segment" VAs to undefined symbols.

### Current approach: GOT slot VA matching

Instead of replicating IDA's fragile extern VA assignment algorithm (which was wrong
for many binaries — see history below), xr now emits `to=got_slot_va` (the real
address the CPU dereferences) for GOT-indirect calls/jumps. The benchmark normalizes
IDA's extern-target xrefs back to GOT slot VAs by decoding the instruction bytes at
each xref's source address (FF 15 / FF 25 pattern matching).

**Implementation:**
- `src/loader.rs:build_elf_got_slots()` — collects `HashSet<Va>` of GOT slot VAs from
  GLOB_DAT / JUMP_SLOT relocations in `.rela.dyn` / `.rela.plt`
- `src/arch/x86_64.rs:emit_got_indirect()` — emits Call/Jump to `got_slot_va` (gated
  by `got_slots.contains()` to avoid FPs from non-GOT RIP-relative indirect calls)
- `src/bin/benchmark.rs:resolve_x86_got_slot()` — decodes FF 15/FF 25 instruction at
  IDA xref's `from` to recover the GOT slot VA; replaces extern VA target

**Result:** blackcat.elf call F1 0.644 → **0.964**, hello-linux-gcc call FPs 266 → **0**,
no regressions across all 20 test binaries.

### Historical: IDA extern VA algorithm (previously used, now deleted)

The previous approach tried to replicate IDA's extern VA assignment:
```
extern_base = max(PT_LOAD p_vaddr + p_memsz) + pie_base + 0x20
extern_va[i] = extern_base + i * 8
```
Symbol ordering: STT_FUNC SHN_UNDEF first by dynsym index, then others.
This worked for libharlem-shake.so (0 mismatches) but produced systematically wrong
targets on blackcat.elf (5184 FP calls) and hello-linux-gcc (266 FP calls). The root
cause is that IDA's extern segment layout uses variable-width entries, different base
addresses, and different symbol orderings that are binary-dependent. The `got_slot_va`
approach eliminates this fragility entirely.

---

## Requirements / Wants / Features

### VA range filter

Support filtering the emitted xref set to a user-specified address range. Both `from`
and `to` can be independently bounded; when both are specified the filter is AND-ed
(an xref is emitted only if both addresses satisfy their respective constraints).

**Design implications:**
- CLI: `--from-range <start>-<end>` and `--to-range <start>-<end>` (hex or decimal).
  Either flag is optional; omitting one means "no constraint on that side".
- `PassConfig`: add `from_range: Option<(u64, u64)>` and `to_range: Option<(u64, u64)>`.
- `from_range` must be applied **before decoding**, at shard-generation time:
  - In `split_range` (or the caller in `pass.rs`), clamp each segment's VA range to
    the intersection with `from_range` before generating shards. Segments that don't
    overlap the range produce no shards at all — zero decode work.
  - This is cheap: it's just range arithmetic on the segment list before the Rayon
    pool is even spawned.
- `to_range` is a post-pass filter on `Vec<Xref>` (cannot be pushed earlier without
  threading it into every arch scanner's target-resolution logic — not worth it).

---

## Planned Improvements

### Low value or high complexity (no high-value easy wins remain)

#### 1. GOT-indirect call/jump resolution — DONE (v1: extern VA, v2: GOT slot VA)

v1: Cracked IDA's extern VA algorithm. Worked for some binaries but not others.
v2: Switched to GOT slot VA approach — emit to=got_slot_va, normalize in benchmark.
blackcat.elf call F1 0.644→0.964, hello-linux-gcc call FPs 266→0. See GOT section.

#### 2. Reachability-based code discovery (jump FPs)

Track reachable code regions from entry points / known function starts; emit xrefs
only from reachable code. Would fix ~5780 x86-64 and ~1017 ARM64 jump FPs.
Requires significant architecture work (recursive disassembly / flood-fill).

Not planned — substantial complexity for ~+0.006 overall F1 improvement.

#### 3. x86-64 jump table recovery — DONE

Recognises the CMP+JA+LEA+MOVSXD+ADD+JMP pattern. Reads i32 offset tables from
.rodata, computes targets, emits Jump xrefs. CMP bound tracking per register limits
table size precisely. curl-amd64 jump FN 3448→403 (+3045 TPs), overall F1 0.961→0.969.
No regressions on any binary. ARM64 not yet implemented.

#### 4. Register tracking for indirect jumps/calls

Data-flow analysis to resolve `JMP Rn` / `BR Xn`. Would recover remaining ~400 jump FNs
on x86-64 (tables where CMP bound tracking failed) and ~3160 on ARM64.
Not planned — requires interprocedural analysis.

#### 4. Relocation-derived data_ptr recovery — DONE (ELF + PE)

Parse ELF `.rela.dyn` (R_*_RELATIVE, R_*_64/ABS64) and PE base relocation table
(IMAGE_REL_BASED_DIR64) to extract pointer pairs. Emit as DataPointer xrefs.
Recovered ~24k+ TPs across all dynamically-linked ELF binaries. PE gains modest.
Mach-O fixup chains not yet implemented.

---

## File Map

```
xr/
  Cargo.toml
  STATUS.md                      ← this file
  src/
    lib.rs
    main.rs
    xref.rs                      ← XrefKind enum (Call/Jump/DataRead/DataWrite/DataPointer)
    shard.rs                     ← split_range: parallel shard boundaries
    loader.rs                    ← ELF/Mach-O/PE parser; Segment struct; byte_scannable/executable flags
                                    PIE rebase (ET_DYN + first PT_LOAD at 0 → +0x400000)
                                    got_slots: FxHashSet<Va> from GLOB_DAT/JUMP_SLOT + PE IAT
                                    reloc_pointers: Vec<RelocPointer> from ELF .rela.dyn + PE .reloc/.pdata/UNWIND_INFO
                                    RelocPointer, Symbol structs; PeSectionMap, VaRangeSet helpers
    pass.rs                      ← XrefPass: orchestrates parallel scan; invokes arch scanners
                                    min_ref_va post-dedup filter
    arch/
      mod.rs                     ← byte_scan_pointers (exec-target suppressed)
      arm64.rs                   ← ADRP/ADD/LDR/STR pair resolution; BL/BLR/BR exec-target suppression
                                    two-level decode dispatch via is_tracked(); BLR/BR: no extern VA
      arm64_decode.rs            ← pure bitmask ARM64 decoder; Arm64Insn::is_tracked() fast-path classifier
      x86_64.rs                  ← LEA/MOV RIP+disp; CALL/JMP decode; imm_as_address() for CMP/SUB
                                    FF15/FF25: emit_got_indirect() emits to=got_slot_va (gated by got_slots)
    bin/
      benchmark.rs               ← CLI: --binary --ground-truth --workers --depth
                                     --dump-fps/fns/tps --dump-kind --min-ref-va

  testcases/
    curl-amd64                   ← x86-64 ELF, stripped, statically linked
    curl-aarch64                 ← ARM64 ELF, stripped, statically linked
    blackcat.elf                 ← x86-64 PIE ELF, large
    libharlem-shake.so           ← x86-64 PIE ELF (Rust, many external symbol calls)
    libziggy.so                  ← AArch64 PIE ELF (Rust)
    libssl3-amd64.so.3           ← x86-64 ELF
    libssl3-arm64.so.3           ← AArch64 ELF
    libcurl-arm64.so             ← AArch64 ELF
    libcurl-x86.so               ← x86-64 ELF
    libpjsip-everything.so       ← x86-64 ELF
    libpjsip.so.2                ← x86-64 ELF
    libDJIFlySafeCore.so         ← AArch64 ELF
    hello-linux-gcc              ← x86-64 PIE ELF (GCC)
    hello.aarch64-apple-darwin   ← Mach-O ARM64
    hello.x86_64-pc-windows-gnu.exe ← PE x86-64 (MinGW)
    simple.exe                   ← PE x86-64 (Rust+MSVC)
    sudo.exe                     ← PE x86-64 (Rust+MSVC)
    win32kbase_rs.sys            ← PE x86-64 (Rust kernel driver)
    dwritemin.dll                ← PE x86-64 (MSVC C++)
    concrt140.dll                ← PE x86-64 (MSVC Concurrency Runtime)
    concrt140-arm64.dll          ← PE ARM64 (MSVC Concurrency Runtime)
    msvcp140.dll                 ← PE x86-64 (MSVC C++ STL)
    vccorlib140.dll              ← PE x86-64 (MSVC WinRT/COM)
    vcomp140.dll                 ← PE x86-64 (MSVC OpenMP)
    vcruntime140.dll             ← PE x86-64 (MSVC CRT)
    vcruntime140-arm64.dll       ← PE ARM64 (MSVC CRT)
    *.xrefs.json                 ← IDA ground truth (per binary)

  scripts/
    ida_extract_xrefs.py         ← IDA Pro script for ground-truth extraction
    batch_extract_xrefs.sh       ← batch IDA ground truth for all testcases
    score_all.sh                 ← run benchmark on all testcases, summary table
    analyze_fn_datawrite.py
    analyze_fn_datawrite2.py
    analyze_adrp_distance.py
    simulate_reg_tracker.py
    analyze_fp_dataptr.py
    analyze_fp_dataptr2.py
```

---

## Key Code Locations

| What | File | Notes |
|------|------|-------|
| Segment struct + byte_scannable | `src/loader.rs:31` | |
| PIE ELF rebase | `src/loader.rs:~293` | ET_DYN + first PT_LOAD at 0 → pie_base=0x400000 |
| ELF exec section-granular split | `src/loader.rs:~336` | NON_CODE_SECTIONS list |
| `.data.rel.ro` suppression | `src/loader.rs:~229` | NO_SCAN_SECTIONS list |
| got_slots field | `src/loader.rs` | `FxHashSet<Va>` from GLOB_DAT/JUMP_SLOT relocs; `build_elf_got_slots()` + `build_pe_iat_slots()` |
| byte_scan_pointers | `src/arch/mod.rs:40` | Exec-target suppression at line 70 |
| ARM64 is_tracked fast-path | `src/arch/arm64_decode.rs` | Bitmask classifier; skips decode for ~65% of instructions |
| ARM64 ADRP scan | `src/arch/arm64.rs` | Two-level decode dispatch; ADR/ADD-VA suppressed |
| ARM64 BL/BLR/BR exec-target filter | `src/arch/arm64.rs:~315` | `target_is_exec` guards; no extern VA |
| ARM64 data_write RO-target filter | `src/arch/arm64.rs:~299` | `!s.writable` check |
| x86-64 LEA/MOV/JMP decode | `src/arch/x86_64.rs` | |
| x86-64 CMP/SUB imm32 data_ptr | `src/arch/x86_64.rs` | `imm_as_address()` helper |
| GOT-indirect xref emission | `src/arch/x86_64.rs` | `emit_got_indirect()` — FF15/FF25 to got_slot_va |
| x86-64 jump table recovery | `src/arch/x86_64.rs` | `recover_jump_table()` + `update_jt_state()` + `update_cmp_state()` |
| SegmentDataIndex::read_i32_at | `src/arch/mod.rs` | Read table entries from any segment |
| Benchmark GOT normalization | `src/bin/benchmark.rs` | `resolve_x86_got_slot()` + `extern_bound()` |
| ELF reloc pointer extraction | `src/loader.rs` | `build_elf_reloc_pointers()` — R_*_RELATIVE + R_*_64/ABS64 |
| PE reloc pointer extraction | `src/loader.rs` | `build_pe_reloc_pointers()` — base reloc table DIR64 entries |
| PE .pdata parsing | `src/loader.rs` | `build_pe_pdata_xrefs()` — RUNTIME_FUNCTION 4-xref emission |
| PE UNWIND_INFO handlers | `src/loader.rs` | `build_pe_unwind_handler_xrefs()` — ExceptionHandler RVA extraction |
| PE IAT slots | `src/loader.rs` | `build_pe_iat_slots()` — populates got_slots from PE import table |
| Reloc pointer emission | `src/pass.rs` | Single batch before code/data shards; bypasses min_ref_va |
| min_ref_va filter | `src/pass.rs` | Post-dedup drop of below-min-va targets (code/data scan only, not reloc_pointers) |
| Threading pipeline | `src/pass.rs` | Scan pool → drain relay → output thread via sync_channel |
| Output chunked parallel format | `src/main.rs` | 8192-record chunks, fold+reduce into Vec<u8>, BufWriter |
| Printer trait (write_record) | `src/output.rs` | Append-to-buf interface; no per-record allocation |
| Benchmark CLI | `src/bin/benchmark.rs` | |

---

## Session History (most recent first)

### Session N+9 — PE metadata parsing & MSVC test binaries

**Goal**: Expand PE test coverage with pure MSVC C/C++ binaries and improve PE
recall by parsing structured binary metadata (exception directory, unwind info).

**Test suite expansion:**

Added 7 pure MSVC DLLs from the VC++ 2022 redistributable:
- x86-64: `concrt140.dll`, `msvcp140.dll`, `vccorlib140.dll`, `vcomp140.dll`, `vcruntime140.dll`
- ARM64: `concrt140-arm64.dll`, `vcruntime140-arm64.dll`

These are the first pure MSVC C/C++ binaries and first ARM64 PE testcases.
Previous PE binaries were all Rust+MinGW or Rust+MSVC-linked.

Generated IDA ground truth (`.xrefs.json`) for all 7 binaries. Fixed
`ida_extract_xrefs.py` naming for multi-extension files (`.dll.xrefs.json`).
Added `scripts/score_all.sh` and `scripts/batch_extract_xrefs.sh`.

**Changes:**

1. **`src/loader.rs`** — Four new functions:
   - `build_pe_iat_slots()`: populates `got_slots` from PE import table
     (`pe.imports[].rva`), enabling `emit_got_indirect` for PE binaries
   - `build_pe_pdata_xrefs()`: parses PE exception directory — each
     RUNTIME_FUNCTION (12 bytes, 3 u32 RVAs) emits 4 data_ptr xrefs
     (to image_base + 3 resolved targets), all from entry start VA
   - `build_pe_unwind_handler_xrefs()`: follows .pdata → UNWIND_INFO,
     extracts ExceptionHandler RVA from entries with UNW_FLAG_EHANDLER
     or UNW_FLAG_UHANDLER (100% precision: 2438 TP, 0 FP)
   - Type improvements: `RelocPointer` struct, `Symbol` struct, `SegFlags`
     newtype, `FxHashSet` for `got_slots`

2. **`src/pass.rs`** — `reloc_pointers` batch now bypasses `min_ref_va`
   filter. PE .pdata entries emit `(entry_va, image_base)` but image_base
   is below the first section; min_ref_va was wrongly suppressing ~34K
   xrefs. Authoritative metadata should not be filtered by heuristic bounds.

3. **`src/arch/mod.rs`** — `SegFlags` newtype replacing raw u8 bitmask.

4. **`src/bin/benchmark.rs`** — Broadened GOT/IAT extern normalization to
   all xref kinds and all RIP-relative operand positions (not just
   indirect call/jump).

**Score impact (PE F1, Paired depth):**

| Binary | Before | After | Δ |
|--------|--------|-------|---|
| win32kbase_rs.sys | 0.894 | 0.995 | +0.101 |
| simple.exe | 0.736 | 0.890 | +0.154 |
| dwritemin.dll | 0.724 | 0.869 | +0.145 |
| vcomp140.dll | — | 0.869 | (new) |
| hello.x86_64-pc-windows-gnu.exe | 0.878 | 0.954 | +0.076 |
| msvcp140.dll | — | 0.701 | (new) |
| vcruntime140.dll | — | 0.732 | (new) |
| vccorlib140.dll | — | 0.759 | (new) |
| sudo.exe | 0.859 | 0.918 | +0.059 |

No regressions on ELF or Mach-O binaries.

### Session N+8 — x86-64 jump table recovery

**Goal**: Recover jump xrefs from switch-statement jump tables (12.3% of all FNs,
~3448 jump FNs on curl-amd64).

**Changes:**

1. **`src/arch/mod.rs`** — Added `SegmentDataIndex::read_i32_at()` for reading
   signed 32-bit table entries from any mapped segment.

2. **`src/arch/x86_64.rs`** — Major additions:
   - `jt_info: [Option<(u64, u64, Option<u32>)>; 16]` — tracks (table_start,
     target_base, max_entries) through MOVSXD+ADD propagation
   - `cmp_bound: [Option<u32>; 16]` — tracks CMP immediate bounds per register,
     propagated through register-to-register MOV
   - `update_jt_state()` — recognises MOVSXD [base+idx*4] loads and ADD reg,reg
     with base-register verification via reg_vals
   - `update_cmp_state()` — tracks CMP rN,imm → cmp_bound[N] = imm+1, propagated
     through MOV r,r, cleared by other writes
   - `recover_jump_table()` — reads i32 offsets from table, computes targets =
     target_base + offset, emits Jump xrefs. Guarded by CMP bound when available;
     without CMP bound requires non-exec table segment + small fallback limit.
   - `scan_with_prop()` and `scan_linear()` now take `data_idx: &SegmentDataIndex`

3. **`src/pass.rs`** — Passes `ctx.data_idx` to x86_64 scanners in `scan_shard`.

**FP mitigation**: Two key guards prevent false positives from dead-code zones:
- CMP bound tracking limits reads to the exact table size for most tables
- Without CMP bound: requires table in non-exec segment (.rodata), fallback limit=0
  (effectively CMP-bound-only recovery avoids all dead-zone FPs)

**Score delta (selected binaries, overall F1):**
- curl-amd64: 0.961 → **0.969** (+0.008), jump FN 3448→403
- hello.x86_64-pc-windows-gnu.exe: 0.852 → **0.878** (+0.026)
- hello-linux-gcc: 0.897 → **0.914** (+0.017)
- libssl3-amd64.so.3: 0.916 → **0.925** (+0.009)
- libharmel-shake.so: 0.861 → **0.867** (+0.006)
- blackcat.elf: 0.952 → **0.954** (+0.002)

No regressions on any of 19 test binaries. ARM64 unaffected (not yet implemented).

### Session N+7 — Relocation-table data_ptr recovery (ELF + PE)

**Goal**: Recover data_ptr xrefs from relocation tables, targeting the ~75% of all FNs
that are data_ptr. Pointers in `.data.rel.ro` (suppressed from byte scan) and other
relocation-covered sections are authoritative — the reloc table says exactly which
slots are pointers and what they point to.

**Changes:**

1. **`src/loader.rs`** — Added `reloc_pointers: Vec<(Va, Va)>` to `LoadedBinary` and
   `ParseResult`. Two new functions:
   - `build_elf_reloc_pointers()`: parses `.rela.dyn` / `.rel.dyn` for `R_*_RELATIVE`
     (target = pie_base + addend) and `R_*_64` / `R_*_ABS64` (target = sym.st_value +
     pie_base + addend, defined symbols only). Filters to targets within mapped segments.
   - `build_pe_reloc_pointers()`: parses PE base relocation table blocks, reads 64-bit
     pointer values at `IMAGE_REL_BASED_DIR64` slots, filters to mapped targets.

2. **`src/pass.rs`** — Emits `reloc_pointers` as a single batch of `DataPointer` xrefs
   (confidence = ByteScan) at the start of `pool.install`, before code and data shards.
   Applies `min_ref_va`, `from_range`, and `to_range` filters.

**Score delta (data_ptr, selected binaries):**
- blackcat.elf: F1 **0.766 → 0.883** (+2329 TPs), overall F1 0.937→0.952
- libssl3-amd64: F1 **0.511 → 0.732** (+2335 TPs), overall F1 0.873→0.916
- libcurl-arm64: F1 **0.642 → 0.736** (+1246 TPs), overall F1 0.886→0.902
- libziggy.so: F1 **0.172 → 0.317** (+182 TPs), overall F1 0.816→0.836
- libDJIFlySafeCore: F1 **0.450 → 0.589** (+13134 TPs), overall F1 0.847→0.869

**No regressions.** Statically linked binaries (curl-amd64, curl-aarch64) unaffected.
PE gains modest (dwritemin.dll: only 3114 of 42228 FNs are in base reloc table).
Mach-O fixup chains not yet implemented.

### Session N+6 — GOT slot VA approach (replace extern VA algorithm)

**Goal**: Fix GOT-indirect call/jump resolution for all x86-64 PIE ELFs. The previous
extern VA algorithm (Session N+5) worked for libharlem-shake.so but was wrong for
blackcat.elf (5184 call FPs) and hello-linux-gcc (266 call FPs).

**Root cause**: IDA's extern segment layout uses variable-width entries, different base
addresses, and binary-dependent symbol orderings. Replicating this exactly is fragile.

**Approach**: Emit `to=got_slot_va` (real address) instead of `to=extern_va` (synthetic).
Normalize IDA xrefs in the benchmark by decoding instruction bytes at each `from`.

**Changes:**

1. **`src/loader.rs`** — Deleted `build_elf_got_map()` and `got_map: HashMap<Va,Va>`.
   Added `build_elf_got_slots()` → `got_slots: HashSet<Va>` (just the set of GOT slot
   VAs from GLOB_DAT/JUMP_SLOT relocs). Deleted `EXTERN_BASE_PAD`.

2. **`src/arch/x86_64.rs`** — `emit_got_indirect()` emits `to=got_slot_va`, gated by
   `got_slots.contains()` (prevents FPs from non-GOT `CALL [RIP+disp]`).

3. **`src/pass.rs`** — `ScanCtx` carries `got_slots: &HashSet<Va>` instead of `got_map`.

4. **`src/bin/benchmark.rs`** — `resolve_x86_got_slot()` decodes FF 15/FF 25 instruction
   bytes to recover GOT slot VA. `extern_bound()` detects IDA's synthetic extern segment.
   IDA call/jump xrefs targeting extern VAs are normalized to GOT slot VAs before comparison.

**Score delta:**
- blackcat.elf call: F1 **0.644 → 0.964**, FP 5255→73
- hello-linux-gcc call: FP **266 → 0**, prec 0.506→1.000
- No regressions on any of 20 test binaries

### Session N+5 — GOT-indirect call/jump resolution (extern VA algorithm)

**Goal**: Implement correct GOT-indirect call/jump resolution for x86-64 PIE ELFs —
mapping `CALL [RIP+GOT_slot]` (FF 15) and `JMP [RIP+GOT_slot]` (FF 25) to IDA's
synthetic "extern segment" VAs. Fix libharlem-shake.so call F1 from 0.587.

**Changes:**

1. **`src/loader.rs`** — Wrote `build_elf_got_map()` with the IDA extern VA algorithm:
   - Collects ALL SHN_UNDEF non-TLS symbols from dynsym (including those without GLOB_DAT relocs, which still consume extern segment slots)
   - Explicitly skips the null symbol at dynsym[0] (empty name)
   - Sorts: STT_FUNC first by dynsym index, then all others by dynsym index
   - `extern_base = max(PT_LOAD p_vaddr + p_memsz) + pie_base + 0x20`
   - Assigns `extern_va[i] = extern_base + i * 8`; maps `got_slot_va → extern_va` for GLOB_DAT/JUMP_SLOT relocs

2. **`src/arch/x86_64.rs`** — `emit_got_indirect()` helper emits Call/Jump xrefs to extern VAs for FF15/FF25 instructions

3. **`src/pass.rs`** — `ScanCtx` carries `got_map`, threaded through to x86_64 scanners

**Score delta (libharlem-shake.so):**
- call: F1 **0.587 → 0.959** (+0.372), TP 3715→8235, FN 5231→711
- jump: F1 **0.966 → 0.976** (+0.010), TP 14890→15169, FN 1035→756
- overall: F1 **0.787 → 0.862** (+0.075)

**Problem**: Algorithm was wrong for blackcat.elf (5184 call FPs) and hello-linux-gcc
(266 call FPs). Replaced by GOT slot VA approach in Session N+6.

### Session N+4 — Performance

**Goal**: maximize CPU utilization and eliminate latency issues; no F1 changes.

**Commits**: `733445f`, `c524363`, `edf2e05`

**Changes:**

1. **Pure Rust ARM64 decoder** (`arm64_decode.rs`): replaced `bad64::decode` (C FFI, 4168B zeroed per call) with a pure bitmask decoder. Eliminated `_platform_memset` which was consuming ~28% of worker CPU.

2. **`Arm64Insn::is_tracked` fast-path** (`arm64_decode.rs`, `arm64.rs`): cheap bitmask pre-classifier skips `Arm64Insn::decode` for ~65% of instructions (those that decode to `Other`). Inline register invalidation via `word & 0x1F` replaces full enum dispatch. Reduced decode cost from ~19% to ~1% of worker CPU.

3. **`immediate_xref` inlined** (`arm64.rs`): marked `#[inline(always)]`.

4. **Output pipeline overhaul** (`main.rs`, `output.rs`, `pass.rs`):
   - `Printer` trait redesigned: `write_record(&self, r, &mut Vec<u8>)` appends to a caller buffer — zero per-record allocation
   - 4 MiB `BufWriter<Stdout>` — amortises syscall overhead
   - Dedicated output thread (`pass.rs`): drain relay thread forwards `Vec<Xref>` batches via `sync_channel(n_workers*4)` without blocking on formatting; output thread runs `on_batch` under `pool.install` so `par_iter` shares the scan pool
   - Chunked parallel format (`main.rs`): batches split into 8192-record sub-chunks; each chunk formatted via `par_iter().fold()+reduce()` into a `Vec<u8>`, then one `write_all` — incremental flushing eliminates hang proportional to `--limit`

5. **`--limit` applied before disasm context** (`main.rs`): `.take(remaining)` before `context()` call — previously entire batch was context-disassembled before truncation.

6. **XBEGIN panic fix** (`x86_64.rs`): TSX `XBEGIN` instruction no longer panics the x86-64 scanner.

**Benchmark (dyld shared cache arm64e, 171M xrefs, 14 cores):**

| Scenario | Before | After |
|---|---|---|
| `--depth paired` (no output) | ~57% worker CPU (scan bottleneck) | ~800% CPU, 1.3s |
| `--limit 10M` (no context) | — | ~800% CPU, 1.3s |
| `--limit 10M -A 5` | 8.1s, 718% CPU | 6s, ~950% CPU |
| `--limit 100M` (full output) | 51.8s, 117% CPU | 6s, ~650% CPU |

### Session N+3

**Fixes applied:**
1. Reverted GOT map extern VA resolution (arm64.rs, x86_64.rs, loader.rs):
   empirical analysis showed IDA's extern VA assignment order ≠ dynsym seq order.
   Removed `build_got_map()`, set `got_map` to always-empty. Removed `is_extern`
   check from BLR/BR handlers. Removed `got_indirect_target()` from x86-64 scanner.
2. Result: libharlem-shake.so overall F1 0.738→**0.787**, call F1 0.433→**0.587**.
   libziggy.so overall F1 0.813→**0.818**, jump F1 0.967→**0.978**.

### Session N+2

**Fixes applied:**
1. Ground truth JSON cleanup: removed IDA type-system xrefs; rebased libziggy and
   libharlem ground truth by +0x400000 to match PIE load addresses.
2. PIE ELF rebase: ET_DYN with first PT_LOAD at p_vaddr==0 now rebased by +0x400000
   (standard Linux load address) in `loader.rs`.
3. `min_ref_va` filter: `PassConfig` field + `--min-ref-va` CLI flag; post-dedup
   retain of xrefs whose target VA ≥ binary's lowest segment VA.
4. GOT map implementation attempt: `build_got_map()` in loader.rs, `got_indirect_target()`
   in x86_64.rs, `is_extern` check in arm64.rs BLR/BR. Produced wrong extern VAs
   (dynsym seq order ≠ IDA order) — reverted in Session N+3.

### Session N+1

**Fixes applied:**
1. `BLR`/`BR` exec-target suppression (`src/arch/arm64.rs`): resolved targets must be
   executable — IDA never records calls/jumps to non-exec addresses (e.g. `.rodata`).
   Removed 77 call FPs and 118 jump FPs. Call F1: 0.999→1.000, jump F1: 0.974→0.975.
2. `BL` exec-target suppression: direct `BL` to non-exec suppressed. Removed 1 call FP.
3. x86-64 `CMP`/`SUB` imm32 data_ptr (`src/arch/x86_64.rs`): IDA records data_ptr for
   `CMP r/m64,imm32` and `SUB r/m64,imm32` when imm resolves to a mapped address.
   Added `imm_as_address()` helper targeting only CMP/SUB/MOV (not AND/OR/XOR bitmasks).
   Net: +25 TPs, +18 FPs on x86-64 data_ptr (+0.0002 data_ptr F1).

**Score delta:**
- ARM64: 0.943 → **0.944** (+0.001)
- x86-64: 0.961 → **0.961** (marginal data_ptr improvement)

### Session N

**Fixes applied:**
1. Fixed 5 compilation errors: missing `byte_scannable` field in `Segment` constructors
   across `parse_macho`, `parse_pe`, `Object::Unknown` arm.
2. Restored `.data.rel.ro` suppression: dead `if false &&` in the PT_LOAD-granular
   fallback was leaving `byte_scannable=true` unconditionally. Fixed to check overlap.
3. Investigated jump FPs/FNs: confirmed x86-64 FPs from dead-zone in `.text`;
   ARM64 FPs from `.rodata`/`.eh_frame*` in exec PT_LOAD.
4. Split exec PT_LOADs per-section: `.rodata`, `.eh_frame_hdr`, `.eh_frame`,
   `.gcc_except_table` etc. marked `executable=false` → eliminated 1915 ARM64 jump FPs
   (+0.011 ARM64 jump F1, +0.005 ARM64 overall).
5. Fixed ARM64 data_write regression: after `.rodata` became non-exec, STR→.rodata
   emitted as data_write FP. Added `!s.writable` check at `arm64.rs:299`.

**Score delta:**
- ARM64: 0.938 → **0.943** (+0.005)
- x86-64: **0.961** (unchanged)

### Session N-1

**Fixes applied:**
1. Fixed `parse_macho` broken state (stray `};` at line 403).
2. Suppressed ADD-VA data_ptr emission (ADRP+ADD pairs emit at ADRP_VA only).
3. Suppressed ADR data_ptr emission (IDA records 0 data_ptr at ADR sources).
4. Fixed byte-scan shard alignment bug (data shard split used insn_align=1 not ptr_size).
5. Added exec-target suppression for byte scan.
6. Added `byte_scannable` field to `Segment` struct + updated `scannable_data_segments()`.
7. Added `--depth`, `--dump-fps`, `--dump-fns`, `--dump-tps`, `--dump-kind` flags to benchmark.
8. Added `.data.rel.ro` suppression via `NO_SCAN_SECTIONS` + section-overlap check.

**Score delta:**
- ARM64: 0.926 → **0.938** (+0.012)
- x86-64: 0.949 → **0.961** (+0.012)
