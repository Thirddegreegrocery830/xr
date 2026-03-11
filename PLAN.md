# Recall improvement plan

Three independent workstreams. Each can be implemented and tested in isolation.

---

## 1. Fix GOT-indirect call/jump resolution

### Problem

For GOT-indirect calls (`FF 15 [RIP+disp]`) and jumps (`FF 25 [RIP+disp]`),
xr tries to replicate IDA's synthetic "extern segment" VA assignment so that
`CALL [got_slot]` emits a call xref to the extern VA that IDA expects.

The extern VA assignment algorithm (`build_elf_got_map` in `src/loader.rs`)
is wrong for some binaries. It was verified on `libharlem-shake.so` (0
mismatches) but produces systematically wrong targets on `blackcat.elf`
(5184 FP calls to wrong extern VAs, 6292 FN calls — those same call sites
with IDA's correct extern VAs).

Root cause: IDA's extern segment layout is not a simple `extern_base + i * 8`
scheme. IDA uses its internal segment allocator, which produces
variable-width entries (4/8/16 byte gaps), a different base address
(page-aligned vs xr's `max_pt_load + 0x20`), and a different symbol
ordering. Replicating this exactly is fragile and binary-dependent.

### Impact

- `blackcat.elf`: call F1 jumps from 0.644 → ~0.77 just by fixing this
- `hello-linux-gcc`: call F1 jumps from 0.506 → ~0.64
- Other PIE ELF binaries with GOT-indirect calls are affected similarly
- Binaries where got_map already works (`libharlem-shake.so`, `libssl3-*`,
  `libcurl-arm64.so`) must not regress

### Approach: match by GOT slot VA, not extern VA

Instead of trying to replicate IDA's extern VA assignment, emit xrefs using
the GOT slot VA as the target. Then in the benchmark, match IDA's extern
xrefs back to their GOT slots.

Concretely:

**Option A — Normalize at benchmark time (least invasive):**

1. Keep xr's current behaviour: for `CALL [RIP+disp]` where `disp` resolves
   to a GOT slot, emit `Call(from=insn_va, to=got_slot_va)`.
2. In `benchmark.rs`, build a reverse map from the binary's relocation
   tables: `extern_va → got_slot_va`. For each IDA xref whose target is an
   extern VA, normalize it to the corresponding GOT slot VA before
   comparison. This way both xr and IDA agree on `(from, got_slot_va)`.
3. This doesn't require changing `build_elf_got_map` at all — in fact,
   delete `got_map` entirely from `LoadedBinary` and the `scan_linear` /
   `scan_with_prop` call chain.

**Option B — Replace extern VA with GOT slot VA in xr output:**

1. Same as A, but also change `emit_got_indirect()` in `src/arch/x86_64.rs`
   to emit `to=got_slot_va` instead of `to=extern_va`.
2. The output now shows the GOT slot address as the call target, which is
   arguably more useful (it's a real address in the binary, not a synthetic
   one).
3. Benchmark normalization is the same as A.

**Recommended: Option A** — least code change, keeps benchmark accurate.

### Verification after fix

- `blackcat.elf` call FPs should drop from 5255 to ~71
- `hello-linux-gcc` call FPs should drop from 266 to ~0
- `libharlem-shake.so`, `libssl3-*`, `libcurl-arm64.so` must not regress
  (call prec should stay ≥0.999)
- Run the full benchmark suite to confirm no regressions

### Files to modify

- `src/loader.rs`: possibly delete `build_elf_got_map` and `got_map` field,
  or keep it and change the target from extern_va to got_slot_va
- `src/arch/x86_64.rs`: `emit_got_indirect()` — change target from
  extern_va to got_slot_va, or remove got_map usage entirely
- `src/pass.rs`: remove `got_map` from `ScanCtx` if deleted
- `src/bin/benchmark.rs`: build a `extern_va → got_slot_va` reverse map
  from ELF relocation tables; normalize IDA xrefs before comparison
- `src/main.rs`: remove `got_map` threading if deleted

### Step by step

1. Read `src/arch/x86_64.rs:emit_got_indirect()` and understand the current
   flow: `insn.memory_displacement64()` gives the GOT slot VA, then
   `got_map.get(&got_slot_va)` gives the extern VA.

2. Change `emit_got_indirect()` to emit `to=got_slot_va` directly (the
   data_read xref already does this). Remove the `got_map` lookup. The
   `kind` should stay as `Call` or `Jump`.

3. Delete `got_map` from `LoadedBinary`, `ScanCtx`, `scan_linear`,
   `scan_with_prop`, `build_elf_got_map`. Clean up all threading of this
   field through the call chain.

4. In `benchmark.rs`, after loading the binary and ground truth:
   - Parse the ELF's `.rela.dyn` and `.rela.plt` sections (use `goblin`).
   - For each `R_X86_64_GLOB_DAT` / `R_X86_64_JUMP_SLOT` /
     `R_AARCH64_GLOB_DAT` / `R_AARCH64_JUMP_SLOT` reloc, record
     `r_offset + pie_base` → this is the GOT slot VA.
   - For each IDA xref whose `to` address is in the extern segment
     (above the highest PT_LOAD end + pie_base), find which GOT slot
     has a reloc whose `r_sym` matches the extern VA's symbol. This
     requires building the extern VA → symbol → GOT slot chain.
   - Simpler alternative: just match GOT-indirect xrefs by `from` address
     only (ignore `to`). Since there's exactly one `CALL [RIP+disp]` per
     from-address, matching by `(from, kind=call)` is unambiguous.

5. Run benchmark on all testcases. Verify no regressions.

---

## 2. Relocation-table data_ptr recovery

### Problem

74.8% of all FNs (107,855 / 144,138) are `data_ptr` xrefs. These are
pointer-sized values in data sections (`.data.rel.ro`, `.got`, `.init_array`,
vtables, etc.) that IDA recognizes as pointers via relocation tables and
type propagation.

Currently, xr has two mechanisms for data_ptr:
- **Byte scan** (`byte_scan_pointers`): reads every 8-byte-aligned slot in
  scannable data segments. Catches raw pointers that happen to point into
  mapped segments.
- **ADRP/LDR pairing** (ARM64) and **LEA/MOV imm** (x86-64): catches
  code-side pointer references.

Both miss pointers in sections that are marked `byte_scannable: false`:
- ELF: `.data.rel.ro`, `.data.rel.ro.local` (excluded due to high FP rate
  without relocation context — see `NO_SCAN_SECTIONS` in `parse_elf`)
- Mach-O: `__got`, `__la_symbol_ptr`, `__nl_symbol_ptr`, `__cfstring`
- PE: BSS-like sections

The relocation tables tell us exactly which slots in `.data.rel.ro` contain
pointers and what they point to. Using them eliminates the FP problem that
caused these sections to be excluded.

### Impact

- `dwritemin.dll`: data_ptr recall could jump from 0.148 to potentially
  >0.5 (42,228 FNs, most from reloc-covered sections)
- PIE ELF binaries: data_ptr recall should improve significantly (the
  `.data.rel.ro` exclusion suppresses thousands of TPs)
- Statically linked binaries: no change (no relocation tables)

### Approach

Add a new scan source that reads ELF/PE/Mach-O relocation tables and
emits `DataPointer` xrefs for every relocation that resolves to a mapped
address.

### ELF implementation

1. In `parse_elf()` (or a new function called from there), iterate all
   `R_X86_64_64`, `R_X86_64_GLOB_DAT`, `R_AARCH64_ABS64`,
   `R_AARCH64_GLOB_DAT` relocations in `.rela.dyn`.

2. For each reloc: `from_va = r_offset + pie_base`. The target is the
   symbol's resolved address: for defined symbols it's `sym.st_value +
   pie_base + r_addend`; for SHN_UNDEF symbols it's the extern VA (which
   we may not know — skip those, or emit to GOT slot VA).

3. Emit `Xref { from: from_va, to: target, kind: DataPointer,
   confidence: Confidence::ByteScan }` (or a new `RelocResolved`
   confidence level).

4. Remove `.data.rel.ro` from `NO_SCAN_SECTIONS` — the relocation-based
   scan replaces the blanket exclusion. (Or keep the exclusion for the
   byte scanner but add reloc-based pointers on top.)

### PE implementation

1. PE has a `.reloc` section (base relocation table) with
   `IMAGE_REL_BASED_DIR64` entries. Each entry gives an RVA where the
   loader writes a relocated pointer.

2. Read the pointer value at each relocated slot. If it points into a
   mapped segment, emit a `DataPointer` xref.

3. PE also has the Import Address Table (IAT) — each entry is a pointer
   to an imported function. Parse the IAT and emit `DataPointer` xrefs.

### Mach-O implementation

1. Mach-O dyld fixup chains (`LC_DYLD_CHAINED_FIXUPS`) or classic
   `LC_DYSYMTAB` indirect symbol tables identify pointer slots.

2. Parse the fixup chain entries and emit `DataPointer` xrefs for each
   slot that resolves to a mapped address.

### Files to modify

- `src/loader.rs`: add `reloc_pointers: Vec<(Va, Va)>` to `ParseResult`
  and `LoadedBinary`. Populate in `parse_elf`, `parse_pe`, `parse_macho`.
- `src/pass.rs`: emit relocation-derived `DataPointer` xrefs alongside
  byte-scan and code-scan xrefs. These are not sharded — they come from
  a pre-built list, so just emit them in a single batch.
- `src/xref.rs`: optionally add `Confidence::RelocResolved` between
  `ByteScan` and `LinearImmediate`.

### Step by step

1. Start with ELF only. In `parse_elf()`, after building segments, iterate
   `elf.dynrelas` and `elf.pltrelocs`.

2. For each reloc with type `R_X86_64_64` or `R_AARCH64_ABS64`:
   - `from = r_offset + pie_base`
   - Look up `r_sym` in `.dynsym`. If `sym.st_shndx != SHN_UNDEF`,
     `target = sym.st_value + pie_base + r_addend`.
   - If target is in a mapped segment, record `(from, target)`.

3. For `R_X86_64_RELATIVE` / `R_AARCH64_RELATIVE`:
   - `from = r_offset + pie_base`
   - `target = r_addend + pie_base`
   - If target is in a mapped segment, record `(from, target)`.

4. Store in `LoadedBinary::reloc_pointers`.

5. In `XrefPass::run`, emit these as a single batch of `DataPointer` xrefs
   before or after the scan shards. Apply the same `min_ref_va` and
   `to_range` filters.

6. Run benchmark. Expect data_ptr recall to improve significantly on PIE
   ELF binaries. Check that precision stays high (reloc-derived pointers
   should be nearly 100% precise).

7. Then extend to PE (base relocation table) and Mach-O (fixup chains).

---

## 3. Jump table recovery

### Problem

12.3% of FNs (17,731 / 144,138) are `jump` xrefs. Most are jump table
targets: the compiler generates `jmp [reg*8 + table_base]` (x86-64) or
`adr x16, table; ldr w17, [x16, w17, uxtw #2]; add x16, x16, w17, sxtw;
br x16` (ARM64). IDA recovers the table entries via CFG + dataflow.

xr currently emits a `data_read` to the table base (via RIP-relative or
ADRP pairing) but doesn't read the table contents to discover the actual
jump targets.

### Impact

- `curl-aarch64`: ~3310 jump FNs
- `curl-amd64`: ~3450 jump FNs
- Most are from switch statements in large binaries

### Approach

Pattern-match the common jump table idioms and read the table data.

### x86-64 jump tables

The canonical pattern (GCC/Clang) is:

```
lea  rcx, [rip + table_base]    ; or mov rcx, table_addr
movsxd rax, dword ptr [rcx + rax*4]  ; load 32-bit offset
add  rax, rcx                   ; add base
jmp  rax                        ; indirect jump
```

Or the simpler absolute-address table:

```
jmp  qword ptr [rax*8 + table_base]  ; absolute 64-bit pointers
```

Detection:
1. When `scan_with_prop` encounters an indirect `JMP reg`, check if the
   register value was set by a sequence involving a memory load from a
   base + index pattern.
2. If the base is a known constant (from LEA or MOV), scan the table at
   that address: read successive 32-bit signed offsets (or 64-bit
   pointers), add the base, and emit `Jump` xrefs for each valid target.
3. Stop scanning when a target falls outside the code segment or exceeds
   a reasonable bound (256 entries is a safe limit for most switches).

### ARM64 jump tables

The canonical pattern (Clang) is:

```
adr  x16, table_base
ldrsw x17, [x16, x17, lsl #2]   ; load signed 32-bit offset
add  x16, x16, x17              ; compute target
br   x16                        ; indirect jump
```

Or (GCC):

```
adrp x0, page
add  x0, x0, #table_offset
ldr  w1, [x0, w1, uxtw #2]     ; unsigned 32-bit offset
add  x0, x0, w1, sxtw
br   x0
```

Detection:
1. When `scan_adrp` encounters a `BR Xn` where `Xn` was set by an
   `ADD Xn, Xbase, Xoffset` and `Xbase` came from an ADR/ADRP, check
   if there's a preceding `LDR Wt, [Xbase, Widx, ...]` that loaded from
   the table.
2. Read the table: starting at the ADR/ADRP-resolved base, read 32-bit
   signed (or unsigned) offsets, add the base, and emit `Jump` xrefs.

### Files to modify

- `src/arch/x86_64.rs`: add `recover_jump_table()` function, called from
  `scan_with_prop` when an indirect `JMP reg` is encountered and the
  register state contains a known base address.
- `src/arch/arm64.rs`: add similar recovery in `scan_adrp` for `BR Xn`
  patterns.
- `src/arch/mod.rs`: `SegmentDataIndex::read_i32_at()` helper for reading
  table entries.

### Step by step

1. Start with x86-64. In `scan_with_prop`, when processing `Code::Jmp_rm64`
   with `OpKind::Register` and a known register value:
   - Check if the known value came from a `LEA r, [rip+disp]` (the prop
     state already tracks this via `Lea_r64_m`).
   - If so, treat it as a potential jump table base.

2. Add `recover_x86_jump_table(base_va, idx, data_idx) -> Vec<Xref>`:
   - Read up to 256 consecutive `i32` values at `base_va`.
   - For each value, compute `target = base_va + offset_i32`.
   - If target is in an executable segment, emit `Jump(from=jmp_va,
     to=target)`.
   - Stop on first target outside executable range.

3. Also detect the `jmp [reg*8 + table]` pattern:
   - When `Jmp_rm64` has `OpKind::Memory` with a `memory_index` register
     and scale, check if the displacement is a mapped address.
   - If so, read 64-bit pointers from that address.

4. Test against `curl-amd64` jump FNs.

5. Then extend to ARM64 with the ADR+LDR+ADD+BR pattern.

### Confidence level

Jump table targets should use `Confidence::LocalProp` — they're derived
from local analysis of the instruction sequence, not from a full CFG.

---

## Priority order

1. **GOT fix** — pure bugfix, highest F1 impact per line of code changed
2. **Reloc data_ptr** — biggest FN category (75%), moderate implementation
   effort
3. **Jump tables** — meaningful FN reduction, most implementation effort
