# TODO

## Error Handling

- [ ] Thread pool build uses `.expect()` instead of returning an error.
  `rayon::ThreadPoolBuilder::build().expect(...)` panics on failure (e.g.
  OOM). Since `XrefPass::run` doesn't return `Result`, this is consistent
  but not ideal. Consider making `run` return `Result<PassResult>`.
  (`src/pass.rs`)

## Architecture & Design

- [x] ARM64 `scan_linear` takes unused `_data_idx: &SegmentDataIndex`
  parameter. The x86-64 side was already cleaned up (removed the unused
  `_data_idx` from `scan_linear`/`scan_with_prop`) but ARM64's
  `scan_linear` still carries it. `scan_adrp` legitimately uses it for
  pointer-follow, but `scan_linear` does not.
  (`src/arch/arm64.rs:33`)

- [ ] No GOT/IAT map for Mach-O or PE binaries. `parse_macho` and
  `parse_pe` return empty `got_map`, so indirect `CALL [RIP+got]` /
  `JMP [RIP+got]` xrefs to extern symbols are never resolved for those
  formats. ELF's `build_elf_got_map` shows the approach; Mach-O needs
  `__got`/`__la_symbol_ptr` parsing, PE needs IAT parsing.
  (`src/loader.rs`)

- [ ] `build_elf_got_map` only handles x86-64 and AArch64 relocation
  types (`R_X86_64_GLOB_DAT/JUMP_SLOT`, `R_AARCH64_GLOB_DAT/JUMP_SLOT`).
  ARM32 (`R_ARM_GLOB_DAT`=21, `R_ARM_JUMP_SLOT`=22) and x86
  (`R_386_GLOB_DAT`=6, `R_386_JMP_SLOT`=7) are missing — GOT-indirect
  calls on those arches produce no extern-VA xrefs.
  (`src/loader.rs`, `build_elf_got_map`)

- [ ] `ScanRegion` has two `#[allow(dead_code)]` fields: `mode` and
  `writable`. They are reserved for future ARM32/Thumb and
  write-tracking passes. Either implement the passes that use them or
  remove the fields and add them back when needed.
  (`src/arch/mod.rs`)

## Performance

- [ ] `ContextLine` allocates a `String` for `hex` on every disassembly line
  via `bytes_to_hex`. Since context is rendered in parallel via `par_iter`,
  this is many small allocations. Writing hex directly to the output buffer
  would avoid the intermediate `String`.
  (`src/output.rs`)

- [ ] `disasm_x86` and `build_window` clone `Vec<u8>` and `String` for
  every instruction line (`bytes.clone()`, `text.clone()`). The tuples
  could be consumed (moved) instead of cloned when building the final
  `DisasmLine` vec — the source vecs are not used after conversion.
  (`src/disasm.rs`)

## Testing

- [ ] Test helpers in `pass.rs` and `arch/*.rs` use `Box::leak` to create
  `&'static [u8]` slices for synthetic segments. This leaks memory on
  every test invocation. Harmless for correctness but accumulates with
  `--test-threads=1` under sanitisers. A `ManuallyDrop`+destructor or
  a test-scoped arena would avoid the leaks.
  (`src/pass.rs`, `src/arch/arm64.rs`, `src/arch/x86_64.rs`)

## Minor

- [ ] `benchmark.rs` `run_pass` discards the `PassResult` returned by
  `XrefPass::run` (assigned to `_result`). The `elapsed_ms` and
  `confidence_counts` fields could replace the manual `Instant` timing
  and provide a per-confidence breakdown in the benchmark output.
  (`src/bin/benchmark.rs`)

- [ ] `Confidence::COUNT` is a manual constant (`5`) that must stay in
  sync with the enum variants. A `const { ... }` block deriving the
  count from `Confidence::ALL.len()` would make it self-maintaining.
  (`src/xref.rs`)
