# TODO

## Bugs

- [x] x86-64 `update_prop_state` drops `Mov_r32_imm32` values. The match handles
  `Code::Mov_r32_imm32` but checks for `OpKind::Immediate64` and
  `OpKind::Immediate32to64` — neither matches, so it falls through to
  `vals[dst_idx] = None`. `mov eax, <addr>; call rax` is never resolved by
  propagation. (`src/arch/x86_64.rs:305`)

- [x] `arm64_decode.rs` comment table has wrong LDR/STR masks. Header says
  `LDR mask=BFC0_0000, match=B940_0000` but code uses
  `mask=FFC0_0000, match=F940_0000`. Code is correct (64-bit LDR only);
  comment is misleading. Same for STR.

## Error Handling

- [x] `main.rs` silently ignores all I/O errors. `let _ = stdout.write_all(...)`
  and `let _ = stdout.flush()` at lines 165, 240, 253, 255. The final `flush()`
  should propagate errors since `main` returns `Result`.

- [x] `parse_macho` uses `Debug` formatting for errors:
  `map_err(|e| anyhow::anyhow!("{e:?}"))` produces ugly output.
  Should use `{e}` (Display). (`src/loader.rs`)

## Architecture & Design

- [x] `ParseResult` is a 6-element tuple; `DyldParseResult` adds a 7th. Should
  be a named struct. (`src/loader.rs:220`)

- [x] `Depth::ByteScan` on code segments runs full analysis. ARM64 ByteScan maps
  to `scan_adrp` (depth-2), x86-64 ByteScan maps to `scan_linear` (depth-1).
  README says ByteScan is "pointer-sized byte scan of data sections only" but
  code segments get full analysis regardless.

- [x] Unused `_segments: &[Segment]` parameter threaded through
  `arm64::scan_linear`, `arm64::scan_adrp`, `x86_64::scan_linear`,
  `x86_64::scan_with_prop`. All access goes through index types.

- [x] Duplicated scan logic in `x86_64.rs`. `scan_linear_with_index` and
  `scan_with_prop` copy the entire decode loop, branch emission, RIP-relative
  handling, and `imm_as_address` logic. `scan_with_prop` should compose with
  depth-1 logic rather than duplicate it.

## Typing & Naming

- [x] Raw `u64` used everywhere for virtual addresses. VAs, file offsets, sizes,
  and immediates are all `u64`. A newtype `Va(u64)` would prevent mixing.

- [x] `from_range` / `to_range` are `Option<(u64, u64)>`. A named
  `VaRange { start: u64, end: u64 }` or `Range<u64>` would be clearer.

- [x] Magic constants scattered without named constants: `0x0040_0000` (PIE base),
  `0x0100_0000` (exec target threshold), `0x20` (extern base offset),
  `8192` (chunk size), `4 * 1024 * 1024` (BufWriter capacity),
  `64` (boundary overlap default).

- [x] `XrefKind::name()` returns `&'static str` used for scoring comparisons in
  `benchmark.rs`. String-based kind matching is fragile compared to direct
  enum comparison.

## Soundness

- [x] `&'static` lifetime on segment data is unsound when `Segment` is cloned.
  `Segment` derives `Clone` and `data: &'static [u8]` is a lie — backing
  mmap/Box lives only as long as `LoadedBinary`. Not currently exploitable
  (segments only borrowed within `XrefPass::run`), but the public API allows it.

## Minor

- [x] `ConfidenceCounts::add` uses a match on `Confidence`. If a new variant is
  added it must be updated in lockstep. An array indexed by `repr(u8)` value
  would be safer.

- [x] No validation of overlapping segments in `SegmentIndex::build`. Malformed
  binaries with overlapping PT_LOADs could cause wrong binary-search results.
  A debug assertion on build would catch this.

## Investigate

- [x] ARM64 recall regressed significantly at some point (possibly before or after
  repo history was squashed). STATUS.md records curl-aarch64 overall F1=0.944
  (rec=0.907) but current code produces F1=0.866 (rec=0.771). data_read collapsed
  from F1=0.906 to 0.042, data_write from 0.541 to 0.290, data_ptr from 0.813 to
  0.518. Call and jump are roughly unchanged. Need to bisect and fix.
  **Root cause**: LDR handler cleared `adrp_state[rt]` before reading
  `adrp_state[rn]`. When Rt==Rn (24% of LDRs: `ADRP X0, page; LDR X0, [X0, #off]`)
  the ADRP state was destroyed before pair resolution. Fix: snapshot base state first.
  Result: overall F1 0.866→0.943, data_read F1 0.042→0.894, data_ptr F1 0.518→0.815.
