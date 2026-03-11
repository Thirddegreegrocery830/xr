# TODO

## Error Handling

- [ ] Thread pool build uses `.expect()` instead of returning an error.
  `rayon::ThreadPoolBuilder::build().expect(...)` panics on failure (e.g.
  OOM). Since `XrefPass::run` doesn't return `Result`, this is consistent
  but not ideal. Consider making `run` return `Result<PassResult>`.
  (`src/pass.rs`)

## Minor

- [ ] `ContextLine` allocates a `String` for `hex` on every disassembly line
  via `bytes_to_hex`. Since context is rendered in parallel via `par_iter`,
  this is many small allocations. Writing hex directly to the output buffer
  would avoid the intermediate `String`.
  (`src/output.rs`)
