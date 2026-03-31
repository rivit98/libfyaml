# libfyaml fuzzing checkout

This is libfyaml with an AFL++ campaign on top: `./fuzz` drives builds, the
campaign and triage (see `fuzzer/README.md`), and the harness is
`src/fuzz/main.c`. The library sources are upstream's, unpatched: keep
`git diff $(git merge-base HEAD origin/master) -- src include ':!src/fuzz'`
empty. Bugs are confirmed on the `repro` / `repro-msan` builds and reported
against the merge base - no clean upstream tree. Build one only when upstream
changed the code since the merge base; it goes under `./scratch`, not the
scratchpad.

## Crash triage

Turning an artifact, a sanitizer log or a whole `logs_test_*` directory into
`RA()`/`RF()` pairs and `reportN.md` files: use the `triage-crash` skill
(`/triage-crash <artifact | logs dir> [log]`).

Triage workflow rules (details in the skill):

- Define every `RA()`/`RR()` for a triage batch in one edit and rebuild once;
  do the same for the `RF()` entries. Never edit and rebuild `main.c` per
  root - each rebuild recompiles the harness.
- Digging into the library is not required to file a report. The sanitizer
  stack and the failing `test_*` function are enough.
- The standalone reproducer in `reportN.md` is a modification of the original
  `test_*` function from `main.c` (harness removed, code trimmed), not a
  program written from library knowledge.

## Builds

- Every build directory lives in `fuzzer/build/<variant>/` - the reproducers
  are `fuzzer/build/repro` (ASAN+UBSAN) and `fuzzer/build/repro-msan` (MSAN).
  Never create `build-repro*` or other build directories at the repository
  root.
- Reuse existing builds and rebuild incrementally
  (`cmake --build fuzzer/build/repro --target fuzz2`). Configure only when the
  directory is missing, through `./fuzz build <variant>`.
- `--target fuzz2` also rebuilds `libfyaml.a`; the `libfyaml.so` in the
  repro dirs is stale. Standalone reproducers link the `.a`.
- Never build in `fuzzer/build/` while `./fuzz build` runs
  (`pgrep -af 'fuzz build'`); it rebuilds every variant, repro ones last.

## Reports and issues

- Every reported bug keeps its `RA()` + `RF()` pair at the bottom of
  `src/fuzz/main.c`, tagged `/* reportN.md */`, with either the
  `gh issue create` comment or the issue URL above the `RF()`.
- Never run `gh issue create` on your own: filing is the user's call. When
  the user asks you to file, run the prepared command, then replace the
  comment above the `RF()` with the issue URL. Always spell out
  `--repo pantoniou/libfyaml`, because `origin` is upstream but a `fork`
  remote also exists.
- Once upstream fixes a bug, confirm that `tc<n>` passes, then delete its pair.
  A passing `tc<n>` is noise, not a test.
