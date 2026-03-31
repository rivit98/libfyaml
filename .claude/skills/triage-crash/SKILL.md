---
name: triage-crash
description: Use when given a libfyaml fuzzer artifact (AFL crash or hang file), the sanitizer log from replaying one, or a logs_test_* directory of such logs, or when asked to triage crashes, add an RA()/RF() reproducer to main.c, or write a reportN.md for upstream.
argument-hint: <artifact | logs dir> [sanitizer log]
---

# Crash triage

Input: $ARGUMENTS

You get a fuzzer **artifact** and the **sanitizer log** from replaying it
(`./fuzz triage <artifact>` writes one log per build), or a whole
`logs_test_<group>/` directory of them. For every new root cause you produce:

1. an `RA()` entry in `src/fuzz/main.c`, to find the test case that fails
2. an `RF()` entry in `main.c`, a self-contained reproducer inside the harness
3. `reportN.md`, a report ready to submit upstream - see
   [report-template.md](report-template.md)

Triage establishes whether the problem is real, new and the library's, and
then produces the entries without deeper analysis. Everything runs on this
checkout's `repro` / `repro-msan` builds: no clean upstream tree (§3).

**Batch the work, rebuild once per phase.** Every edit of `main.c` recompiles
the harness, so never go root by root: cluster all the roots first (§1), add
*all* their `RA()` entries in one edit and rebuild once (§5), run `vc<n>` for
all of them, then paste *all* the `RF()` blocks in one edit and rebuild once
(§6). The same goes for `RR()` (identical to `RA()`) and for the temporary
`RF(99)` copies. Number the roots 1..N up front.

**Do not dig into the library.** The cause is not needed to file a report. The
sanitizer stack and the failing `test_*` function are enough; reading library
code is for duplicate checks only (§7), never for explaining the bug.

## 1. Many logs: group, then dedup by replay

```
uv run --directory ~/workspace/fuzzing/fuzzing-tools libfuzzer-parse <logs dir> > parse.txt
```

The parser groups by top frames. Its groups are not root causes:

- Its counts mix builds. `fast` logs have no stack, so its
  `SIGSEGV unknown` / `SIGABRT unknown` groups pool unrelated roots under one
  representative. Never size a root by them.
- One root shows up as many groups: ASAN, MSAN, LSAN and `fast` each report
  it differently, and a dtor crash appears once per caller.

Replay each group's `input:` through both reproducers and compare the
**replay**, not the parser's site:

```
( ulimit -s 8192; TC=test_<group> timeout 30 fuzzer/build/repro/fuzz2 <artifact> )
( ulimit -s 8192; TC=test_<group> timeout 30 fuzzer/build/repro-msan/fuzz2 <artifact> )
```

Script it over all groups in parallel (`xargs -P`), keep the `SUMMARY:` line,
the UBSAN `runtime error:` line and the first library frames per replay, and
cluster on those. ASAN runs first and stops at the first error, so the MSAN
replay is often the one that names a second root. Decode reflection inputs
(entry, meta, yaml, blob strings) to see what a cluster has in common.

If `./fuzz build` is running (`pgrep -af 'fuzz build'`), it rebuilds
`repro`/`repro-msan` last and will replace `fuzz2` under you: copy both
`fuzz2` binaries to the scratchpad and replay those. Never run
`cmake --build` in a build directory that `./fuzz build` is working on.

## 2. Is it new, and is it the library?

- Compare with the `RA()`/`RF()` groups at the bottom of `main.c`, each tagged
  with its `reportN.md`, and the `reportN.md` files themselves. The same root
  cause reached from a different call site is a duplicate, not a new report.
- An allocation frame in `main.c` or `fuzz_utils.h` means suspect the harness
  first. Before blaming the library, read the ownership contract in
  `include/libfyaml/*.h`. A free of a pointer allocated by
  `corpus_prime_tokens()` or another fixture means the library freed memory
  it never owned - stale data in the deterministic heap (`fuzz_heap.h`), not a
  fixture bug.
- An MSAN report whose frames leave libfyaml (glibc, BLAKE3 assembly) is
  almost certainly a false positive.
- The harness is not fully deterministic: there is a shared corpus document and
  a seeded allocator recipe. Replay 2-3 times before calling a crash
  unreproducible. A replay that hits the 30 s timeout is a slow deep
  recursion or a hang, not "does not reproduce".

## 3. Why no clean upstream tree

The library sources here are upstream's, unpatched. Check that this prints
nothing (the working tree included):

```
git diff $(git merge-base HEAD origin/master) -- src include ':!src/fuzz'
```

Then the repro builds are upstream at the merge base, and that commit is the
report's code version. If the diff is not empty, stop and ask: a library
patch makes every finding suspect. Build a clean tree under `./scratch` only
when `git fetch origin && git log --oneline HEAD..origin/master -- <files in
the stack>` shows upstream changed the code since the merge base.

## 4. The reproducer builds

`fuzz2` is the harness without a fuzzing engine (`-DREPRODUCER`, harness at
`-O0`):

| build | directory | binary | library for standalones |
|---|---|---|---|
| ASAN+UBSAN | `fuzzer/build/repro` | `fuzz2` | `libfyaml.a` |
| MSAN (origins) | `fuzzer/build/repro-msan` | `fuzz2` | `libfyaml.a` |

After editing `main.c`, rebuild incrementally:

```
cmake --build fuzzer/build/repro --target fuzz2
cmake --build fuzzer/build/repro-msan --target fuzz2
```

Only when a directory is missing or its `CMakeCache.txt` does not match the
flags in `fuzzer/lib/build.sh`, configure it with `./fuzz build repro` or
`./fuzz build repro-msan`. Never create a build directory outside
`fuzzer/build/`.

- `--target fuzz2` rebuilds `libfyaml.a` (the `fyaml_static` target `fuzz2`
  links). The `libfyaml.so` next to it is NOT rebuilt and is weeks stale:
  never link a standalone against it.
- `repro` has `-DENABLE_ASAN=ON`, which instruments the library as well, not
  only the harness. Stack-overflow findings depend on the library's frame
  sizes.
- `repro-msan` instruments every translation unit through `CMAKE_C_FLAGS` and
  builds with libclang off: an uninstrumented libclang floods MSAN with false
  positives.

## 5. RA: find the failing test case

At the bottom of `main.c`, inside `#if defined REPRODUCER` and before
`main()`, add the next free numbers (`RR` is identical to `RA`). Add **every**
root's entry in this one edit, then rebuild **once**:

```c
/* reportN.md */
RA(n, "/absolute/path/to/artifact")
```

Then run all of them from the one binary:

```
for n in 1 2 3; do VERBOSE=1 stdbuf -o0 fuzzer/build/repro/fuzz2 vc$n > vc$n.out 2> vc$n.err; done
```

- stdout gets a ready-to-paste `RF(n, test_func, ...)` block among the flag
  dumps. Without `stdbuf -o0` the crash eats the buffered block.
- stderr gets `=== Running <test> ===` before each test case and a timing line
  after it. The first round of `Running` lines is `warmup_exec()`, not the
  artifact. In the second round, the last `Running` line with no timing line
  after it is the failing test case, and the `test_*` frame in the stack trace
  should agree.
- `TC=<test case or group>` runs only that. A `TC` left in the environment
  restricts every later run.
- If the crash needs two test cases in sequence (both touch the shared corpus
  document), wrap them in one static function and use that as `test_func`.

## 6. RF: the reproducer

Paste the printed blocks under their `RA()`s - all roots in one edit, then one
rebuild (script the paste from the `vc<n>.out` files; the block ends at the
first `\n)\n`). Replace `test_func` with the failing test case, and above it
put the sanitizer that caught the bug in a few words, then the `gh` command
that files the issue (written once the report and its title exist - see
[report-template.md](report-template.md)):

```c
/* MSAN */
// gh issue create --repo pantoniou/libfyaml --body-file reportN.md --title "<area>: <what breaks> <when>"
RF(n,
test_generic_document_builder,
(&(struct flags_t){ ... }),
"\x7c\x39\x0a...",
25
)
```

Rebuild. `fuzz2 tc<n>` has to fail with the same `SUMMARY` as the log, under
the same sanitizer. For stack overflows, run `(ulimit -s 8192; fuzz2 tc<n>)`:
8 MB is the default stack a report should assume.

**`alloc_fail_nth` is not 0:** the `allocation N failed (injected)` line
prints only after the test case returns, so a crash hides it. Add a
temporary `RF(99)` copy with `.alloc_fail_nth = 0` and run `tc99`. If it
passes, the bug needs the failed allocation and the standalone must simulate
it ([report-template.md](report-template.md)); say so in the comment above
the `RF()`. Delete `RF(99)` afterwards.

## 7. Root cause

The report does not explain the bug. You need just enough of the cause to
catch duplicates; the standalone is the `test_*` function trimmed down, so it
needs no understanding of the library (§8).

- Name the condition ("an anonymous struct reached through a pointer", "a
  `void *` field with a default") from the sanitizer stack and the input, not
  from reading library source. Reflection inputs: diff the blob against the
  nearest `fuzzer/seeds/reflection/blob_*` and apply the differing bytes one
  at a time; `fuzzer/build/fytool-clang/fy-tool --reflect --import-blob X
  --generate-c` prints the mutated C types, which usually names the condition
  at once (a duplicate enum value, `T *` turned into `T **`). Confirm with a
  real C header (`--dry-run --import-c-file x.h --generate-blob x.blob`).
- A timeout is a bug only with a stack: sample it
  (`ASAN_OPTIONS=handle_segv=1:fast_unwind_on_fatal=0 timeout -s SEGV 8 fuzz2 <artifact>`)
  and bucket by the top library frames. Do not claim a hot frame explains an
  artifact until a reproducer built from sane input shows it.
- An ASAN `allocation-size-too-big` is the sanitizer's limit, not a bug, if the
  library handles the NULL (`ASAN_OPTIONS=allocator_may_return_null=1`).
- For MSAN, trust the origin (`repro-msan` tracks origins), not the crash
  frame.
- `NDEBUG` changes behaviour: `assert()`s vanish, and without `NDEBUG`,
  `fy-parse.c` defines `ATOM_SIZE_CHECK`. The repro builds are RelWithDebInfo
  like the fuzzer; keep it that way.

## 8. Standalone program and report

Follow [report-template.md](report-template.md). The reproducer in the report
is the failing `test_*` function from `main.c` with the harness removed - not
a program written from an understanding of the library. Filing happens only
when the user asks; then replace the `gh` comment above the `RF()` with the
issue URL.

## Common mistakes

| Mistake | Instead |
|---|---|
| Sizing a root by the parser's biggest group | Replay; `fast`'s `unknown` groups mix roots |
| Linking a standalone against `fuzzer/build/repro/libfyaml.so` | `libfyaml.a` - the `.so` is stale |
| Trusting "no `injected` line" when `alloc_fail_nth != 0` | Rerun a copy with `alloc_fail_nth = 0` |
| Rebuilding `repro` while `./fuzz build` runs | Replay snapshot copies, wait for it to finish |
| Writing the standalone from scratch | Copy the failing test case (report-template §7) |
| Reading library code to explain the bug | Not needed; stack + test case suffice (duplicate checks only) |
| One `RA()` / `RF()` edit + rebuild per root | Add all of them in one edit, rebuild once per phase |
| Matching a `logs_test_yaml` log by `id:000000` | Match the full file name; the dir holds stale logs from older runs |
