---
name: triage-crash
description: Use when given a libfyaml fuzzer artifact (AFL crash or hang file) or the sanitizer log from replaying one, or when asked to triage a crash, add an RA()/RF() reproducer to main.c, or write a reportN.md for upstream.
argument-hint: <artifact> [sanitizer log]
---

# Crash triage

Input: $ARGUMENTS

You get a fuzzer **artifact** and the **sanitizer log** from replaying it
(`./fuzz triage <artifact>` writes one log per build). You produce three things:

1. an `RA()` entry in `src/fuzz/main.c`, to find the test case that fails
2. an `RF()` entry in `main.c`, a self-contained reproducer inside the harness
3. `reportN.md`, a report ready to submit upstream - see
   [report-template.md](report-template.md) for the standalone program and the
   report format

Triage does not look for the cause. It only establishes whether the problem
really exists and whether the harness is to blame (§2), then produces the
`RA()`/`RF()` entries (§4-§5) without deeper analysis.

## 1. Read the log

- Header lines: `### artifact :` is the input file, `### variant :` is the
  build that crashed: `asan` (ASAN+UBSAN), `msan`, `lsan` (leaks), or `fast`
  (no sanitizer: SEGV or abort only). The `SUMMARY:` line gives the bug class
  and the top frame.
- Pick the reproducer build: `msan` → `fuzzer/build/repro-msan`, anything else
  → `fuzzer/build/repro`.
- The first 4 bytes of an artifact are a little-endian `uint32` seed.
  `setup_flags()` expands it into `struct flags_t`, and the test cases receive
  the bytes after it.
- The log's MSAN build has no origin tracking, and its frames can point far
  from the cause. The `repro-msan` build tracks origins.

## 2. Is it new, and is it the library?

- Compare with the `RA()`/`RF()` groups at the bottom of `main.c`, each tagged
  with its `reportN.md`. The same root cause reached from a different call site
  is a duplicate, not a new report.
- An allocation frame in `main.c` or `fuzz_utils.h` means suspect the harness
  first. Before blaming the library, read the ownership contract in
  `include/libfyaml/*.h`.
- An MSAN report whose frames leave libfyaml (glibc, BLAKE3 assembly) is
  almost certainly a false positive.
- The harness is not fully deterministic: there is a shared corpus document and
  a seeded allocator recipe. Replay 2-3 times before calling a crash
  unreproducible.

## 3. Build the reproducer

`fuzz2` is the harness without a fuzzing engine (`-DREPRODUCER`, harness at
`-O0`). Both reproducer builds live under `fuzzer/build/`:

| build | directory | binary |
|---|---|---|
| ASAN+UBSAN | `fuzzer/build/repro` | `fuzzer/build/repro/fuzz2` |
| MSAN (origins) | `fuzzer/build/repro-msan` | `fuzzer/build/repro-msan/fuzz2` |

After editing `main.c`, rebuild incrementally:

```
cmake --build fuzzer/build/repro --target fuzz2
cmake --build fuzzer/build/repro-msan --target fuzz2
```

Only when a directory is missing or its `CMakeCache.txt` does not match the
flags in `fuzzer/lib/build.sh`, configure it with `./fuzz build repro` or
`./fuzz build repro-msan`. Never create a build directory outside
`fuzzer/build/`.

- `repro` has `-DENABLE_ASAN=ON`, which instruments the library as well, not
  only the harness. Stack-overflow findings depend on the library's frame
  sizes.
- `repro-msan` instruments every translation unit through `CMAKE_C_FLAGS` and
  builds with libclang off: an uninstrumented libclang floods MSAN with false
  positives.
- `fuzzer/build/repro/fuzz2 <artifact>` replays a file directly, which is a
  quick first check.

## 4. RA: find the failing test case

At the bottom of `main.c`, inside `#if defined REPRODUCER` and before
`main()`, add the next free number (`RR` is identical to `RA`):

```c
/* reportN.md */
RA(n, "/absolute/path/to/artifact")
```

Rebuild, then run:

```
VERBOSE=1 fuzzer/build/repro/fuzz2 vc<n>
```

- stdout gets a ready-to-paste `RF(n, test_func, ...)` block, printed before the
  artifact runs through every test case. When piping, use `stdbuf -o0`, or the
  crash eats the buffered block.
- stderr gets `=== Running <test> ===` before each test case and a timing line
  after it. The last `Running` line with no timing line after it is the failing
  test case, and the `test_*` frame in the stack trace should agree.
- `TC=<test case>` runs only that test case. Use it to confirm the test case
  fails on its own. A `TC` left in the environment restricts every later run.
- If the crash needs two test cases in sequence (both touch the shared corpus
  document), wrap them in one static function and use that as `test_func`.
- If `VERBOSE` prints `allocation N failed (injected)`, the crash depends on an
  injected allocation failure (`flags_t.alloc_fail_nth`). The standalone
  reproducer then has to simulate that allocation failing.

## 5. RF: the reproducer

Paste the printed block under the `RA()`. Replace `test_func` with the failing
test case, and above it put the sanitizer that caught the bug in a few words,
then the `gh` command that files the issue (written once the report and its
title exist - see [report-template.md](report-template.md)):

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

## 6. Root cause

The report does not explain the bug, but you still need the cause: to pick the
public API calls for the standalone program, and to catch duplicates.

- For MSAN, trust the origin, not the crash frame. If the origin is also
  unhelpful (a hash state, a copy buffer), add
  `__msan_check_mem_is_initialized(ptr, len)` in a scratch copy of the tree,
  at the point where the data enters (for example right after
  `fy_token_get_text()`), and walk it back.
- `NDEBUG` changes behaviour. Without it, `fy-parse.c` defines
  `ATOM_SIZE_CHECK`, which recomputes scalar lengths and can hide a bug or move
  it elsewhere. Build the way the fuzzer did (RelWithDebInfo). Switch to Debug
  only if the bug fires only there, and say so in the compile line.
- Confirm on a clean upstream tree (this checkout carries fuzzing-only
  patches), built under `~/workspace`, not the scratchpad:
  ```
  git ls-remote https://github.com/pantoniou/libfyaml refs/heads/master
  git archive <commit> | tar -x -C <scratch dir>
  ```

## 7-8. Standalone program and report

Follow [report-template.md](report-template.md).
