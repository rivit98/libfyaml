# Crash triage — working notes

> SKETCH. Section skeleton + what I know so far. TODOs mark what still needs
> filling in from real sessions.

## 1. Parse the run

```
uv run --directory ~/workspace/fuzzing/fuzzing-tools libfuzzer-parse <fuzz-dir>/logs/
```

- Groups logs by crash signature; `best` per group = smallest artifact. Start there.
- `--json` for scripting, `--summary` for a quick look, `--prune` to drop
  non-reports and all but the 10 smallest per group.
- Two fuzzers feed the same artifact dir: `id:*` = AFL++ (replay reproduces),
  `crash-<sha1>` = libFuzzer `-fork` (usually does NOT — see §6).

## 2. Decide what is actually new

Do this BEFORE building a reproducer. A group is not new just because the top
frame differs.

- Cross-check every group against the `RR()`/`RF()` blocks at the bottom of
  `main.c` — each carries its `gh#NNN` and `reportN.md`.
- Same root cause, different call site, is a *duplicate with a note*, not a new
  issue. (Ex: the `fy_str_from_p()` bounds gap surfaces as a `strdup()`
  overread in one group and an `asprintf()` overread in another.)
- Ask the user which groups they consider new; they usually already know.
- TODO: keep a checked-in duplicates table so this stops being from memory.

## 3. Is it the library or the harness?

Cheapest question to answer, and it saves a whole report.

- Look at the ASAN *allocation* frame, not the crash frame. Allocated in
  `main.c` / `fuzz_utils.h` → suspect the harness first.
- Known harness-side signatures live in the `harness-side-leak-artifacts`
  memory. Check it before writing anything up.
- A UAF where the free is in one test case and the read in another is NOT
  automatically harness fault — it can be the library holding a pointer into
  caller memory across an API boundary. Establish which by reading the
  ownership contract in `include/libfyaml/*.h`.
- TODO: list the harness's known ownership shortcuts in one place.

## 4. Reproduce

Two levels; do both.

**In-harness** (fast, proves the artifact):
1. `RR(n, ARTIFACTS "<file>")` in the `#if defined REPRODUCER` block.
2. Build `fuzz2`, run `stdbuf -o0 ./build/fuzz2 vc<n>` — pipe through `stdbuf`
   or the harvested text is swallowed by stdio buffering.
3. Paste the printed `RF(n, ...)` back, replacing `test_func` with the failing
   test case. `./build/fuzz2 tc<n>` then replays with no artifact file.
4. `TC=<name>` restricts to one test case, `VERBOSE=1` names them as they run.
5. Crash needs two test cases in sequence (shared corpus state)? Wrap them in a
   small static function and point `RF()` at that.

**Standalone** (what actually goes in the report):
```
clang -g -O0 -fsanitize=address,undefined -fno-omit-frame-pointer \
      -I include -I build -o repro repro.c -L build -lfyaml -Wl,-rpath,$PWD/build
```
- Public API only, no harness headers. If it can't be expressed in public API,
  say so in the report.
- Do NOT minimize the input (see the `no-input-minimization` memory). Keep the
  original bytes; make big blobs readable with `memcpy`/`memset`, or an inline
  `unsigned char[]` when small.

## 5. Find the root cause before writing

The report is worth much more with a mechanism than with a stack trace.

- Decode the input against the parsing code — for a binary blob, hand-decode
  the header fields and confirm the arithmetic matches ASAN's "N bytes after
  M-byte region". If it doesn't, you don't understand the bug yet.
- Look for the guard that should have caught it. `assert()` under `NDEBUG` is
  the recurring one in this codebase.
- Note when a fix that only patches the crashing call site leaves siblings open.
- TODO: recurring root-cause patterns in libfyaml (assert-as-validation,
  refcounted-state mutation, tokens outliving non-copying inputs).

## 6. libFuzzer fork-mode artifacts

Parent log keeps only the `==pid==ERROR:` header. To recover the child report:
```
TMPDIR=<dir> ASAN_OPTIONS=log_path=<dir>/asan ./build/fuzz -fork=3 corpus
```
Details in the `libfuzzer-fork-mode-logs` memory.

## 7. Write it up

- Follow `report1.md`'s shape: greeting → `## Code version` (upstream commit,
  not the local fuzzer commit) → mechanism → `## How to reproduce` + C → the
  ASAN output.
- Trim the pasted ASAN: drop BuildId lines, absolute scratch paths, and the
  shadow-byte block. Keep the frames that name library source.
- One issue per file, `reportN.md`, next free N — old numbers stay claimed by
  the `RR()` comments even after the file is deleted.
- Title format: `<area>: <what breaks> <when>`.
- Suggest the fix only when the codebase shows the intended mechanism already
  exists (e.g. an unused `_copy()` helper). Otherwise describe, don't prescribe.

## 8. Leave the repo triage-ready

- Every reported group has an `RR()` + `RF()` pair with a `gh#NNN reportN.md`
  comment.
- TODO: decide whether reproduced-and-fixed cases get promoted into the real
  test suite, and where.
