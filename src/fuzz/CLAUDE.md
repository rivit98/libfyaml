# Crash triage — working notes

> The engine is AFL++ only (`fuzzer/`). libFuzzer is gone: no `-fork`, no
> `crash-<sha1>` artifacts, no `-max_len`/`-artifact_prefix`. Anything below
> that mentions libFuzzer is about *old* artifacts still on disk.

## 0. Where things are

| | |
|---|---|
| campaign tool | `fuzzer/a <command>` - run, status, triage, cmin, coverage |
| dependencies | `fuzzer/README.md`, Requirements - host and backend binaries |
| seeds | `fuzzer/seeds/<group>/` (checked in; `./a seeds --import DIR`) |
| campaign state | `../fuzz/libfyaml/{state/<group>,logs}` |
| crashes | `../fuzz/libfyaml/state/<group>/<instance>/crashes/id:*` |
| replay logs | `../fuzz/libfyaml/logs/<instance>_<input>.log` |
| builds | `fuzzer/build/{fast,asan,cmplog,msan,tsan,lsan,cov}/` |
| reproducer | `fuzzer/build/repro/fuzz2` + the `RR()`/`RF()` block at the bottom of `main.c` |

Backend is docker or a host AFL++ install; `FUZZ_BACKEND=auto` picks (local
AFL++ first, docker otherwise) and prepares it on first use. It only matters
when you run something by hand — force one with `FUZZ_BACKEND=docker`.

## 1. Replay and group

```
`./fuzzer/a triage`                 # new crashes only
`./fuzzer/a triage` --all --hangs   # everything, hangs too
```

`triage.sh` replays each input **with the build that found it** — a crash from
the `msan` instance means nothing under ASAN — and writes one log per input,
headed by `### instance: … build: … input: …`. It prints a signature histogram
at the end; that histogram is the grouping.

For the finer grouping the old workflow used:

```
uv run --directory ~/workspace/fuzzing/fuzzing-tools libfuzzer-parse ../fuzz/libfyaml/logs/
```

- still works: it parses sanitizer logs, not libFuzzer output. `best` per group
  = smallest artifact. Start there.
- `--json` for scripting, `--summary` for a quick look, `--prune` to drop
  non-reports and all but the 10 smallest per group.
- Every AFL artifact replays deterministically-ish; see §3 on stability.

## 2. Decide what is actually new

Do this BEFORE building a reproducer. A group is not new just because the top
frame differs.

- Cross-check every group against the `RR()`/`RF()` blocks at the bottom of
  `main.c` — each carries its `gh#NNN` and `reportN.md`.
- Same root cause, different call site, is a *duplicate with a note*, not a new
  issue. (Ex: the `fy_str_from_p()` bounds gap surfaces as a `strdup()`
  overread in one group and an `asprintf()` overread in another.)
- A fixed bug that still crashes is usually a *second* bug on the same input:
  after gh#343 fixed the signature walk, the same 10KB input went on to
  overflow the stack in `fy_generic_dump_primitive()`. Check the frames, not
  the artifact name.
- Ask the user which groups they consider new; they usually already know.

## 3. Is it the library, the harness, or the sanitizer?

Cheapest question to answer, and it saves a whole report.

- Look at the sanitizer *allocation* frame, not the crash frame. Allocated in
  `main.c` / `fuzz_utils.h` → suspect the harness first.
- Known harness-side signatures live in the `harness-side-leak-artifacts`
  memory. Check it before writing anything up.
- A UAF where the free is in one test case and the read in another is NOT
  automatically harness fault — it can be the library holding a pointer into
  caller memory across an API boundary. Establish which by reading the
  ownership contract in `include/libfyaml/*.h`.
- Per-lane caveats:
  - **msan** — built with `-DENABLE_LIBCLANG=OFF` because an uninstrumented
    libclang is a false-positive farm. A report whose frames leave libfyaml
    (glibc, libclang, the BLAKE3 asm) is almost certainly a false positive.
  - **tsan** — libfyaml's thread pool is the interesting target; a race whose
    two stacks are both inside the harness is harness-side.
  - **lsan** — `__AFL_LEAK_CHECK()` in `LLVMFuzzerTestOneInput()` exits 23 on a
    leak, so leaks are per-input again. Most historical leak findings here were
    the harness not freeing caller-owned buffers — check the memory first.
- Stability on this harness sits at **75–80 %** (nine test cases per exec, a
  per-process corpus fixture, a randomly chosen allocator recipe). A crash that
  does not reproduce on the first replay is not automatically bogus; replay it
  two or three times before discarding it.

## 4. Reproduce

Two levels; do both.

**Straight replay** (the first thing to try — no macros, no rebuild):
```
./fuzzer/build/repro/fuzz2 <artifact>
```
`fuzz2` has no fuzzing engine and is built with asan+ubsan, so one input file
through it is usually all a reproducer needs. It takes files only, one per
argument; a directory is refused.

**In-harness** (when you want the `RF()` text, or the crash needs a specific
test case):
1. `RR(n, ARTIFACTS "<file>")` in the `#if defined REPRODUCER` block. `ARTIFACTS`
   points at the old artifact dir — for an AFL crash, give the full path to
   `../fuzz/libfyaml/state/<instance>/crashes/id:...`.
2. Build it (`./fuzzer/a build repro`), run `stdbuf -o0 ./fuzzer/build/repro/fuzz2 vc<n>` — pipe
   through `stdbuf` or the harvested text is swallowed by stdio buffering.
3. Paste the printed `RF(n, ...)` back, replacing `test_func` with the failing
   test case. `./fuzzer/build/repro/fuzz2 tc<n>` then replays with no artifact file.
4. `TC=<group>` restricts to one test group (`test_yaml`, `test_path`,
   `test_scanf`, `test_blob`, `test_meta` - the group functions at the bottom
   of `main.c`), `VERBOSE=1` names them as they run.
   Careful: a `TC=` left in the environment silently restricts every later run —
   `triage.sh` and `coverage.sh` clear it, a manual `./fuzzer/build/repro/fuzz2` does not.
5. Crash needs two test cases in sequence (shared corpus state)? Wrap them in a
   small static function and point `RF()` at that.
6. Stack-overflow findings are stack-limit sensitive: `fuzz2` is `-O0`, so it
   overflows at a *different* depth than the campaign binary. Reproduce under
   `(ulimit -s 8192; ./fuzzer/build/repro/fuzz2 tc<n>)` — the default 8 MB is what the
   report should assume.

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
- For an msan/tsan finding build the standalone repro with that sanitizer
  instead (`-fsanitize=memory -fsanitize-memory-track-origins=2`,
  `-fsanitize=thread`), and say so in the report.

## 5. Find the root cause before writing

The report is worth much more with a mechanism than with a stack trace.

- Decode the input against the parsing code — for a binary blob, hand-decode
  the header fields and confirm the arithmetic matches ASAN's "N bytes after
  M-byte region". If it doesn't, you don't understand the bug yet.
- Look for the guard that should have caught it. `assert()` under `NDEBUG` is
  the recurring one in this codebase.
- Note when a fix that only patches the crashing call site leaves siblings open.
- `./fuzzer/a coverage` answers "did the fuzzer even reach this?" — AFL++'s
  `cov-analysis` over the `cov` build. `gaps.txt` in the report ranks uncovered
  regions by size, and `--search src/lib/fy-parse.c:1234` names the corpus
  entries that reach a line. Nothing is filtered by default; `--ignore
  '(src/fuzz/|src/blake3/|src/xxhash/)'` drops the harness and vendored code.
  `--edges` is the AFL-only metric and needs no coverage build.

## 6. Write it up

- Follow `report1.md`'s shape: greeting → `## Code version` (upstream commit,
  not the local fuzzer commit) → mechanism → `## How to reproduce` + C → the
  sanitizer output.
- Trim the pasted report: drop BuildId lines, absolute scratch paths, and the
  shadow-byte block. Keep the frames that name library source. For a deep
  recursion, keep a few frames and write
  `[ ... frame N repeats to the end of the stack ... ]`.
- One issue per file, `reportN.md`, next free N — old numbers stay claimed by
  the `RR()` comments even after the file is deleted.
- Title format: `<area>: <what breaks> <when>`.
- Suggest the fix only when the codebase shows the intended mechanism already
  exists (e.g. an unused `_copy()` helper). Otherwise describe, don't prescribe.
- File with `gh issue create --repo pantoniou/libfyaml --title "..." --body-file reportN.md`.

## 7. Leave the repo triage-ready

- Every reported group has an `RR()` + `RF()` pair with a `gh#NNN reportN.md`
  comment.
- When upstream fixes one, verify with `(ulimit -s 8192; ./fuzzer/build/repro/fuzz2 tc<n>)`
  and delete the stale `RR()`/`RF()` group — a `tc<n>` that passes is not a
  test, it is noise. Keep only the open findings.
- After a long campaign: `./fuzzer/a cmin`, then start the next one from
  `corpus.cmin`. Crash inputs are never minimized.
