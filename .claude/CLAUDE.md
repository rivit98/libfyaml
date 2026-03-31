# Crash triage

You get a fuzzer **artifact** and the **sanitizer log** from replaying it. You
produce three things:

1. an `RA()` entry in `main.c`, to find the test case that fails
2. an `RF()` entry in `main.c`, a self-contained reproducer inside the harness
3. `reportN.md`, a report ready to submit upstream

## 1. Read the log

- Header lines: `### artifact :` is the input file, `### variant :` is the
  build that crashed: `asan` (ASAN+UBSAN), `msan`, `lsan` (leaks), or `fast`
  (no sanitizer: SEGV or abort only). The `SUMMARY:` line gives the bug class
  and the top frame.
- Pick the reproducer build: `msan` → MSAN, anything else → ASAN.
- The first 4 bytes of an artifact are a little-endian `uint32` seed.
  `setup_flags()` expands it into `struct flags_t`, and the test cases receive
  the bytes after it.
- The log's MSAN build has no origin tracking, and its frames can point far
  from the cause. The MSAN reproducer below tracks origins.

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
`-O0`). `build*/` directories are git-ignored; after editing `main.c`, rebuild
incrementally.

ASAN+UBSAN:
```
cmake -S . -B build-repro -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
      -DCMAKE_BUILD_TYPE=RelWithDebInfo -DBUILD_TESTING=OFF -DENABLE_NETWORK=OFF \
      -DENABLE_PYTHON_BINDINGS=OFF -DENABLE_ASAN=ON
cmake --build build-repro --target fuzz2
```

MSAN:
```
cmake -S . -B build-repro-msan -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
      -DCMAKE_BUILD_TYPE=RelWithDebInfo -DBUILD_TESTING=OFF -DENABLE_NETWORK=OFF \
      -DENABLE_PYTHON_BINDINGS=OFF -DENABLE_LIBCLANG=OFF -DFUZZ_REPRO_SANITIZER=memory \
      -DCMAKE_C_FLAGS="-fsanitize=memory -fsanitize-memory-track-origins=2 -fno-omit-frame-pointer"
cmake --build build-repro-msan --target fuzz2
```

- `-DENABLE_ASAN=ON` instruments the library as well, not only the harness.
  Stack-overflow findings depend on the library's frame sizes.
- MSAN needs every translation unit instrumented, which is why the flags go in
  `CMAKE_C_FLAGS`. It also needs libclang off: an uninstrumented libclang
  floods MSAN with false positives.
- `build-repro/fuzz2 <artifact>` replays a file directly, which is a quick
  first check.

## 4. RA: find the failing test case

At the bottom of `main.c`, inside `#if defined REPRODUCER` and before
`main()`, add the next free number (`RR` is identical to `RA`):

```c
/* reportN.md */
RA(n, "/absolute/path/to/artifact")
```

Rebuild, then run:

```
VERBOSE=1 build-repro/fuzz2 vc<n>
```

- stdout gets a ready-to-paste `RF(n, test_func, ...)` block, printed before the
  artifact runs through every test case.
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
then the `gh` command that files the issue (see the end of §8 - write it once
the report and its title exist):

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

Once the issue is filed, that comment is replaced by the issue URL, the way
`RF(n)` carries one.

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
- This checkout carries fuzzing-only patches in the library (for example
  version-number parsing in `fy-parse.c`). Always confirm on a clean upstream
  tree:
  ```
  git ls-remote https://github.com/pantoniou/libfyaml refs/heads/master
  git archive <commit> | tar -x -C <scratch dir>
  ```

## 7. The standalone program

- Public API only: `#include <libfyaml.h>`, no harness headers, no `flags_t`.
  Pass the parse or emit flags the crash actually needs, spelled out.
- Keep the original input bytes and do not minimize: minimizers drift to other
  bugs. The whole program lives in `main()`. Write a small input as an inline
  array; build a large one in a `static unsigned char buf[N]` inside `main()`
  with `memcpy()` for literal stretches and `memset()` for runs.
- Build it on the clean upstream tree with exactly the commands that go into
  the report, and take the output from that run.

## 8. The report

`reportN.md` at the repository root, next free N: check existing `report*.md`
files and the `reportN.md` comments in `main.c`. One issue per file.

It contains exactly these parts and nothing else. No description, no analysis,
no suggested fix:

````markdown
Hi, I found the following problem while fuzzing libfyaml.

## Code version
`<full upstream commit hash>`

## How to reproduce
```c
<standalone program>
```

Compile with <AddressSanitizer | MemorySanitizer | UndefinedBehaviorSanitizer> and run:
```
<library build commands>
<reproducer compile command>
./repro
```

## Output
```
<sanitizer output>
```
````

Compile commands, run from the libfyaml source root:

- **ASAN**, also for UBSAN findings and leaks:
  ```
  cmake -S . -B build-asan -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
        -DCMAKE_BUILD_TYPE=RelWithDebInfo -DENABLE_ASAN=ON
  cmake --build build-asan --target fyaml
  clang -g -O0 -fsanitize=address,undefined -fno-omit-frame-pointer \
        -I include -o repro repro.c -L build-asan -lfyaml -Wl,-rpath,$PWD/build-asan
  ```
- **MSAN**:
  ```
  cmake -S . -B build-msan -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
        -DENABLE_LIBCLANG=OFF -DCMAKE_BUILD_TYPE=RelWithDebInfo \
        -DCMAKE_C_FLAGS="-fsanitize=memory -fsanitize-memory-track-origins=2 -fno-omit-frame-pointer" \
        -DCMAKE_CXX_FLAGS=-fsanitize=memory \
        -DCMAKE_SHARED_LINKER_FLAGS=-fsanitize=memory -DCMAKE_EXE_LINKER_FLAGS=-fsanitize=memory
  cmake --build build-msan --target fyaml
  clang -g -O0 -fsanitize=memory -fsanitize-memory-track-origins=2 -fno-omit-frame-pointer \
        -I include -I build-msan -o repro repro.c -L build-msan -lfyaml -Wl,-rpath,$PWD/build-msan
  ```

Trimming the output:

- Drop `BuildId`, the `0x...` addresses in frames, the shadow-byte block, and
  the `__libc_start_*` / `_start` frames.
- Make paths relative to the libfyaml source root.
- Keep the frames that name library source.
- For deep recursion, keep a few frames and write
  `[ ... frame N repeats to the end of the stack ... ]`.

The issue title does not go in the file. Suggest one in your reply, in the form
`<area>: <what breaks> <when>`, and put the command that files the issue with
it above the `RF()` in `main.c`, as a comment - always, for every report:

```c
// gh issue create --repo pantoniou/libfyaml --body-file reportN.md --title "<area>: <what breaks> <when>"
```

Do not run it. Filing is the user's call; the comment is there so they can
paste it. `--repo pantoniou/libfyaml` is spelled out because `origin` is
upstream but a `fork` remote also exists - never let `gh` guess the repo.

## 9. Housekeeping

- Every reported bug keeps its `RA()` + `RF()` pair in `main.c`, with either
  the `gh issue create` comment or the issue URL above the `RF()`.
- Once upstream fixes it, confirm that `tc<n>` passes, then delete the pair. A
  passing `tc<n>` is noise, not a test.
