# Standalone program and report

## 7. The standalone program

Start from the failing test case, not from scratch. Work in the scratchpad.
The reproducer is a **modification of the original `test_*` function**: copy it
and cut it down until only the calls the crash needs remain. Do not read the
library to decide what to keep; remove a call, rebuild, and keep the removal if
the `SUMMARY` line is unchanged. When the harness wraps a public API in a
different set-up (an allocator recipe, builder flags), keep the set-up too,
and check each dropped flag by running it - a flag that looks irrelevant (an
`auto` per-obj-free allocator, `FYOPPF_COLLECT_DIAG`) often is the trigger.

1. **Copy** the test case function from `src/fuzz/main.c`, plus the static
   helpers it calls, into `main()` of `repro.c`.
2. **Inline the harness away.** Every `flags->x` becomes the literal value
   from the `RF()` (spelled-out flag names). `CHECK(c)` becomes
   `if (!(c)) return 1;`. `USE(x)` becomes a plain call. The data becomes
   declarations from the helper:
   ```
   uv run --no-project python -I .claude/skills/triage-crash/scripts/rf_data.py src/fuzz/main.c <n>
   ```
   `--reflection` splits a `test_reflection_*` input the way the harness does:
   `blob[]`, `entry[]`, `meta[]` and `yaml[]` (see `report3.md` - `report10.md`
   for the shape that follows).
3. **Minimize a little, the code only.** Drop one call or set one flag set to
   0, rebuild, rerun; keep the change only if the `SUMMARY` line is unchanged.
   Typical removals: introspection loops, the emit step, parse flags.
   Never change the input bytes: minimizers drift to other bugs. A large input
   goes in a `static unsigned char buf[N]` filled with `memcpy()` for literal
   stretches and `memset()` for runs.
4. **Allocation failure** (`alloc_fail_nth` mattered, SKILL.md §6): link the
   static library with `-Wl,--wrap=malloc` and fail one counted call around
   the API call that crashes. Scan the count (a loop over a `fail_at` from
   `argv[1]`) for one that reproduces, then hard-code it:
   ```c
   void *__real_malloc(size_t size);
   static long fail_at = -1;   /* armed: the fail_at-th malloc() fails */

   void *__wrap_malloc(size_t size)
   {
   	if (fail_at > 0 && --fail_at == 0)
   		return NULL;
   	return __real_malloc(size);
   }
   ```
   `report8.md` is the worked example.

Public API only in the result: `#include <libfyaml.h>` (and
`<libfyaml/libfyaml-reflection.h>` etc.), no harness headers, no `flags_t`.

Build and run it against this checkout's reproducer library, never the stale
`libfyaml.so`:

```
L=<repo root>
clang -g -O0 -fsanitize=address,undefined -fno-omit-frame-pointer \
      -I $L/include -o repro repro.c $L/fuzzer/build/repro/libfyaml.a -lm
clang -g -O0 -fsanitize=memory -fsanitize-memory-track-origins=2 -fno-omit-frame-pointer \
      -I $L/include -I $L/fuzzer/build/repro-msan -o repro repro.c \
      $L/fuzzer/build/repro-msan/libfyaml.a -lm
```

These libraries are built with the same flags as the report's compile
commands below, so the output of this run is the report's output. Run UBSAN
findings with `UBSAN_OPTIONS=print_stacktrace=1` and put that in the report's
run line too.

## 8. The report

`reportN.md` at the repository root, next free N: check existing `report*.md`
files and the `reportN.md` comments in `src/fuzz/main.c`. One issue per file.

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

The code version is `git merge-base HEAD origin/master` - the upstream commit
this checkout is built from (SKILL.md §3).

Compile commands as the reader runs them, from the root of an upstream tree.
These `build-asan` / `build-msan` directories belong to the report, not to
this checkout:

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
- **Allocation failure** (`--wrap=malloc` cannot reach a shared library):
  build `--target fyaml_static` instead of `fyaml`, and link
  `build-asan/libfyaml.a -lm -Wl,--wrap=malloc` in place of
  `-L build-asan -lfyaml -Wl,-rpath,...`.

Trimming the output:

- Drop `BuildId`, the `0x...` addresses in frames, the shadow-byte block, and
  the `__libc_start_*` / `_start` frames.
- Make paths relative to the libfyaml source root.
- Keep the frames that name library source.
- For deep recursion, keep a few frames and write
  `[ ... frame N repeats to the end of the stack ... ]`.

## Title and the gh command

The issue title does not go in the file. Suggest one in your reply, in the form
`<area>: <what breaks> <when>`, and put the command that files the issue above
the `RF()` in `main.c`, as a comment - always, for every report:

```c
// gh issue create --repo pantoniou/libfyaml --body-file reportN.md --title "<area>: <what breaks> <when>"
```

Do not run it. Once the user files the issue, the comment is replaced by the
issue URL.
