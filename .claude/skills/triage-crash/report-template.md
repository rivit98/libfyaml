# Standalone program and report

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

Compile commands, run from the root of the clean upstream tree. These
`build-asan` / `build-msan` directories belong to that tree and to the report,
not to this checkout:

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

## Title and the gh command

The issue title does not go in the file. Suggest one in your reply, in the form
`<area>: <what breaks> <when>`, and put the command that files the issue above
the `RF()` in `main.c`, as a comment - always, for every report:

```c
// gh issue create --repo pantoniou/libfyaml --body-file reportN.md --title "<area>: <what breaks> <when>"
```

Do not run it. Once the user files the issue, the comment is replaced by the
issue URL.
