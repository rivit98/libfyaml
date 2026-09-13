# AFL++ campaign for libfyaml

One entry point, `./a`, drives everything: builds, seeds, the campaign, triage
and coverage. AFL++ is the only fuzzing engine in the repo — libFuzzer is gone,
and the two engine-free binaries (`fuzz2`, `fuzz_cov`) get their `main()` from
the harness itself.

```bash
cd fuzzer
./a build                        # every variant; ./a build fast for one
./a run                          # start the campaign and attach
```

## Requirements

Nothing checks for these up front: a missing binary reports itself when the
command that needs it runs.

**On the host, whatever the backend** — what the `./a` scripts run themselves:

| binary | needed by |
|---|---|
| `bash` 4.3+ | every command (`wait -n`, `mapfile`) |
| `tmux` | `run`, `stop` |
| `lscpu` | every command: one instance per physical core |
| `awk`, `df` | `status` |
| `nproc` | `triage` |
| `docker` | `FUZZ_BACKEND=docker`, `clean containers` — the daemon reachable without sudo |
| `taskset`, `pgrep`, `pkill` | `FUZZ_BACKEND=host`: core pinning, `status`, `stop` |

**In the backend** — on `PATH` (or `$AFL_PATH`) for `host`, inside
`aflplusplus/aflplusplus:stable` for `docker`:

| binary | needed by | notes |
|---|---|---|
| `afl-fuzz` | `run` | |
| `afl-cc`, `afl-clang-fast` | `build` | plus `afl-clang-lto` when `afl-cc -h` reports LTO available |
| `afl-showmap`, `afl-cmin` | `seeds`, `cmin`, `coverage --edges` | |
| `afl-tmin` | `cmin --tmin` | |
| `afl-whatsup` | `status` | optional summary at the bottom |
| `cmake`, `make` | `build` | |
| `clang` | `build` | `cov` and `repro` are plain clang |
| `llvm-ar`, `llvm-ranlib` | `build`, LTO mode | optional; only the bare names are looked up |
| `timeout` | `triage` | |
| `cov-analysis` | `coverage` | in the docker image; usually not on a host |
| `llvm-profdata`, `llvm-cov` | `coverage` | must match `clang`'s major version; `-NN` names are found |
| `gawk` | `coverage --stability` | not in the docker image |
| `llvm-symbolizer` | `triage`: symbolized frames | the sanitizers look up the bare name only — a versioned-only install (`llvm-symbolizer-NN`, the docker image's included) leaves raw addresses unless it is symlinked or `ASAN_SYMBOLIZER_PATH` is set |

## Commands

`./a help` lists them; every command takes its options as flags, everything
that varies between campaigns is an environment variable.

### `build [--clean] [<variant>...]`

| | |
|---|---|
| *(no args)* | every variant: `fast asan cmplog msan tsan lsan laf sand-asan sand-msan cov repro` |
| `<variant>...` | only these, e.g. `./a build sand-msan` |
| `--clean` | wipe `fuzzer/build/` first (also how you switch backends) |

Variant names are checked before anything builds. A variant that fails does
not stop the rest; the run ends with a summary — each variant `built` (time,
size, binary) or `FAILED` (time, exit status, log) — and exits non-zero if
anything failed. Each build tees its full output to
`fuzzer/build/<variant>/build.log`.

### `seeds [--import DIR] [--cmin] [--group <group>]`

| | |
|---|---|
| *(no args)* | list what each group holds |
| `--import DIR` | add `DIR`'s files to a group's seeds (needs `--group`) |
| `--cmin` | re-minimize the checked-in seeds in place |
| `--group <g>` | restrict either action to one group |

### `run`

No options — `JOBS`, `FUZZ_PLAN`, `FUZZ_GROUP` and `TC` come from the
environment. Starts one instance per physical core in tmux, laid out by a plan
(see [The instance mix](#the-instance-mix)), and attaches; window 0 is the dashboard.
Detach with `C-b d`, the campaign keeps running.

Each instance tab shows AFL's own status screen, repainted in place
(`AFL_FORCE_UI=1` — without it the pipe into the log would put afl-fuzz in its
non-tty mode, one scrolling line per fuzzed queue entry). `$LOG_DIR/<instance>.log`
gets only the message lines — startup, warnings, aborts, the closing summary —
so it stays a few dozen KB instead of half a megabyte a minute. Per-second
numbers live in `$OUT_DIR/<instance>/{fuzzer_stats,plot_data}`, which is what
`./a status` reads.

### `status [--loop] [--json]`

| | |
|---|---|
| *(no args)* | print the table once |
| `--loop` | refresh every `$REFRESH` seconds (default 15) |
| `--json` | per-instance stats for scripting |

### `stop [--keep-tmux] [--force]`

SIGINT every instance (so the primary flushes its `AFL_FINAL_SYNC` import),
then drop the session. `--keep-tmux` leaves the windows for reading,
`--force` SIGKILLs whatever is still alive.

### `triage [--all] [--hangs] [--with v1,v2] [--input FILE] [--timeout S]`

Replays saved artifacts through **every built variant** and writes one log per
(artifact, variant) into `$LOG_DIR`. Nothing else — reading the logs is
`src/fuzz/CLAUDE.md`'s job.

| | |
|---|---|
| *(no args)* | every crash, every runnable variant, new logs only |
| `--all` | re-replay artifacts that already have logs |
| `--hangs` | hangs instead of crashes |
| `--with a,b` | only these variants |
| `--input FILE` | one artifact, from anywhere |
| `--timeout S` | per-replay wall clock, default 120 s |

Runs `$(nproc)` replays at a time. `cmplog`, `cov`, `laf` and the `sand-*`
oracles are never replayed: `cmplog` exists for `afl-fuzz -c`, `cov` and `laf`
have no sanitizer, and the oracles are `asan`/`msan` without an edge map.

### `cmin [--tmin]`

`afl-cmin` over every instance queue into `$CMIN_DIR`, for the next campaign's
seeds. `--tmin` also shrinks each survivor (slow, rarely worth it). Crash
inputs are never minimized.

### `coverage [--corpus DIR] [--ignore REGEX] [--edges|--stability|--search FILE:LINE]`

| | |
|---|---|
| *(no args)* | `cov-analysis` report over the campaign queue |
| `--corpus DIR` | measure some other corpus |
| `--ignore REGEX` | drop matching files from the report (off by default) |
| `--edges` | `afl-showmap -C`: AFL-only edge coverage, no `cov` build needed |
| `--stability` | per-line non-deterministic hit counts (needs gawk) |
| `--search FILE:LINE` | which corpus entries reach that line |

### `clean [--all] [<target>...]`

| | |
|---|---|
| *(no args)* | `builds logs coverage containers` — what is safe to lose |
| `--all` | those plus `state` and `crashes` |
| `<target>...` | exactly these |

`state` and `crashes` are never in the default set, and the command refuses to
touch them while a campaign is running. Seeds are not a target at all.

## Environment

| | |
|---|---|
| `FUZZ_BACKEND` | `auto` (default), `docker`, `host` |
| `FUZZ_GROUP` | seed group and campaign identity: `yaml` (default), `path`, `scanf`, `blob`, `meta` |
| `TC` | restrict every instance to one group or one test case |
| `JOBS` | instances (default: one per physical core) |
| `FUZZ_PLAN` | `auto` (default: the smallest plan with at least `JOBS` lanes), `8`, `16`, `32`, or a path |
| `FUZZ_DIR` | campaign state root (default `../fuzz/libfyaml`) |
| `SEED_ROOT` | seed corpora root (default `fuzzer/seeds`) |
| `FUZZ_CC_MODE` | `lto` or `fast`, forcing afl-cc's instrumentation mode |
| `FUZZ_MAX_LEN` | `-G`, max input length (default 10000) |
| `REFRESH` | dashboard refresh seconds |

Every knob this project invents is `FUZZ_*`, never `AFL_*`: afl-cc warns about
`AFL_*` names it does not know, and that warning should stay meaningful.

## Backends

| `FUZZ_BACKEND` | what runs AFL | paths |
|---|---|---|
| `host` | a system install, or `$AFL_PATH` | the host's own; pinning via `taskset` |
| `docker` | `aflplusplus/aflplusplus:stable` | `$REPO_DIR -> /repo`, `$FUZZ_DIR -> /fuzz`; pinning via `--cpuset-cpus` |
| `auto` | host if `afl-fuzz` is there, else docker | |

Nothing has to be installed or pulled by hand: the image is pulled the first
time a command needs it. Binaries are produced by the same backend that runs
them, so clang, the instrumentation pass and libc never disagree — switching
backends means `./a build --clean`.

## Layout

```
fuzzer/
├── a              the entry point: ./a <command> [options]
├── seeds/         the seed corpora, one directory per group (checked in)
├── plans/         instance plans: 8.plan, 16.plan, 32.plan
└── lib/
    ├── common.sh    configuration, logging, backend plumbing (sourced first)
    ├── build.sh     the build variants
    ├── seeds.sh     seed corpora: list, import, minimize
    ├── run.sh       the tmux campaign (window 0 = health, 1..N = instances)
    ├── status.sh    dashboard + health checks
    ├── stop.sh      SIGINT every instance, drop the session
    ├── triage.sh    replay artifacts through every built variant
    ├── cmin.sh      minimize the queue for the next campaign
    ├── clean.sh     remove builds/logs/coverage/state/crashes
    └── coverage.sh  cov-analysis report / edges / stability / search
```

Command files are sourced by `a`, not exec'd, so they share one configuration
and one logger. Campaign *state* lives outside the repo, so a `git clean` never
eats a running campaign: `../fuzz/libfyaml/{state/<group>,logs,cov}`.

## The builds

| build | flags | used for |
|---|---|---|
| `fast` | plain afl-cc | every throughput lane; catches SEGV/abort |
| `asan` | `AFL_USE_ASAN=1 AFL_USE_UBSAN=1` | the lane that classifies memory bugs. `AFL_USE_UBSAN` implies `-fno-sanitize-recover=undefined`, so a UBSAN report becomes a saved crash |
| `cmplog` | `AFL_LLVM_CMPLOG=1` | passed to `afl-fuzz -c`, never fuzzed directly |
| `msan` | `AFL_USE_MSAN=1`, `-DENABLE_LIBCLANG=OFF` | uninitialized reads, for triage — the plans get MSAN from `sand-msan`. libclang is dropped: an uninstrumented dependency under MSAN is a false-positive farm |
| `tsan` | `AFL_USE_TSAN=1` | data races (`fy_thread_pool`, the allocators) |
| `lsan` | `AFL_USE_LSAN=1` | per-input leaks via `__AFL_LEAK_CHECK()` |
| `laf` | `AFL_LLVM_LAF_ALL=1` | laf-intel lanes: multi-byte compares split into byte compares, so a partial keyword match registers as coverage |
| `sand-asan` | `AFL_USE_ASAN=1 AFL_USE_UBSAN=1 AFL_LLVM_ONLY_FSRV=1` | SAND oracle for `afl-fuzz -w`: sanitizers and a fork server, no edge map (`afl-showmap`: 0 tuples) |
| `sand-msan` | `AFL_USE_MSAN=1 AFL_LLVM_ONLY_FSRV=1`, `-DENABLE_LIBCLANG=OFF` | SAND MSAN oracle; `afl-clang-fast`, like `msan` |
| `cov` | `-fprofile-instr-generate`, plain clang | `fuzz_cov` for `./a coverage` |
| `repro` | `-O0`, asan+ubsan, plain clang, `-DENABLE_ASAN=ON` | `fuzz2`: the `RR()`/`RF()` reproducer |
**Which compiler each build uses**, and why it is not uniform:

* every `fuzz` variant is built by **afl-cc** — `afl-clang-lto` when afl-cc
  reports LTO available (collision-free edge IDs), else `afl-clang-fast`.
  `afl-clang-lto -v` prints "clang version …" because it *is* a clang wrapper;
  verify instrumentation with `nm build/<variant>/fuzz | grep -c __afl_` (≈130)
  or `afl-showmap … -- build/<variant>/fuzz <input>` (≈3200 tuples here).
* **`cov` and `repro` are deliberately plain clang** — instrumenting the
  coverage binary would measure AFL's counters instead of the library, and the
  reproducer has no use for edge counters.
* **`msan` is pinned to `afl-clang-fast`**: in LTO mode the binary links but its
  fork server dies with SIGSEGV on the first exec.
* **`lsan` compiles the BLAKE3 `.S` files with plain clang** — afl-cc
  force-includes `<sanitizer/lsan_interface.h>` into every TU under
  `AFL_USE_LSAN`, and hand-written assembly cannot parse a C header. Assembly
  is never instrumented by any AFL mode, so nothing is lost.
* **`repro` needs `-DENABLE_ASAN=ON`** so the *library* is instrumented too; an
  uninstrumented library has much smaller stack frames, which hides the
  stack-overflow findings entirely.
## Seed groups

The harness groups its test cases by the shape of input they consume, and the
group is itself a test case, so `TC=` selects one. Each group has its own
seeds, campaign state, tmux session and container prefix (`FUZZ_GROUP`).

| group | `TC=` | feeds | input | seeds |
|---|---|---|---|---|
| `yaml` | `test_yaml` | `parse_with_flags`, `parser_checkpoint_rollback`, `fy_parser_parse_fp`, `generic_document_builder` | a YAML/JSON document | 432 |
| `path` | `test_path` | `parse_path`, `fy_path_expr_build_from_string` | a path / ypath expression | 12 |
| `scanf` | `test_scanf` | `document_scanf` | a `fy_document_scanf()` format | 7 |
| `blob` | `test_blob` | `reflection_packed_blob` | a packed `FYPG` blob | see `./a seeds` |
| `meta` | `test_meta` | `reflection_type_context_entry_meta` | meta doc `\n` YAML doc | 7 |

`TC=` also accepts an individual test case name, which runs that one inside its
group. **Without `TC` every group runs on every input** — broader, but it pays:

| | execs/sec | stability | bitmap_cvg |
|---|---|---|---|
| no `TC` (all five groups) | 2597 | **80.5 %** | 22.9 % |
| `TC=test_yaml` | 2988 | **98.6 %** | 20.4 % |

Feeding one input to five unrelated groups is most of what made this harness
non-deterministic, and a crash found at 80 % stability may not replay. So:

```bash
FUZZ_GROUP=path TC=test_path ./a run
```

`TC` reaches the instances explicitly — the backends deliberately do not
inherit it, because a stray `TC` in a shell silently restricts a whole campaign.

Seeds are **checked in** under `fuzzer/seeds/<group>/`: they are an input to a
campaign, not an artifact of it. Adding material:

```bash
./a seeds --import ~/yaml-corpus --group yaml   # prefix, add, minimize
./a seeds --cmin --group path                   # re-minimize in place
```

`--import` adds the harness's 4-byte flag prefix (three variants per file) and
then runs `afl-cmin` under that group's `TC=`, so an import only grows the
corpus by what adds coverage. By hand, one seed is just:

```bash
{ printf '\x00\x00\x00\x00'; cat doc.yaml; } > fuzzer/seeds/yaml/doc
```
## The instance mix

One instance per **physical** core (SMT siblings roughly halve each other's
speed), each pinned with `--cpuset-cpus` (docker) or `taskset` (host), all
sharing one `-o` directory. Tab 0 is the `status --loop` dashboard, tabs 1..N
the lanes of a plan:

```bash
./a run                      # FUZZ_PLAN=auto: 8.plan on 8 cores, 32.plan on 32
JOBS=12 ./a run              # the first 12 lanes of 16.plan
FUZZ_GROUP=yaml TC=test_yaml FUZZ_PLAN=32 ./a run
```

Plans live in `plans/<lanes>.plan`, one lane per line
(`name | variant | afl-fuzz args | env`; the tokens are documented at the top
of `lib/run.sh`). `auto` takes the smallest plan with at least `JOBS` lanes and
runs its first `JOBS`, so each file is ordered by what to keep when cores are
short. A lane whose build is missing is skipped, and a missing SAND oracle is
dropped from its lane, each with a warning.

Every plan follows AFL++'s `docs/fuzzing_in_depth.md`, "Using multiple cores":

| | 8 | 16 | 32 |
|---|---|---|---|
| `-M main`: dictionary, deterministic stage, `AFL_FINAL_SYNC=1` | 1 | 1 | 1 |
| full ASAN+UBSAN lanes | 1 | 1 | 3 |
| `lsan` / `tsan` | – | 1 / 1 | 1 / 1 |
| CMPLOG, at least one `-l 2AT` | 1 | 2 | 4 |
| laf-intel | 1 | 1 | 2 |
| other secondaries | 4 | 9 | 20 |

Across the other secondaries (the 32-lane numbers; smaller plans round):
`-Z` 10 %, `AFL_DISABLE_TRIM` 60 %, `-P explore` 40 %, `-P exploit` 20 %, 30 %
without `-a` and the rest `-a text` (`binary` for the `blob` group), every
power schedule `-p` offers, and MOpt (`-L`) on two. A few lanes run without
the dictionary; they still get the LTO autodictionary. Each plan's header
carries its own count.

* **Every secondary runs `-z`.** Since AFL++ 4.20 the deterministic stage is
  on in every instance by default, and it produces the same inputs wherever it
  runs — only `main` keeps it.
* **Sanitizers mostly come from SAND oracles** (`docs/SAND.md`). Nearly every
  native, laf and CMPLOG lane carries `-w sand-asan`, a third of them also
  `-w sand-msan`: afl-fuzz re-runs selected inputs through those builds, so a
  lane keeps native speed and still reports ASAN/UBSAN/MSAN findings (saved as
  `+san` crashes). Which inputs get re-run is the whole cost, measured here
  (5 min, one core each, `TC=test_yaml`):

  | lane | execs/s | execs through the oracles | edges |
  |---|---|---|---|
  | native, no oracle | 1090 | – | 12464 |
  | `-w sand-asan -w sand-msan`, default abstraction | 380 | 55 % | 11410 |
  | `-w sand-asan -w sand-msan`, `coverage_increase` | 1400 | 1.3 % | 12671 |

  The default re-runs anything with a new simplified coverage map, and this
  harness's flag seed and allocator recipes make nearly every input look new.
  `AFL_SAN_ABSTRACTION=coverage_increase` (set for every lane in
  `lib/common.sh`) checks only new queue entries. SAND's authors measure that
  mode missing ~15 % of bugs, which is what the full `asan` lanes cover: they
  check every exec, at about a fifth of native speed.
* **No dedicated `msan` lane** any more: `sand-msan` covers it at native speed.
  `lsan` and `tsan` keep their lanes because SAND has no equivalent for them.
* **32 is the ceiling.** AFL++ stops scaling somewhere between 32 and 64
  instances per machine, so `run` caps `JOBS` at the largest plan. With that
  many lanes `AFL_IMPORT_FIRST=1` makes the first minutes slow while every
  lane imports the others' seeds.

## Plan parameters

Everything a plan line can set, and what `run` adds to every lane. The plan
files say *which* lane uses what and why; this is what each knob does.
Sources: `afl-fuzz -h`, `docs/env_variables.md`, `docs/FAQ.md`,
`docs/fuzzing_in_depth.md`, `docs/SAND.md` of the AFL++ install.

### Added by `run`, not written in plans

| | |
|---|---|
| `-M main` | the lane named `main`: the primary. The only lane running the deterministic stage; `-M` also sets `-Z` and disables trimming |
| `-S <name>` | every other lane: a secondary, syncing through the shared `-o` directory |
| `-z` | every secondary: skip the deterministic stage. Since AFL++ 4.20 it is on by default, and it generates the same inputs in every instance that runs it |
| `-i`, `-o` | `fuzzer/seeds/<group>`, `../fuzz/libfyaml/state/<group>` |
| `-G 10000` | max input length (`FUZZ_MAX_LEN`) |
| `-m none` | no memory limit — required for the sanitizer builds |
| `-t 2000` | per-exec timeout in ms, unless the line sets one (`TIMEOUT_FAST`) |

### Plan tokens and flags

| | |
|---|---|
| `-x DICT` | the dictionary, `src/fuzz/yaml.dict`. Lanes without it still get the tokens afl-clang-lto extracts from the binary's string compares (the autodictionary) |
| `-a FMT` | input format hint: `text` for every group but `blob`, which gets `binary`. Fixes which mutation set havoc uses; without `-a` afl-fuzz decides per queue entry whether it looks like text (the `ascii=` field in its log). The docs: when `-a` is used, 30 % of the lanes should run without it |
| `-c CMPLOG` | CmpLog / RedQueen: the `cmplog` build logs the operands of every comparison and afl-fuzz writes them back into the input where they came from — how magic values and keywords get solved without guessing |
| `-l 2` / `2AT` / `3AT` | CmpLog settings. Digit: which queue entries get CmpLog — `1` small files, `2` larger files (default), `3` all. `A`: arithmetic solving (the input was offset or scaled before the compare). `T`: transformational solving (the input was transformed before the compare) |
| `-L` | MOpt: pick mutation operators adaptively (particle-swarm), by which ones found coverage |
| `-p <schedule>` | power schedule — how much mutation energy an entry gets. `explore` (default) and `fast` are the most effective per the FAQ; the rest diversify parallel lanes. `fast`: grows with how often the entry was picked, shrinks with how common its path is. `coe`: like `fast`, but nothing for entries on above-average-frequency paths. `lin` / `quad`: `fast` with linear / quadratic growth. `exploit`: original AFL. `rare`: favours entries hitting rarely-seen edges. `seek`: `explore` ignoring runtime. `mmopt`: `explore` with extra energy for the newest entries |
| `-P explore` / `-P exploit` | fixed mutation strategy: `explore` aims at new coverage, `exploit` at crashes in what is already covered. Without `-P` afl-fuzz switches to exploit after 1000 s without finds and back on new coverage |
| `-Z` | walk the queue in order instead of weighted-random selection (AFL's old queue cycling) |
| `-w ASAN_ORACLE` / `-w MSAN_ORACLE` | SAND oracle: the `sand-asan` / `sand-msan` build, re-run on the inputs `AFL_SAN_ABSTRACTION` selects. A sanitizer report is saved as a crash with `+san` in its name |
| `-t TIMEOUT_SAN` | 5000 ms, for the full sanitizer lanes (`TIMEOUT_MSAN`: 10000 ms) |

### Per-lane environment (plan `env` column)

| | |
|---|---|
| `AFL_FINAL_SYNC=1` | `main` only: one last import from every lane on exit, so `./a cmin` needs only main's queue |
| `AFL_DISABLE_TRIM=1` | do not trim new queue entries. On one instance "usually a bad idea" (env_variables.md); across parallel lanes the docs recommend it on 50–70 % — trimming costs execs, and the other lanes still trim |
| `AFL_CMPLOG_ONLY_NEW=1` | CMPLOG lanes: run CmpLog only on entries found in this run, not on the seeds or a resumed queue |

### Every lane (`AFL_ENV` and `SAN_ENV` in `lib/common.sh`)

| | |
|---|---|
| `AFL_SAN_ABSTRACTION=coverage_increase` | SAND oracles re-run only new queue entries (see [The instance mix](#the-instance-mix) for the measurement) |
| `AFL_TMPDIR=/dev/shm` | temporary input files on tmpfs, off the disk |
| `AFL_FAST_CAL=1` | 3 calibration runs per entry instead of 8 (more if it turns out unstable). Halves startup on the yaml seeds — fast 11.7 → 6.1 s, asan 41 → 18 s, tsan 35 → 19 s, lsan 30 → 15 s — and speeds up calibrating every new find and synced entry |
| `AFL_TESTCACHE_SIZE=250` | MB of queue entries cached in RAM per lane |
| `AFL_AUTORESUME=1` | re-running `./a run` resumes the existing state instead of refusing |
| `AFL_IMPORT_FIRST=1` | import the other lanes' queues before fuzzing own entries |
| `AFL_IGNORE_SEED_PROBLEMS=1` | skip seeds that crash or time out instead of aborting |
| `AFL_NO_AFFINITY=1` | afl-fuzz does not pin itself — `run` already pins with `taskset` / `--cpuset-cpus` |
| `AFL_SKIP_CPUFREQ=1` | no abort on the `powersave` governor (`afl-system-config` fixes the governor) |
| `AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1` | tolerate a `core_pattern` pipe; the sanitizers abort on error anyway |
| `AFL_FORCE_UI=1` | keep the status screen although stdout is piped into the log filter |
| `TC=<test case>` | only when set for `run`: restricts every lane's harness |
| `ASAN_OPTIONS` … `TSAN_OPTIONS` | fuzzing mode: abort on the first report, no symbolization, AFL owns the signals. The `lsan` lane overrides `LSAN_OPTIONS` to `detect_leaks=1`; `./a triage` switches all of them to reporting mode |

## Health checks (window 0)

The table carries AFL's own `bitmap_cvg` per instance, so a lane stuck well
below the others shows up immediately; the summary line takes the highest.

`lib/status.sh` reads `state/<group>/*/fuzzer_stats` directly (so it still
works when an instance is wedged) and flags:

* an instance whose stats have not moved for 2 min → **dead/wedged**
* stability < 85 % → non-deterministic paths, crashes may not replay
* no new path in an hour → plateau; time for new seeds or `./a cmin`
* live stats with no running instance → a tmux tab died
* `/dev/shm` and state-filesystem free space, load average vs `JOBS`

It appends `afl-whatsup -s` for the AFL-native view.

## Coverage: what AFL can and cannot tell you

AFL's instrumentation is an **edge bitmap** — collision-free edge IDs under LTO,
hit counts, nothing else. It answers "how much of the map has this corpus
covered" and never "which source line was missed". That is why a
clang-instrumented build still exists: source-level coverage needs
`-fprofile-instr-generate`, and AFL++'s own `cov-analysis` shells out to
`llvm-profdata`/`llvm-cov` exactly like everyone else.

| | needs | gives |
|---|---|---|
| `./a coverage --edges` | nothing beyond the `fast` build | `afl-showmap -C`: "4922 of 50176 edges (9.81%)" — a corpus-health trend |
| `./a coverage` | the `cov` build | `cov-analysis report`: summary.txt, **gaps.txt** (uncovered regions ranked by size), HTML, JSON, profdata, plus `lcov.info` |
| `./a coverage --search FILE:LINE` | the `cov` build | which corpus entries reach that line |
| `./a coverage --stability` | the `cov` build **and gawk** | per-line non-deterministic hit counts |

The dashboard's `bitmap_cvg` is the same edge metric, live, for free.

`llvm-profdata` and `llvm-cov` have to match the `clang` that built `fuzz_cov`.
Both `cov-analysis` and the `lcov.info` export resolve them the same way —
`<tool>-<clang major>`, then the bare name, then any version
(`LLVM_TOOL_FN` in `lib/common.sh`).

## Notes / gotchas

* **Seed shape.** `LLVMFuzzerTestOneInput()` eats bytes 0..3 as the flag seed
  and passes byte 4 onward to the test cases, so a seed must be ≥ 5 bytes.
  `seeds --import` enforces that and emits three flag prefixes per file.
* **`-G 10000`.** Big enough for the ~10 KB deep-nesting inputs that produced
  the `fy_generic_dump_primitive()` stack overflow.
* **`core_pattern`.** The host pipes cores to systemd-coredump, which AFL
  refuses by default; `AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1` is set because
  the sanitizers' `abort_on_error` reports crashes anyway. `sudo
  afl-system-config` (or `docker run --rm --privileged -u 0:0 $FUZZ_IMAGE
  afl-system-config`) fixes it, and is worth up to ~15 % more execs/sec.
* **`TC` is stripped from inherited environments.** The host backend would
  otherwise pass a stray `TC=` from your shell into every exec — measured once
  at 159 edges instead of 3199, a campaign fuzzing a fifth of the target.
  `run` forwards `TC` explicitly when you set it.
* **Persistent mode is automatic**: `libAFLDriver.a` carries `__AFL_LOOP` and
  the deferred forkserver, so the `fast` build runs ~30k execs/sec on a no-op
  input. `AFL_FUZZER_LOOPCOUNT` overrides the loop count.
* **TSAN under docker** needs `--security-opt seccomp=unconfined`: the runtime
  calls `personality(ADDR_NO_RANDOMIZE)` before `main()` and the default
  seccomp profile blocks it, which AFL reports as "Fork server crashed with
  signal 11". `backend_extra_for()` in `lib/common.sh` adds it for that variant
  only; the host backend needs nothing.
* **MSAN reports that leave libfyaml are false positives** — the build drops
  libclang, but glibc and the BLAKE3 assembly are still uninstrumented.
* **`afl-showmap`/`afl-cmin` abort against the msan build** ("Fork server
  crashed with signal 6") even though `afl-fuzz` drives it fine. Corpus tooling
  always uses the `fast` build.
* **`afl-cmin` needs `@@`.** Without a file argument the input goes through
  AFL's shared-memory path, which the AFLDriver target only honours under
  `afl-fuzz`; under showmap it runs on an empty buffer and the corpus collapses
  to one file.
* **Lane speed, measured here:** fast ~1400 execs/s in a campaign lane, msan
  ~970, tsan ~235, lsan ~85 (a full leak check per input is expensive). That is
  why the sanitizer lanes sit low in the plan.
* **Crash inputs are never minimized** — the repo's bug reports keep original
  artifact bytes.
