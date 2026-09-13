# Shared configuration, logging and backend plumbing for the campaign.
#
# Sourced by `a` before any command file; never run on its own. Everything
# below can be overridden from the environment, e.g. JOBS=12 ./a run
#
# ── backends ──────────────────────────────────────────────────────────────────
# FUZZ_BACKEND=auto|docker|host   (default: auto)
#
# Every knob this project invents is FUZZ_*, never AFL_*: afl-cc scans its
# environment and prints "WARNING: Mistyped AFL environment variable" for any
# AFL_* name it does not know. Harmless in itself, but it trains you to ignore
# that warning - and the next one will be a real typo in AFL_USE_ASAN.
# AFL_* names here are AFL++'s own (AFL_PATH, AFL_USE_*, AFL_LLVM_CMPLOG, ...).
#
#   docker  everything runs in $FUZZ_IMAGE.  Host paths are mapped onto two
#           fixed mount points, $REPO_DIR -> /repo and $FUZZ_DIR -> /fuzz.
#   host    everything runs from a system (or $AFL_PATH) AFL++ install, with
#           the host's own paths and taskset for core pinning.
#   auto    host if afl-fuzz is on PATH (or in $AFL_PATH), else docker.
#
# Binaries are always produced by the same backend that runs them, so clang,
# the instrumentation pass and libc never disagree.  Switching backends means
# rebuilding: ./a build --clean.
# shellcheck shell=bash

set -euo pipefail

: "${FUZZ_ROOT:?common.sh is sourced by ./a, not run directly}"
REPO_DIR="$(cd "$FUZZ_ROOT/.." && pwd)"

PROJECT_NAME="${PROJECT_NAME:-libfyaml}"
FUZZ_IMAGE="${FUZZ_IMAGE:-aflplusplus/aflplusplus:stable}"
FUZZ_BACKEND="${FUZZ_BACKEND:-auto}"

# Campaign state lives outside the repo, so a `git clean` never eats a running
# campaign. Everything sits directly in $FUZZ_DIR - seeds/, state/, logs/ -
# with no extra nesting.
FUZZ_DIR="${FUZZ_DIR:-$(cd "$REPO_DIR/.." && pwd)/fuzz/$PROJECT_NAME}"
CAMPAIGN_DIR="${CAMPAIGN_DIR:-$FUZZ_DIR}"
# ── seed groups ───────────────────────────────────────────────────────────────
# The harness groups its test cases by the shape of input they consume, and the
# group is a test case in its own right - see the group block in src/fuzz/main.c.
# TC=test_<group> selects one; seeds are built and minimized per group; state,
# tmux session and container names follow FUZZ_GROUP, so groups run side by side.
#
#   group  TC             feeds                                    input
#   yaml   test_yaml      parse_with_flags, parser_checkpoint_      a YAML/JSON
#                         rollback, fy_parser_parse_fp,             document
#                         generic_document_builder
#   path   test_path      parse_path, fy_path_expr_build_from_str   path/ypath
#   scanf  test_scanf     document_scanf                           scanf format
#   blob   test_blob      reflection_packed_blob                   packed FYPG
#   meta   test_meta      reflection_type_context_entry_meta       meta \n yaml
SEED_GROUPS=(yaml path scanf blob meta)
group_tc() {
  case "$1" in
    yaml|path|scanf|blob|meta) echo "test_$1" ;;
    *) echo "" ;;
  esac
}
FUZZ_GROUP="${FUZZ_GROUP:-yaml}"

# afl-fuzz -a: the input format hint the plans' FMT token expands to. Every
# group is text after the 4-byte flag prefix except the packed blobs.
group_format() {
  case "$1" in
    blob) echo binary ;;
    *)    echo text ;;
  esac
}

# Instance plans, one file per core count (format: run.sh's header).
# FUZZ_PLAN=auto picks the smallest plan with at least JOBS lanes; a name
# (8, 16, 32) or a path forces one.
PLAN_DIR="${PLAN_DIR:-$FUZZ_ROOT/plans}"
FUZZ_PLAN="${FUZZ_PLAN:-auto}"

# Seeds live with the harness and are checked in: they are an input to a run,
# not an artifact of it, and nothing a campaign does writes to them (afl-fuzz
# only ever reads -i). ./a seeds --import adds to them.
SEED_ROOT="${SEED_ROOT:-$FUZZ_ROOT/seeds}"
SEED_DIR="${SEED_DIR:-$SEED_ROOT/$FUZZ_GROUP}"
OUT_DIR="${OUT_DIR:-$CAMPAIGN_DIR/state/$FUZZ_GROUP}"
LOG_DIR="${LOG_DIR:-$CAMPAIGN_DIR/logs}"
CMIN_DIR="${CMIN_DIR:-$CAMPAIGN_DIR/corpus.cmin}"

BUILD_ROOT="${BUILD_ROOT:-$FUZZ_ROOT/build}"
# The harness eats the first 4 bytes as the flag seed and returns early on
# anything shorter than 5 bytes, so a seed must be at least that long.
MIN_SEED_BYTES=5

DICT="${DICT:-$REPO_DIR/src/fuzz/yaml.dict}"

# Build variants (see build.sh). bin_of <variant> resolves the binary: the
# campaign variants all produce `fuzz`, the two engine-free ones do not.
FUZZ_VARIANTS=(fast asan cmplog msan tsan lsan laf sand-asan sand-msan cov repro)
bin_of() {
  case "$1" in
    cov)   echo "$BUILD_ROOT/cov/fuzz_cov" ;;
    repro) echo "$BUILD_ROOT/repro/fuzz2" ;;
    *)     echo "$BUILD_ROOT/$1/fuzz" ;;
  esac
}

BIN_FAST="$(bin_of fast)"       # no sanitizer          - throughput lanes
BIN_ASAN="$(bin_of asan)"       # ASAN+UBSAN            - the lane that classifies
BIN_CMPLOG="$(bin_of cmplog)"   # CMPLOG                - passed to -c, never run alone
BIN_MSAN="$(bin_of msan)"       # MSAN                  - uninitialized reads
BIN_TSAN="$(bin_of tsan)"       # TSAN                  - data races in the thread pool
BIN_LSAN="$(bin_of lsan)"       # LSAN + __AFL_LEAK_CHECK - per-input leaks
BIN_COV="$(bin_of cov)"         # coverage, no engine, no sanitizer
BIN_REPRO="$(bin_of repro)"     # the RR/RF reproducer, asan+ubsan, no engine

# -G: max input length.  10000 keeps the ~10KB
FUZZ_MAX_LEN="${FUZZ_MAX_LEN:-10000}"
TIMEOUT_FAST="${TIMEOUT_FAST:-2000}"
TIMEOUT_SAN="${TIMEOUT_SAN:-5000}"
TIMEOUT_MSAN="${TIMEOUT_MSAN:-10000}"

TMUX_SESSION="${TMUX_SESSION:-afl-$PROJECT_NAME-$FUZZ_GROUP}"
CONTAINER_PREFIX="${CONTAINER_PREFIX:-afl-$PROJECT_NAME-$FUZZ_GROUP}"

# ── logging ───────────────────────────────────────────────────────────────────
# One place for every message these scripts print: timestamp, a level marker in
# AFL's own [+]/[*]/[!]/[-] shape, then the text. Colour only when the stream is
# a terminal, so a tee'd build.log or a CI capture stays plain text.
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'
  C_BLU=$'\033[34m'; C_DIM=$'\033[2m'; C_BLD=$'\033[1m'; C_OFF=$'\033[0m'
else
  C_RED=; C_GRN=; C_YEL=; C_BLU=; C_DIM=; C_BLD=; C_OFF=
fi

_log() { # _log <colour> <marker> <stream> <message...>
  local colour="$1" marker="$2" stream="$3"; shift 3
  printf '%s%s%s %s%s%s %s\n' \
    "$C_DIM" "$(date '+%F %T')" "$C_OFF" \
    "$colour" "$marker" "$C_OFF" "$*" >&"$stream"
}

log()      { _log "$C_BLU" '[*]' 1 "$@"; }   # what is happening
log_ok()   { _log "$C_GRN" '[+]' 1 "$@"; }   # it worked / here is the result
log_warn() { _log "$C_YEL" '[!]' 2 "$@"; }   # keeps going, but read this
log_err()  { _log "$C_RED" '[-]' 2 "$@"; }   # it failed
die()      { log_err "$@"; exit 1; }

# A section header - the one line worth finding when scrolling a long log.
log_step() { printf '\n%s%s=== %s%s\n' "$C_BLD" "$C_BLU" "$*" "$C_OFF"; }

# ── small shared helpers ──────────────────────────────────────────────────────
count_files() { find "$1" -maxdepth 1 -type f 2>/dev/null | wc -l; }

# The campaign directories, created on demand by whichever command needs them -
# there is no setup step and no Makefile recipe to forget.
ensure_dirs() { mkdir -p "$@"; }

# Does this AFL++ have a working LTO mode? Ask afl-cc, not PATH: the lld it
# uses is compiled into it. Captured first, because `afl-cc -h` exits non-zero
# and these scripts run with pipefail, which would turn a match into a miss.
afl_lto_available() {
  local help
  help="$(afl-cc -h 2>&1 || true)"
  grep -qE '\[LTO\].*AVAILABLE' <<<"$help"
}

# A build variant's binary, or die with the command that produces it.
need_bin() { # need_bin <variant>
  local b; b="$(bin_of "$1")"
  [ -x "$b" ] || die "$b missing - run ./a build $1"
  echo "$b"
}

need_dir() { [ -d "$1" ] || die "${2:-no such directory}: $1"; }

# Seconds -> "45s" / "12m" / "3h20m" / "2d4h"; -1 means never.
human_age() {
  local s="$1"
  [ "$s" -lt 0 ] && { echo never; return; }
  if   [ "$s" -lt 60 ]   ; then echo "${s}s"
  elif [ "$s" -lt 3600 ] ; then echo "$((s / 60))m"
  elif [ "$s" -lt 86400 ]; then echo "$((s / 3600))h$(( (s % 3600) / 60 ))m"
  else echo "$((s / 86400))d$(( (s % 86400) / 3600 ))h"; fi
}

# ── cores ─────────────────────────────────────────────────────────────────────
# One instance per *physical* core: two AFL instances sharing a core through SMT
# run at roughly half speed each, so hyperthreads buy almost nothing.
core_list() { lscpu -p=CPU,CORE | grep -v '^#' | awk -F, '!seen[$2]++{print $1}'; }
JOBS="${JOBS:-$(core_list | wc -l)}"

# ── backend resolution ────────────────────────────────────────────────────────
host_afl() {
  if [ -n "${AFL_PATH:-}" ] && [ -x "$AFL_PATH/afl-fuzz" ]; then return 0; fi
  command -v afl-fuzz >/dev/null 2>&1
}

resolve_backend() {
  case "$FUZZ_BACKEND" in
    host|docker) ;;   # forced: taken as given, the tool itself reports if it is missing
    auto)
      # Detection, not validation: a local AFL++ wins (no container start-up,
      # no path mapping, and it is what the user installed on purpose), docker
      # is the fallback - and if docker is missing too, docker says so.
      if host_afl; then FUZZ_BACKEND=host; else FUZZ_BACKEND=docker; fi ;;
    *) echo "error: FUZZ_BACKEND must be auto|docker|host" >&2; exit 1 ;;
  esac
  [ "$FUZZ_BACKEND" = host ] && [ -n "${AFL_PATH:-}" ] && PATH="$AFL_PATH:$PATH" && export PATH
  return 0
}
resolve_backend

# Prepare the resolved backend: the docker image is pulled the first time it is
# needed. Nothing here validates that tools exist - a missing docker, tmux or
# afl-fuzz reports itself far better than a hand-written check does, and one
# less check is one less thing that can be wrong about the environment.
require_backend() {
  [ "$FUZZ_BACKEND" = docker ] || return 0
  docker image inspect "$FUZZ_IMAGE" >/dev/null 2>&1 && return 0
  log "pulling $FUZZ_IMAGE (first use of the docker backend)"
  docker pull "$FUZZ_IMAGE" >/dev/null
  log_ok "image ready"
}

# Map a host path onto the path the backend sees.  Identity on the host backend.
cpath() {
  [ "$FUZZ_BACKEND" = host ] && { echo "$1"; return 0; }
  case "$1" in
    "$REPO_DIR"/*|"$REPO_DIR") echo "/repo${1#"$REPO_DIR"}" ;;
    "$FUZZ_DIR"/*|"$FUZZ_DIR") echo "/fuzz${1#"$FUZZ_DIR"}" ;;
    *) echo "error: $1 is outside the mounted trees ($REPO_DIR, $FUZZ_DIR)" >&2; return 1 ;;
  esac
}

# Backend-visible paths (B_ = what afl-fuzz is handed).
B_REPO="$(cpath "$REPO_DIR")"
B_SEED_DIR="$(cpath "$SEED_DIR")"
B_OUT_DIR="$(cpath "$OUT_DIR")"
B_DICT="$(cpath "$DICT")"
B_CMIN_DIR="$(cpath "$CMIN_DIR")"
b_bin_of() { cpath "$(bin_of "$1")"; }
B_BIN_FAST="$(b_bin_of fast)"
B_BIN_ASAN="$(b_bin_of asan)"
B_BIN_CMPLOG="$(b_bin_of cmplog)"
B_BIN_MSAN="$(b_bin_of msan)"
B_BIN_TSAN="$(b_bin_of tsan)"
B_BIN_LSAN="$(b_bin_of lsan)"

# Per-variant backend quirks.  TSAN calls personality(ADDR_NO_RANDOMIZE) before
# main(), which docker's default seccomp profile blocks - the runtime
# CHECK-fails at startup and AFL reports "Fork server crashed with signal 11".
# Nothing is needed for the host backend.
backend_extra_for() {
  [ "$FUZZ_BACKEND" = docker ] || return 0
  case "$1" in
    tsan) printf -- '-x %s -x %s ' --security-opt seccomp=unconfined ;;
  esac
}

# Filter for the per-instance campaign logs.  The tabs run afl-fuzz with
# AFL_FORCE_UI=1 (see run.sh), so the raw stream is the status screen repainted
# five times a second - fine on the pane, megabytes of escape codes a minute in
# a file.  This keeps only the lines worth reading later: warnings, aborts,
# system errors and the closing summary.  Per-second stats are not lost, they
# live in $OUT_DIR/<instance>/{fuzzer_stats,plot_data}.
log_filter() {
  sed -u -e 's/\x1B\[[0-9;?]*[a-zA-Z]//g' -e 's/\x1B[()][A-Za-z0-9]//g' \
    | grep -a --line-buffered -E '^\[[-+*!]\]|PROGRAM ABORT|SYSTEM ERROR|Testing aborted|^\+\+\+'
}

# afl_run [-n NAME] [-c CPUSET] [-i] [-e K=V]... [-x DOCKER_ARG]... -- <shell command>
#
# docker: one --rm container, running as the invoking uid:gid so nothing in the
#         mounted trees ends up root-owned, with a real /dev/shm for AFL_TMPDIR.
# host:   the same command under env(1), pinned with taskset.
afl_run() {
  local name="" cpuset="" tty="" envs=() dextra=()
  while [ $# -gt 0 ]; do
    case "$1" in
      -n) name="$2"; shift 2 ;;
      -c) cpuset="$2"; shift 2 ;;
      -i) tty="-it"; shift ;;
      -e) envs+=("$2"); shift 2 ;;
      -x) dextra+=("$2"); shift 2 ;;
      --) shift; break ;;
      *) break ;;
    esac
  done

  if [ "$FUZZ_BACKEND" = host ]; then
    local pin=()
    [ -n "$cpuset" ] && pin=(taskset -c "$cpuset")
    # -u TC -u VERBOSE: the host backend inherits the caller's environment, and
    # the harness reads both. A TC= left over from a triage session silently
    # restricts every exec to one test case - measured: 159 edges instead of
    # 3199 on the same input, an entire campaign fuzzing a ninth of the target.
    # The docker backend never had this problem: it passes -e explicitly.
    # A caller that wants them sets them through -e, which comes after these.
    env -u TC -u VERBOSE "${envs[@]}" "${pin[@]}" bash -c "$*"
    return $?
  fi

  local dargs=(run --rm $tty
    -u "$(id -u):$(id -g)"
    -v "$REPO_DIR:/repo"
    -v "$FUZZ_DIR:/fuzz"
    --shm-size="${FUZZ_SHM_SIZE:-2g}"
    -w /repo
    -e HOME=/tmp)
  local e; for e in "${envs[@]}"; do dargs+=(-e "$e"); done
  [ "${#dextra[@]}" -gt 0 ] && dargs+=("${dextra[@]}")
  [ -n "$name" ]   && dargs+=(--name "$name")
  [ -n "$cpuset" ] && dargs+=(--cpuset-cpus "$cpuset")

  docker "${dargs[@]}" "$FUZZ_IMAGE" bash -lc "$*"
}

# ── runtime environment shared by every instance ──────────────────────────────
# AFL_TMPDIR      - keep the per-instance .cur_input in tmpfs, off the SSD
# AFL_FAST_CAL    - 3 calibration runs per new queue entry instead of 8 (more
#                   only when an entry turns out unstable). Measured on the 432
#                   yaml seeds, TC=test_yaml: startup to "ready" fast 11.7 ->
#                   6.1 s, asan 41 -> 18 s, tsan 35 -> 19 s, lsan 30 -> 15 s;
#                   stability unchanged. Calibration also runs on every new
#                   find and every entry synced from another lane, so it is
#                   not only a startup cost.
# AFL_TESTCACHE_SIZE - cache queue entries in RAM instead of re-reading them
# AFL_AUTORESUME  - re-running run.sh continues instead of refusing to start
# AFL_IGNORE_SEED_PROBLEMS - the seed corpus still holds inputs that crash or
#                   time out; skip them rather than abort at startup
# AFL_NO_AFFINITY - the instance is already pinned (cpuset / taskset)
# AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES - the host core_pattern is a pipe
#                   (systemd-coredump) and only root can change it; the
#                   sanitizers' abort_on_error is what reports crashes anyway.
#                   Fix it properly with `sudo afl-system-config` (host) or
#                   `docker run --rm --privileged -u 0:0 $FUZZ_IMAGE
#                   afl-system-config` - also worth up to ~15% more execs/sec.
# AFL_SAN_ABSTRACTION - which inputs a lane's SAND oracles (-w) re-run.  The
#                   default (a unique simplified coverage map) sent 55% of all
#                   execs through the oracles on this harness - its flag seed
#                   and allocator recipes make nearly every input look new -
#                   and cut a lane from ~1100 to ~380 execs/s over 5 minutes.
#                   coverage_increase checks only new queue entries: ~1% of
#                   execs, native speed. SAND's authors measure it missing ~15%
#                   of bugs, which is what the plans' full asan lanes are for.
AFL_ENV=(
  AFL_SAN_ABSTRACTION=coverage_increase
  AFL_TMPDIR=/dev/shm
  AFL_FAST_CAL=1
  AFL_TESTCACHE_SIZE=250
  AFL_AUTORESUME=1
  AFL_IGNORE_SEED_PROBLEMS=1
  AFL_SKIP_CPUFREQ=1
  AFL_NO_AFFINITY=1
  AFL_IMPORT_FIRST=1
  AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
)

# Sanitizer settings for *fuzzing*: no symbolization, signal handling left to
# AFL, and the sanitizer aborting so AFL sees a crash.  triage.sh flips all of
# this back to reporting mode.  AFL refuses to start if LSAN_OPTIONS or
# UBSAN_OPTIONS lack symbolize=0, hence the explicit entries.
SAN_ENV=(
  "ASAN_OPTIONS=abort_on_error=1:symbolize=0:detect_leaks=0:allocator_may_return_null=1:detect_odr_violation=0:detect_stack_use_after_return=0:malloc_context_size=0:handle_segv=0:handle_sigbus=0:handle_abort=0:handle_sigfpe=0:handle_sigill=0"
  "UBSAN_OPTIONS=halt_on_error=1:abort_on_error=1:symbolize=0:print_stacktrace=0"
  "LSAN_OPTIONS=detect_leaks=0:symbolize=0"
  "MSAN_OPTIONS=abort_on_error=1:symbolize=0:halt_on_error=1:exit_code=86:handle_segv=0:handle_sigbus=0:handle_abort=0"
  "TSAN_OPTIONS=abort_on_error=1:symbolize=0:halt_on_error=1:handle_segv=0:handle_sigbus=0:handle_abort=0"
)

# The lsan lane wants leak detection ON (that is the whole point of the lane),
# and __AFL_LEAK_CHECK() in main.c turns a leak into a per-input _exit(23).
LSAN_LANE_ENV=("LSAN_OPTIONS=detect_leaks=1:symbolize=0:malloc_context_size=30:print_suppressions=0")

env_args() { local e; for e in "$@"; do printf -- '-e %q ' "$e"; done; }

# ── llvm tools, inside the backend ────────────────────────────────────────────
# Debian and Ubuntu ship the llvm tools versioned (llvm-cov-20, no llvm-cov),
# and the tool that reads a profile has to match the clang that wrote it. This
# is cov-analysis's own lookup - the clang major version first, then the bare
# name, then any version - kept as shell SOURCE because it runs inside the
# backend, where this file's functions do not exist:
#
#   afl_run -- "$LLVM_TOOL_FN; cov=\$(find_llvm_tool llvm-cov) && \$cov ..."
LLVM_TOOL_FN='find_llvm_tool() {
  local t="$1" v
  v="$(clang --version 2>/dev/null | grep -oE "clang version [0-9]+" | grep -oE "[0-9]+" | head -n 1)"
  if [ -n "$v" ] && command -v "$t-$v" >/dev/null 2>&1; then echo "$t-$v"; return 0; fi
  if command -v "$t" >/dev/null 2>&1; then echo "$t"; return 0; fi
  for v in $(seq 30 -1 11); do
    if command -v "$t-$v" >/dev/null 2>&1; then echo "$t-$v"; return 0; fi
  done
  return 1
}'

# How the backend reports "instances that are actually alive".
running_instances() {
  if [ "$FUZZ_BACKEND" = docker ]; then
    docker ps -q --filter "name=^${CONTAINER_PREFIX}-" 2>/dev/null | wc -l
  else
    # pgrep -c prints 0 AND exits 1 when nothing matches; `|| echo 0` would
    # append a second line and every later [ ] on it would blow up.
    local n; n="$(pgrep -fc "afl-fuzz .*-o $OUT_DIR" 2>/dev/null || true)"
    echo "${n:-0}"
  fi
}
