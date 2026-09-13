# Replay saved artifacts through every built variant and write one log per
# (artifact, variant) into $LOG_DIR. That is all this does - reading the logs
# is a separate job, see src/fuzz/CLAUDE.md.
#
#   ./a triage                  # every crash, every runnable variant, new logs only
#   ./a triage --all            # re-replay artifacts that already have logs
#   ./a triage --hangs          # hangs instead of crashes
#   ./a triage --with a,b       # only these variants
#   ./a triage --input FILE     # one artifact, wherever it lives
#   ./a triage --timeout 300    # per-replay wall clock limit (default: 120s)
#
# A crash is replayed under every sanitizer, not just the one that found it:
# the lane that saved it is whichever lane happened to hit the input first, and
# the same input often reports differently (or not at all) under another
# sanitizer.
#
# cmplog and cov are never replayed: cmplog exists to be passed to afl-fuzz -c,
# and cov carries no sanitizer, so neither can report anything a run tells you.
#
# Log name: <instance>__<artifact>__<variant>.log, each one headed by the
# artifact path, the variant and the sanitizer options it ran with.

require_backend

TRIAGE_VARIANTS=(asan msan tsan lsan fast)

# Replays are short, independent and mostly waiting on a sanitizer, so they run
# on every logical core - unlike fuzzing, where one instance per physical core
# is the right number.
PAR="$(nproc)"
WHAT=crashes; ALL=0; ONLY=""; INPUT=""; REPLAY_TIMEOUT=120
while [ $# -gt 0 ]; do
  case "$1" in
    --all)   ALL=1 ;;
    --hangs) WHAT=hangs ;;
    --with)  ONLY="$2"; shift ;;
    --input) INPUT="$2"; shift ;;
    --timeout) REPLAY_TIMEOUT="$2"; shift ;;
    *) die "usage: $PROG triage [--all] [--hangs] [--with v1,v2] [--input FILE] [--timeout S]" ;;
  esac
  shift
done

# Reporting-mode sanitizer options: symbolized frames, stack traces, and the
# signal handlers owned by the sanitizer rather than by AFL.
triage_env_for() {
  case "$1" in
    msan) echo "MSAN_OPTIONS=abort_on_error=1:symbolize=1:halt_on_error=1:print_stats=0" ;;
    tsan) echo "TSAN_OPTIONS=abort_on_error=1:symbolize=1:halt_on_error=1:second_deadlock_stack=1" ;;
    lsan) echo "LSAN_OPTIONS=detect_leaks=1:symbolize=1:malloc_context_size=30" ;;
    *)    echo "ASAN_OPTIONS=abort_on_error=1:symbolize=1:print_stacktrace=1:detect_leaks=0:allocator_may_return_null=1" ;;
  esac
}

# Which variants to run: the requested ones, or every built one.
variants=()
if [ -n "$ONLY" ]; then
  IFS=, read -r -a requested <<<"$ONLY"
  for v in "${requested[@]}"; do
    [ -x "$(bin_of "$v")" ] || die "$v is not built - run ./a build $v"
    variants+=("$v")
  done
else
  for v in "${TRIAGE_VARIANTS[@]}"; do
    [ -x "$(bin_of "$v")" ] && variants+=("$v")
  done
fi
[ "${#variants[@]}" -gt 0 ] || die "no runnable build - run ./a build"

# Which artifacts.
artifacts=()
if [ -n "$INPUT" ]; then
  [ -f "$INPUT" ] || die "no such file: $INPUT"
  artifacts+=("$INPUT")
else
  while IFS= read -r -d '' f; do artifacts+=("$f"); done \
    < <(find "$OUT_DIR"/*/"$WHAT" -name 'id:*' -type f -print0 2>/dev/null)
fi
[ "${#artifacts[@]}" -gt 0 ] || { log_warn "no $WHAT under $OUT_DIR"; exit 0; }

ensure_dirs "$LOG_DIR"

# One replay: artifact x variant -> its log. Runs as a background job, so it
# reports through the log file and the exit status only.
replay_one() { # replay_one <artifact> <variant> <logfile>
  local f="$1" v="$2" log_file="$3" san_env rc
  san_env="$(triage_env_for "$v")"
  {
    echo "### artifact : $f"
    echo "### variant  : $v ($(bin_of "$v"))"
    echo "### options  : $san_env"
    echo "###"
    # timeout's own exit status, not the container's: 124 means the replay hung
    # (a deep-recursion input under MSAN, a thread that never joins), and a log
    # that just stops is indistinguishable from a clean run otherwise.
    # The subshell matters: a replay that aborts makes the shell that reaped it
    # print "Aborted (core dumped)". Inside ( ) that notice goes to the log
    # with everything else instead of onto the terminal.
    ( afl_run $(env_args "$san_env" \
                         "UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1:symbolize=1" \
                         "TC=") $(backend_extra_for "$v") -- \
        "timeout $REPLAY_TIMEOUT $(cpath "$(bin_of "$v")") $(cpath "$f")" ) 2>&1
    rc=$?
    [ "$rc" -eq 124 ] && echo "### TIMED OUT after ${REPLAY_TIMEOUT}s"
    echo "### exit: $rc"
  } >"$log_file"
}

planned=0; skipped=0
todo=()
for f in "${artifacts[@]}"; do
  inst="$(basename "$(dirname "$(dirname "$f")")")"
  # printf, not echo: tr turns the trailing newline into an underscore too.
  safe="$(printf '%s' "$(basename "$f")" | tr -c 'A-Za-z0-9_.:,+' _)"

  for v in "${variants[@]}"; do
    log_file="$LOG_DIR/${inst}__${safe}__${v}.log"
    if [ "$ALL" = 0 ] && [ -s "$log_file" ]; then
      skipped=$((skipped + 1))
      continue
    fi
    todo+=("$f|$v|$log_file")
    planned=$((planned + 1))
  done
done

[ "$planned" -gt 0 ] || { log_ok "nothing to do (${skipped} artifact/variant pairs already have logs)"; exit 0; }

log "replaying ${#artifacts[@]} $WHAT through: ${variants[*]}  ($planned runs, $PAR at a time, timeout ${REPLAY_TIMEOUT}s)"

# A plain job pool: keep at most $PAR replays in flight, reap with `wait -n`.
# Replays share nothing - separate containers, separate log files - so there is
# nothing to serialise beyond not oversubscribing the box.
for entry in "${todo[@]}"; do
  IFS='|' read -r f v log_file <<<"$entry"
  while [ "$(jobs -rp | wc -l)" -ge "$PAR" ]; do wait -n; done
  replay_one "$f" "$v" "$log_file" &
done
wait

# `|| true`: grep exits 1 when nothing matched and this script runs with
# pipefail, which would otherwise end the run right before the summary.
timed_out="$(grep -l '^### TIMED OUT' "$LOG_DIR"/*.log 2>/dev/null | wc -l || true)"
if [ "${timed_out:-0}" -gt 0 ]; then
  log_warn "$timed_out log(s) hit the ${REPLAY_TIMEOUT}s timeout - raise it with --timeout"
fi

log_ok "wrote $planned log(s) to $LOG_DIR${skipped:+, skipped $skipped existing}"
