# Start the multi-core AFL++ campaign in tmux, one instance per tab.
#
#   ./a run                 # JOBS instances (one per physical core), then attach
#   JOBS=12 ./a run         # override the instance count
#   FUZZ_PLAN=32 ./a run    # force a plan: plans/<name>.plan, or a path
#   FUZZ_GROUP=path ./a run # a different seed group (own seeds, state, session)
#   TC=test_scanf ./a run   # restrict every instance to one test case
#
# Window 0 is the campaign dashboard (`./a status --loop`); windows 1..N are the
# fuzzer instances, one per tab, named after the instance.  Each instance is
# pinned to one physical core (docker --cpuset-cpus, or taskset on the host
# backend), so they never fight over a core - AFL's own affinity logic cannot
# see across containers, which is why AFL_NO_AFFINITY is set.
#
# ── plans ─────────────────────────────────────────────────────────────────────
# The instance mix lives in plans/<lanes>.plan, one lane per line:
#
#   name | variant | afl-fuzz args | env
#
#   name     tab, container and -S name.  The lane called `main` is the -M
#            primary; every other lane gets `-S <name> -z` - deterministic
#            mutations produce the same inputs on every instance that runs
#            them, and AFL++ >= 4.20 runs them on all of them unless told not to.
#   variant  the build the lane executes (fast, asan, laf, lsan, tsan, ...)
#   args     afl-fuzz options, with these tokens expanded:
#              DICT          $DICT
#              CMPLOG        the cmplog build          (lane skipped if unbuilt)
#              FMT           text, or binary for the blob group  (-a FMT)
#              ASAN_ORACLE   the sand-asan build       (-w dropped if unbuilt)
#              MSAN_ORACLE   the sand-msan build       (-w dropped if unbuilt)
#              TIMEOUT_SAN, TIMEOUT_MSAN   the sanitizer -t values
#            A lane without -t gets TIMEOUT_FAST.
#   env      space-separated K=V added to the lane, or empty
#
# FUZZ_PLAN=auto takes the smallest plan with at least JOBS lanes and runs its
# first JOBS lanes, so every plan is ordered by what to keep when cores are
# short.  Why the plans look the way they do: README.md, "The instance mix".
# All instances share one -o directory and sync through it.


skipped=()
[ $# -eq 0 ] || die "usage: $PROG run   (options live in the environment: JOBS, FUZZ_PLAN, FUZZ_GROUP, TC)"

require_backend

# ── instance plan ─────────────────────────────────────────────────────────────
plan_lines() { grep -vE '^[[:space:]]*(#|$)' "$1"; }
trim() { local s="$1"; s="${s#"${s%%[![:space:]]*}"}"; printf '%s' "${s%"${s##*[![:space:]]}"}"; }

case "$FUZZ_PLAN" in
  auto)
    PLAN_FILE=""
    while IFS= read -r f; do
      PLAN_FILE="$f"
      [ "$(plan_lines "$f" | wc -l)" -ge "$JOBS" ] && break
    done < <(find "$PLAN_DIR" -maxdepth 1 -name '*.plan' 2>/dev/null | sort -V)
    ;;
  */*) PLAN_FILE="$FUZZ_PLAN" ;;
  *)   PLAN_FILE="$PLAN_DIR/$FUZZ_PLAN.plan" ;;
esac
[ -n "$PLAN_FILE" ] && [ -f "$PLAN_FILE" ] || die "no plan '${PLAN_FILE:-$PLAN_DIR/*.plan}'"

# A lane whose build is missing is dropped rather than failing the campaign,
# and so is a SAND oracle: the lane then runs without that -w.
PLAN=(); dropped_oracles=()
while IFS='|' read -r _n _v _a _e; do
  _n="$(trim "$_n")"; _v="$(trim "$_v")"; _a="$(trim "$_a")"; _e="$(trim "$_e")"
  if [ ! -x "$(bin_of "$_v")" ]; then
    skipped+=("$_n (no $_v build)"); continue
  fi
  if [[ " $_a " == *" CMPLOG "* ]] && [ ! -x "$BIN_CMPLOG" ]; then
    skipped+=("$_n (no cmplog build)"); continue
  fi
  for _o in ASAN_ORACLE:sand-asan MSAN_ORACLE:sand-msan; do
    if [[ " $_a " == *" ${_o%%:*} "* ]] && [ ! -x "$(bin_of "${_o#*:}")" ]; then
      _a="$(trim "${_a//-w ${_o%%:*}/}")"
      dropped_oracles+=("${_o#*:}")
    fi
  done
  PLAN+=("$_n|$_v|$_a|$_e")
done < <(plan_lines "$PLAN_FILE")
[ "${#skipped[@]}" -gt 0 ] && log_warn "skipping ${skipped[*]}"
[ "${#dropped_oracles[@]}" -gt 0 ] && \
  log_warn "running without SAND oracle(s) $(printf '%s\n' "${dropped_oracles[@]}" | sort -u | tr '\n' ' ')- ./a build sand-asan sand-msan"
[ "${#PLAN[@]}" -gt 0 ] || die "$PLAN_FILE: no runnable lane"

if [ "$JOBS" -gt "${#PLAN[@]}" ]; then
  log_warn "capping JOBS at ${#PLAN[@]} lanes in $PLAN_FILE"
  JOBS="${#PLAN[@]}"
fi

mapfile -t CORES < <(core_list)
[ "$JOBS" -gt "${#CORES[@]}" ] && \
  log_warn "JOBS=$JOBS on ${#CORES[@]} physical cores - instances will share cores"

instance_cmd() { # <plan index> -> the full host-side command for that tab
  local idx="$1" entry name variant args extra binpath core role extra_env
  entry="${PLAN[$idx]}"
  IFS='|' read -r name variant args extra <<<"$entry"

  binpath="$(b_bin_of "$variant")"
  args="${args//DICT/$B_DICT}"
  args="${args//CMPLOG/$B_BIN_CMPLOG}"
  args="${args//FMT/$(group_format "$FUZZ_GROUP")}"
  args="${args//ASAN_ORACLE/$(b_bin_of sand-asan)}"
  args="${args//MSAN_ORACLE/$(b_bin_of sand-msan)}"
  args="${args//TIMEOUT_MSAN/$TIMEOUT_MSAN}"
  args="${args//TIMEOUT_SAN/$TIMEOUT_SAN}"
  [[ " $args " == *" -t "* ]] || args="$args -t $TIMEOUT_FAST"
  if [ "$name" = main ]; then role="-M main"; else role="-S $name -z"; fi
  core="${CORES[$((idx % ${#CORES[@]}))]}"

  # AFL_FORCE_UI: the tab pipes afl-fuzz into the log filter, so afl-fuzz sees a
  # pipe on stdout and would drop to its non-tty mode - one plain-text line per
  # fuzzed queue entry, thousands a minute scrolling past in every tab.  Forcing
  # the UI keeps the single self-refreshing status screen instead.
  local envs=("${AFL_ENV[@]}" "${SAN_ENV[@]}" AFL_FORCE_UI=1)
  # A campaign against one test case: TC= reaches the instances explicitly,
  # because the backends deliberately do not inherit it (see afl_run).
  [ -n "${TC:-}" ] && envs+=("TC=$TC")
  # The lsan lane is the one place leak detection is wanted; it overrides the
  # detect_leaks=0 the other lanes run with.
  [ "$variant" = lsan ] && envs+=("${LSAN_LANE_ENV[@]}")
  read -r -a extra_env <<<"$extra"
  [ "${#extra_env[@]}" -gt 0 ] && envs+=("${extra_env[@]}")

  # Each tab is its own shell: it has to pull in the same configuration the
  # dispatcher would have given it before afl_run exists.
  # tee /dev/tty puts the raw stream (status screen included) on the pane; the
  # log only gets what log_filter keeps.
  printf 'export FUZZ_ROOT=%q; source %q && afl_run -n %q -c %q %s%s -- %q 2>&1 | tee /dev/tty | log_filter >> %q' \
    "$FUZZ_ROOT" "$LIB_DIR/common.sh" \
    "$CONTAINER_PREFIX-$name" "$core" \
    "$(env_args "${envs[@]}")" "$(backend_extra_for "$variant")" \
    "afl-fuzz -i $B_SEED_DIR -o $B_OUT_DIR -G $FUZZ_MAX_LEN -m none $role $args -- $binpath" \
    "$LOG_DIR/$name.log"
}

for b in "$BIN_FAST" "$BIN_ASAN" "$BIN_CMPLOG"; do
  [ -x "$b" ] || { echo "error: $b missing - run ./a build" >&2; exit 1; }
done
[ -n "$(ls -A "$SEED_DIR" 2>/dev/null)" ] || { echo "error: no seeds - run ./a seeds" >&2; exit 1; }

ensure_dirs "$OUT_DIR" "$LOG_DIR"

if tmux has-session -t "$TMUX_SESSION" 2>/dev/null; then
  log_warn "session '$TMUX_SESSION' is already running - attaching"
  exec tmux attach -t "$TMUX_SESSION"
fi

# A leftover container from a killed session would make docker refuse the name.
if [ "$FUZZ_BACKEND" = docker ]; then
  docker rm -f $(docker ps -aq --filter "name=^${CONTAINER_PREFIX}-" 2>/dev/null) >/dev/null 2>&1 || true
fi

# Window 0: the dashboard.  Never a fuzzer, so Ctrl-C in it kills nothing.
tmux new-session -d -s "$TMUX_SESSION" -n health "$FUZZ_ROOT/a status --loop"
tmux set-option -t "$TMUX_SESSION" -g remain-on-exit on >/dev/null
tmux set-option -t "$TMUX_SESSION" -g history-limit 20000 >/dev/null

# Windows are appended rather than placed at a fixed index: a user tmux.conf
# with base-index 1 would otherwise collide with the dashboard.
for i in $(seq 0 $((JOBS - 1))); do
  tmux new-window -a -t "$TMUX_SESSION:" -n "${PLAN[$i]%%|*}" "$(instance_cmd "$i")"
  sleep 0.5   # stagger the startup so the instances calibrate one at a time
done

tmux select-window -t "$TMUX_SESSION:health"

log_ok "campaign '$TMUX_SESSION' started: $JOBS lanes of $(basename "$PLAN_FILE") on cores ${CORES[*]:0:$JOBS}"
log "detach with C-b d; ./a status from anywhere; ./a stop to end it"

# Attaching is the point of starting a campaign: window 0 is the dashboard.
# Detaching leaves everything running.
exec tmux attach -t "$TMUX_SESSION"
