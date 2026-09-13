# Campaign dashboard and health check - window 0 of the tmux session.
#
#   ./a status            # print once
#   ./a status --loop     # refresh every $REFRESH seconds (default 15)
#   ./a status --json     # machine-readable per-instance stats
#
# Reads $OUT_DIR/*/fuzzer_stats directly rather than relying on afl-whatsup, so
# it still works when the instances are wedged; afl-whatsup's summary is
# appended when the binary is available.


REFRESH="${REFRESH:-60}"

# Health thresholds - a line is flagged when it crosses one of these.
MIN_STABILITY="${MIN_STABILITY:-85}"     # %, below this the target is non-deterministic
STALE_INSTANCE="${STALE_INSTANCE:-120}"  # s since last fuzzer_stats update = dead
STALE_FIND="${STALE_FIND:-3600}"         # s without a new path = plateau

# The shared palette from common.sh, aliased to the short names this file uses.
c_red="$C_RED"; c_grn="$C_GRN"; c_yel="$C_YEL"; c_dim="$C_DIM"; c_off="$C_OFF"

stat_of() { sed -n "s/^$2 *: *//p" "$1" | head -1 | tr -d ' '; }

num() { local v="${1%%.*}"; v="${v//[^0-9-]/}"; echo "${v:-0}"; }

# bitmap_cvg is AFL's own coverage number: the share of the edge map this
# instance has reached. Per instance, not campaign-wide - the lanes sync, so
# they converge, and one lane sitting well below the others is the signal.
collect() {  # emits: name execs_ps coverage corpus crashes hangs stability cycles pending last_find_age last_update_age
  local now; now="$(date +%s)"
  local f
  for f in "$OUT_DIR"/*/fuzzer_stats; do
    [ -f "$f" ] || continue
    local name last_find last_update execs
    name="$(basename "$(dirname "$f")")"
    last_find="$(num "$(stat_of "$f" last_find)")"
    last_update="$(num "$(stat_of "$f" last_update)")"
    # AFL reports a nonsense execs_per_sec until the first second of real
    # fuzzing has elapsed; prefer the last-minute average once it exists.
    execs="$(num "$(stat_of "$f" execs_ps_last_min)")"
    if [ "$execs" -le 0 ]; then
      if [ $(( now - $(num "$(stat_of "$f" start_time)") )) -lt 90 ]; then
        execs=-1                                  # still calibrating: warmup
      else
        execs="$(num "$(stat_of "$f" execs_per_sec)")"
      fi
    fi
    printf '%s %s %s %s %s %s %s %s %s %s %s\n' \
      "$name" \
      "$execs" \
      "$(stat_of "$f" bitmap_cvg | tr -d '%' | sed 's/^$/0/')" \
      "$(num "$(stat_of "$f" corpus_count)")" \
      "$(num "$(stat_of "$f" saved_crashes)")" \
      "$(num "$(stat_of "$f" saved_hangs)")" \
      "$(num "$(stat_of "$f" stability)")" \
      "$(num "$(stat_of "$f" cycles_done)")" \
      "$(num "$(stat_of "$f" pending_total)")" \
      "$([ "$last_find" -gt 0 ] && echo $(( now - last_find )) || echo -1)" \
      "$(( now - last_update ))"
  done
}

print_json() {
  echo '['
  local first=1
  while read -r n e cov c cr h st cy pd lf lu; do
    [ "$first" = 1 ] || echo ','
    first=0
    printf '  {"instance":"%s","execs_per_sec":%s,"coverage_pct":%s,"corpus":%s,"crashes":%s,"hangs":%s,"stability":%s,"cycles":%s,"pending":%s,"last_find_s":%s,"last_update_s":%s}' \
      "$n" "${e:-0}" "${cov:-0}" "${c:-0}" "${cr:-0}" "${h:-0}" "${st:-0}" "${cy:-0}" "${pd:-0}" "${lf:-0}" "${lu:-0}"
  done < <(collect)
  echo; echo ']'
}

print_report() {
  local warn=() t_ex=0 t_cr=0 t_hg=0 t_cp=0 t_cov=0 n_inst=0 alive=0

  echo "${c_dim}$(date '+%F %T')${c_off}  campaign ${TMUX_SESSION}   state: $OUT_DIR"
  echo
  printf '%-10s %9s %8s %8s %8s %7s %9s %7s %9s %11s\n' \
    INSTANCE EXEC/S COVERAGE CORPUS CRASHES HANGS STABILITY CYCLES PENDING LAST-FIND
  printf '%s\n' "--------------------------------------------------------------------------------------------------"

  while read -r n e cov c cr h st cy pd lf lu; do
    n_inst=$((n_inst + 1))
    # bitmap_cvg carries two decimals and lanes differ in the second one, so
    # the max is a float comparison, not an integer one.
    awk -v a="$cov" -v b="$t_cov" 'BEGIN{exit !(a+0>b+0)}' && t_cov="$cov"
    [ "$e" -ge 0 ] && t_ex=$(( t_ex + e ))
    t_cr=$(( t_cr + cr )); t_hg=$(( t_hg + h ))
    [ "$c" -gt "$t_cp" ] && t_cp="$c"

    local mark="" color=""
    if [ "$lu" -gt "$STALE_INSTANCE" ]; then
      color="$c_red"; mark=" DEAD"; warn+=("$n: no fuzzer_stats update in $(human_age "$lu") - instance is dead or wedged")
    else
      alive=$((alive + 1))
      if [ "$st" -lt "$MIN_STABILITY" ]; then
        color="$c_yel"; warn+=("$n: stability ${st}% < ${MIN_STABILITY}% - non-deterministic paths, crashes may not replay")
      elif [ "$lf" -gt "$STALE_FIND" ] && [ "$cy" -gt 0 ] 2>/dev/null; then
        color="$c_dim"; warn+=("$n: no new path in $(human_age "$lf") - plateau, consider new seeds or a dictionary pass")
      fi
    fi
    [ "$cr" -gt 0 ] && color="${color:-$c_grn}"

    printf '%s%-10s %9s %7s%% %8s %8s %7s %8s%% %7s %9s %11s%s%s\n' \
      "$color" "$n" "$([ "$e" -ge 0 ] && echo "$e" || echo warmup)" \
      "$cov" "$c" "$cr" "$h" "$st" "$cy" "$pd" "$(human_age "$lf")" "$mark" "$c_off"
  done < <(collect | sort)

  echo
  printf 'instances %s/%s alive   total %s execs/sec   coverage %s%%   corpus %s   %scrashes %s%s   hangs %s\n' \
    "$alive" "$n_inst" "$t_ex" "$t_cov" "$t_cp" \
    "$([ "$t_cr" -gt 0 ] && echo "$c_grn")" "$t_cr" "$c_off" "$t_hg"

  # Box health: the things that silently ruin a campaign.
  local load shm_free disk_free
  load="$(cut -d' ' -f1 /proc/loadavg)"
  shm_free="$(df -h /dev/shm --output=avail 2>/dev/null | tail -1 | tr -d ' ')"
  disk_free="$(df -h "$OUT_DIR" --output=avail 2>/dev/null | tail -1 | tr -d ' ')"
  printf 'load %s (jobs %s)   /dev/shm free %s   state fs free %s\n' \
    "$load" "$JOBS" "${shm_free:-?}" "${disk_free:-?}"

  if [ "$n_inst" -eq 0 ]; then
    echo; echo "${c_yel}no instances yet - run ./a run${c_off}"
  fi
  if [ "$t_cr" -gt 0 ]; then
    echo; echo "${c_grn}$t_cr crash(es) waiting: $FUZZ_ROOT/a triage${c_off}"
  fi

  # Containers are the other half of "is it alive": a fuzzer_stats file keeps
  # its last values after the container behind it died.
  local n_ctr
  n_ctr="$(running_instances)"
  printf 'backend %s: %s instance(s) running\n' "$FUZZ_BACKEND" "$n_ctr"
  if [ "$n_inst" -gt 0 ] && [ "$n_ctr" -lt "$alive" ]; then
    warn+=("$((alive - n_ctr)) instance(s) have live stats but no process - a tab exited, check its tmux window")
  fi

  if [ "${#warn[@]}" -gt 0 ]; then
    echo; echo "${c_yel}health:${c_off}"
    printf '  - %s\n' "${warn[@]}"
  fi

  if [ "$n_inst" -gt 0 ]; then
    echo; echo "${c_dim}--- afl-whatsup ---${c_off}"
    afl_run -- "afl-whatsup -s $B_OUT_DIR" 2>/dev/null | tail -n 20
  fi
}

# Draw a pre-rendered frame. The report is built into a string FIRST and only
# then painted, so the terminal never shows a half-finished screen (collecting
# it takes a second - afl-whatsup runs the backend). Painting overwrites in
# place rather than running clear(1): clearing first would blank the screen for
# that second and make the tab flicker on every tick.
#
# Overwriting only replaces as many characters as the new line has, so every
# line ends in erase-to-end-of-line (\033[K) - without it, a line that got
# shorter since the last tick keeps the tail of the old one. \033[J then clears
# the rows below a frame that got shorter.
paint() {
  local frame="$1"
  frame="${frame//$'\n'/$'\033[K\n'}"
  # Cursor home, frame, erase to end - as escapes, so there is no tput to find.
  printf '\033[H%s\033[K\n\033[J' "$frame"
}

case "${1:-}" in
  --json) print_json ;;
  --loop)
    printf '\033[?25l'                                   # hide the cursor
    trap 'printf "\033[?25h"; exit 0' INT TERM EXIT      # ... and put it back
    clear
    while :; do
      frame="$(print_report; printf '\n%s' "${c_dim}refreshed $(date +%T), every ${REFRESH}s - this tab is a dashboard, Ctrl-C here kills no fuzzer${c_off}")"
      paint "$frame"
      sleep "$REFRESH"
    done ;;
  "") print_report ;;
  *) echo "usage: $PROG status [--loop|--json]" >&2; exit 1 ;;
esac
