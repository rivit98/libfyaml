# Replay every crash and hang of a campaign through `./fuzz triage`.
#
#   ./fuzz triage-all                   # the campaign's crashes, then its hangs
#   ./fuzz triage-all --with msan       # only the MSAN build
#   ./fuzz triage-all -j 16             # 16 replays at a time
#   ./fuzz triage-all --hang-limit 0    # every hang, not a sample
#   ./fuzz triage-all DIR...            # every file in DIR instead
#
# find lists the artifacts, xargs -P runs them: every replay is
# `./fuzz triage --with <variant> <artifact>` in a child process, so the
# sanitizer options, the log format and the atomic write live in triage.sh
# alone and cannot drift from a hand-run triage; the variant list and the log
# names come from common.sh, which both of them read. Nothing here reads a log
# beyond its exit line: the logs in $LOG_DIR are the product, for whatever
# processes them afterwards.
#
# One replay is one artifact under one variant. Not one artifact at a time:
# triage.sh replays an artifact's variants in parallel and then waits for all
# of them, so every artifact would cost its slowest variant - an MSAN run, or
# a hang that holds its core for the full --timeout - while the other cores sat
# idle. Handed to xargs one pair at a time, the replays keep every -j slot busy
# until the list runs out.
#
# Written for the machine that is fuzzing, next to a live campaign: every
# replay runs under nice -n 19, which leaves the lanes their CPU however many
# of them run. Under FUZZ_BACKEND=docker that nice level stays with the docker
# client and does not reach the container - lower -j there.
#
# Clean logs do not stay: when xargs is done, every log whose replay exited 0
# is removed and its name recorded in $LOG_DIR/clean.list (prune_logs below).
# Every other log stays: sanitizer reports, crashes, leaks, timeouts, and
# replays that failed to start.
#
# Resumable: triage.sh writes each log atomically, and a replay whose log is
# there - or whose name is in clean.list - is dropped before xargs starts, so
# an interrupted sweep continues where it stopped, and a sweep repeated after
# new crashes have landed replays only the new ones.

USAGE="usage: $PROG triage-all [-j N] [--with v1,v2] [--timeout S] [--hang-limit N] [DIR...]

  -j N            replays to run at once, xargs -P (default: \$JOBS, one per
                  physical core - $JOBS here)
  --with a,b      variants to replay (default: every built one of asan, msan,
                  lsan, fast)
  --timeout S     per-replay wall clock, passed to ./fuzz triage
  --hang-limit N  hangs to take per instance, evenly spaced through the sorted
                  directory (default: 5; 0 takes every hang)
  DIR...          triage every file in these directories instead of the
                  campaign's - a flat directory from ./fuzz grab, say. Taken in
                  full: --hang-limit applies only to a campaign's hangs/.

Replays every crash of \$OUT_DIR/<instance>/crashes, then a sample of every
\$OUT_DIR/<instance>/hangs, through ./fuzz triage - one artifact under one
variant per replay, -j replays at a time through xargs -P, each at nice -n 19
so a running campaign keeps its cores. FUZZ_GROUP picks the campaign, as everywhere else.

Prints progress and nothing else: the logs under \$LOG_DIR are the product, and
reaching a verdict about them is another tool's job. A replay whose log exists
is skipped before anything starts, so an interrupted sweep resumes.

At the end only the logs that hit something are left: a clean replay's log
(exit 0) is removed and its name added to \$LOG_DIR/clean.list, which later
sweeps count as done. ./fuzz clean logs forgets both.

A sample, not every hang, because a campaign saves far more hangs than crashes
(AFL++ stops at 512 per instance) and a replay of one costs the full timeout.
--hang-limit 0 when you want them all."
usage_guard "$@"

WITH=""; REPLAY_TIMEOUT=""; HANG_LIMIT=5; PAR="$JOBS"; DIRS=()
while [ $# -gt 0 ]; do
  case "$1" in
    -j)           [ $# -ge 2 ] || usage; PAR="$2"; shift ;;
    --with)       [ $# -ge 2 ] || usage; WITH="$2"; shift ;;
    --timeout)    [ $# -ge 2 ] || usage; REPLAY_TIMEOUT="$2"; shift ;;
    --hang-limit) [ $# -ge 2 ] || usage; HANG_LIMIT="$2"; shift ;;
    -*) usage ;;
    *)  DIRS+=("$1") ;;
  esac
  shift
done
case "$HANG_LIMIT" in ''|*[!0-9]*) usage ;; esac
case "$PAR" in ''|0|*[!0-9]*) usage ;; esac

# Fail here rather than once per replay: every replay needs the same backend
# and the same builds. A typo in --with or a missing build is reported once,
# with every bad name, exactly as ./fuzz triage would report it.
require_backend
triage_select_variants "$WITH"
variants=("${TRIAGE_RUN[@]}")

# What ./fuzz triage gets besides --with and the artifact. An array, so an
# empty option never becomes an empty argument; the ${x[@]+...} guard keeps
# bash from tripping over an empty one under set -u.
pass=()
if [ -n "$REPLAY_TIMEOUT" ]; then pass+=(--timeout "$REPLAY_TIMEOUT"); fi

# Every input find reaches from its arguments, sorted. AFL writes a README.txt
# into crashes/ and hangs/, and it is not an input.
inputs() { # inputs <find start and depth/path arguments...>
  find "$@" -type f ! -name README.txt | sort
}

# At most --hang-limit entries per directory, evenly spaced through its sorted
# list, first one included. The pick is a function of the list alone, so a
# second sweep replays the same hangs instead of a different fifth of them -
# and the ones it already logged are then skipped for free.
sample_per_dir() {
  awk -v limit="$HANG_LIMIT" '
    { d = $0; sub(/\/[^\/]*$/, "", d)
      if (!(d in n)) order[++nd] = d
      f[d, ++n[d]] = $0 }
    END {
      for (i = 1; i <= nd; i++) {
        d = order[i]; c = n[d]
        k = (limit > 0 && c > limit) ? limit : c
        for (j = 0; j < k; j++) print f[d, int(j * c / k) + 1]
      }
    }'
}

# Crashes first, every one of them, then the hangs: the crashes are what a
# campaign is for, and a sweep interrupted halfway should have spent its hours
# on those.
artifacts=()
if [ "${#DIRS[@]}" -gt 0 ]; then
  for d in "${DIRS[@]}"; do
    need_dir "$d"
    mapfile -t files < <(inputs "$d" -mindepth 1 -maxdepth 1)
    [ "${#files[@]}" -gt 0 ] || { log_warn "no files in $d"; continue; }
    artifacts+=("${files[@]}")
  done
else
  need_dir "$OUT_DIR" "no campaign state for '$CAMPAIGN_NAME'"
  mapfile -t crashes < <(inputs "$OUT_DIR" -mindepth 3 -maxdepth 3 -path "$OUT_DIR/*/crashes/*")
  mapfile -t hangs < <(inputs "$OUT_DIR" -mindepth 3 -maxdepth 3 -path "$OUT_DIR/*/hangs/*" | sample_per_dir)
  log "${#crashes[@]} crash(es), ${#hangs[@]} hang(s) - at most $HANG_LIMIT per instance (--hang-limit, 0 = all)"
  artifacts=(${crashes[@]+"${crashes[@]}"} ${hangs[@]+"${hangs[@]}"})
fi
[ "${#artifacts[@]}" -gt 0 ] || die "nothing to triage"

# The replays that came back clean, one log name per line. Their logs are gone
# (prune_logs), so this list is what keeps a later sweep from replaying them
# again. It sits in $LOG_DIR and is not a *.log, so ./fuzz clean logs removes
# it with the logs and whatever reads the logs never sees it.
CLEAN_LIST="$LOG_DIR/clean.list"
declare -A clean=()
if [ -f "$CLEAN_LIST" ]; then
  while IFS= read -r n; do [ -z "$n" ] || clean[$n]=1; done <"$CLEAN_LIST"
fi

# Removes every finished log in $LOG_DIR whose "### exit:" line says 0, after
# recording its name in clean.list - recorded first, so a sweep killed in
# between leaves a log that is also listed, never a clean replay that is
# neither. Exit 0 and nothing else: a sanitizer report, a signal, a leak (lsan's
# 23), a timeout (124) and a replay that never ran (2, 125-127) all stay.
# The whole directory, not only this sweep's logs: a hand-run ./fuzz triage or
# an interrupted sweep leaves clean logs behind too. A .tmp is a replay still
# running (or a killed one) and is not a *.log, so it is never touched.
prune_logs() {
  local gone
  # || true: grep -l exits 1 for a batch with no clean log, and xargs passes
  # that on as 123.
  gone="$(find "$LOG_DIR" -maxdepth 1 -type f -name '*.log' -print0 \
          | xargs -0 -r grep -lx -- '### exit: 0' || true)"
  if [ -z "$gone" ]; then log "no clean logs to remove"; return 0; fi
  sed 's|.*/||' <<<"$gone" >>"$CLEAN_LIST"
  xargs -d '\n' rm -f -- <<<"$gone"
  log "removed $(wc -l <<<"$gone") clean log(s) - recorded in $CLEAN_LIST"
}

# The replays as <variant> <artifact> pairs, artifact-major: every variant of
# the first crash, then of the next one, so the crashes still come before the
# hangs. A replay whose log is already there, or that clean.list names, is
# dropped here rather than handed to ./fuzz triage (which knows nothing of
# clean.list), so the counts below are the work that is left, and resuming a
# sweep of thousands does not start thousands of ./fuzz processes that do
# nothing.
pairs=(); logged=0; was_clean=0; prefix=""
for a in "${artifacts[@]}"; do
  triage_log_prefix prefix "$a"
  for v in "${variants[@]}"; do
    if   [ -s "${prefix}__${v}.log" ];                 then logged=$((logged + 1))
    elif [ -n "${clean[${prefix##*/}__${v}.log]+x}" ]; then was_clean=$((was_clean + 1))
    else pairs+=("$v" "$a")
    fi
  done
done

total=$(( ${#pairs[@]} / 2 ))
log "${#artifacts[@]} artifact(s) x ${#variants[@]} variant(s) (${variants[*]}): $total to replay, $logged already logged, $was_clean clean before -> $LOG_DIR"
# Pruned even with nothing to replay: a repeated sweep is how the clean logs of
# a hand-run triage, or of an interrupted sweep, get cleared.
[ "$total" -gt 0 ] || { prune_logs; log_ok "nothing left to replay"; exit 0; }
log "$PAR replay(s) at a time"

# Job control, so xargs and every replay under it run in a process group of
# their own: a Ctrl-C at the terminal then reaches this script alone and the
# trap below decides what happens to the replays, the same way it does for a
# `kill -INT` from elsewhere. It has to decide, because a sweep is hours long
# and meant to be interrupted, and the replays do not end by themselves - they
# are background jobs of a non-interactive shell (triage.sh's), which have
# SIGINT set to ignore, so without this they would keep -j cores of a fuzzing
# machine busy for the full --timeout after the sweep is gone. (Under
# FUZZ_BACKEND=docker the replay is a container; signalling the docker client
# does not stop it.)
set -m

# Every descendant of a pid. A replay is xargs -> nice/./fuzz triage -> a
# background subshell -> timeout -> the target, and `timeout` puts itself in a
# process group of its own (that is how it kills what it times out), so
# signalling xargs or its group leaves the targets running to the full
# --timeout. The list is collected before anything is killed, because a dead
# parent re-parents its children to init and they can no longer be found this
# way.
descendants() { # descendants <pid>
  local kids kid
  kids="$(ps -eo pid=,ppid= | awk -v p="$1" '$2 == p { print $1 }')"
  for kid in $kids; do
    printf '%s\n' "$kid"
    descendants "$kid"
  done
}

# Ends every replay in flight and leaves their .tmp logs behind, which the next
# sweep replaces.
xpid=""
on_signal() { # on_signal <exit status>
  trap - INT TERM
  local victims="" p
  # xargs first: it would report every replay the kill below ends.
  [ -z "$xpid" ] || victims="$xpid $(descendants "$xpid")"
  # SIGTERM, not SIGINT: triage.sh runs its replays as background jobs of a
  # non-interactive shell, and those have SIGINT set to ignore.
  for p in $victims; do kill -TERM "$p" 2>/dev/null || true; done
  log_warn "interrupted - run again to resume"
  exit "$1"
}
trap 'on_signal 130' INT
# TERM too: with -j replays in flight, a sweep killed from elsewhere would
# otherwise leave all of them running to the full --timeout.
trap 'on_signal 143' TERM

# -n 2: each ./fuzz triage gets one pair appended, "--with <variant>
# <artifact>". -d '\n': a path may hold spaces, never a newline (AFL names do
# not, and a pair is two lines). A failing ./fuzz triage does not stop xargs:
# the rest of the list still runs, and the failures surface as its exit status.
printf '%s\n' "${pairs[@]}" \
  | xargs -d '\n' -r -n 2 -P "$PAR" nice -n 19 "$REPO_DIR/fuzz" triage ${pass[@]+"${pass[@]}"} --with &
xpid=$!
rc=0; wait "$xpid" || rc=$?

# Also after a failure: the replays that did finish wrote complete logs.
prune_logs
[ "$rc" -eq 0 ] || die "some ./fuzz triage runs failed (xargs exit $rc) - see above; re-running resumes"
log_ok "$total replay(s) done - what they hit is in $LOG_DIR"
