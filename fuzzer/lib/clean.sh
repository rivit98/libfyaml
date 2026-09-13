# Remove what a campaign leaves behind. Nothing here is irreplaceable except
# `crashes` - everything else is rebuilt or re-derived by another command.
#
#   ./a clean               # what is safe to lose: builds, logs, coverage
#   ./a clean --all         # everything below, crashes included
#   ./a clean <target>...   # exactly these
#
# Targets:
#   builds     fuzzer/build/*            every variant, rebuilt by `build`
#   logs       $LOG_DIR                  triage replays and per-instance logs
#   coverage   $CAMPAIGN_DIR/cov, HTML   rebuilt by `coverage`
#   state      $OUT_DIR                  the AFL queues - ends any resume
#   crashes    the crashes/ and hangs/ dirs inside $OUT_DIR  - FINDINGS
#   containers leftover $CONTAINER_PREFIX-* docker containers
#
# `state` and `crashes` are never in the default set: a campaign you can still
# resume, and the artifacts you have not reported yet, are not scratch data.

# Seeds are not a target: they are slow to rebuild, they are what a campaign
# starts from, and `seeds --force` already rebuilds them on demand.
DEFAULT_TARGETS=(builds logs coverage containers)
ALL_TARGETS=(builds logs coverage state crashes containers)

target_paths() { # paths a target owns, one per line
  case "$1" in
    builds)   echo "$BUILD_ROOT" ;;
    logs)     echo "$LOG_DIR" ;;
    coverage) echo "$CAMPAIGN_DIR/cov"; echo "$CAMPAIGN_DIR/coverage_html"; echo "$REPO_DIR/lcov.info" ;;
    state)    echo "$OUT_DIR" ;;
    crashes)  ls -d "$OUT_DIR"/*/crashes "$OUT_DIR"/*/hangs 2>/dev/null || true ;;
    containers) ;;   # not a path
  esac
}

clean_target() {
  local t="$1" p n
  case "$t" in
    containers)
      n="$(docker ps -aq --filter "name=^${CONTAINER_PREFIX}-" 2>/dev/null | wc -l)"
      if [ "$n" -gt 0 ]; then
        docker rm -f $(docker ps -aq --filter "name=^${CONTAINER_PREFIX}-") >/dev/null 2>&1 || true
        log_ok "removed $n container(s)"
      fi
      return 0 ;;
  esac

  local freed=0
  while IFS= read -r p; do
    [ -e "$p" ] || continue
    # Never let an unset variable turn this into `rm -rf /`.
    case "$p" in ""|"/"|"$HOME") die "refusing to remove '$p'" ;; esac
    freed=1
    rm -rf -- "$p"
  done < <(target_paths "$t")
  [ "$freed" = 1 ] && log_ok "cleaned $t" || log "$t: nothing to remove"
  return 0
}

targets=()
case "${1:-}" in
  --all)  targets=("${ALL_TARGETS[@]}") ;;
  "")     targets=("${DEFAULT_TARGETS[@]}") ;;
  -*)     die "usage: $PROG clean [--all|<target>...]  (targets: ${ALL_TARGETS[*]})" ;;
  *)
    for t in "$@"; do
      found=0
      for known in "${ALL_TARGETS[@]}"; do [ "$t" = "$known" ] && found=1; done
      [ "$found" = 1 ] || die "unknown target '$t' (${ALL_TARGETS[*]})"
      targets+=("$t")
    done ;;
esac

# Stop the user from deleting a queue out from under a running campaign.
for t in "${targets[@]}"; do
  case "$t" in
    state|crashes)
      [ "$(running_instances)" -gt 0 ] && \
        die "a campaign is still running - ./a stop first (or clean something else)" ;;
  esac
done

log "cleaning: ${targets[*]}"
for t in "${targets[@]}"; do clean_target "$t"; done
