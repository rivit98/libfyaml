# The seed corpora, one directory per test group.
#
#   ./a seeds                        # what each group holds
#   ./a seeds --import DIR           # add DIR's files to a group's seeds
#   ./a seeds --cmin                 # re-minimize the seeds in place
#   ./a seeds --group path ...       # restrict either of those to one group
#
# Seeds live in fuzzer/seeds/<group>/ and are checked in: they are an input to
# the campaign, not an artifact of it, and rebuilding them from scratch on
# another machine would need the same external corpora to be lying around.
# Nothing writes to them except the two commands above - afl-fuzz only reads -i.
#
# Every seed carries the harness's 4-byte flag prefix: LLVMFuzzerTestOneInput()
# reads bytes 0..3 as the flag seed and hands byte 4 onward to the test cases.
# --import adds it (once per prefix below); by hand it is
#
#   { printf '\x00\x00\x00\x00'; cat doc.yaml; } > fuzzer/seeds/yaml/doc
#
# Groups and the test cases they feed are defined in lib/common.sh. A group is
# minimized under its own TC=, so a seed is kept only if it adds coverage in
# the code that group actually feeds.

MODE=list; IMPORT_DIR=""; ONLY_GROUP=""
while [ $# -gt 0 ]; do
  case "$1" in
    --import) MODE=import; IMPORT_DIR="$2"; shift ;;
    --cmin)   MODE=cmin ;;
    --group)  ONLY_GROUP="$2"; shift ;;
    *) die "usage: $PROG seeds [--import DIR] [--cmin] [--group <${SEED_GROUPS[*]}>]" ;;
  esac
  shift
done

FLAG_PREFIXES=('\x00\x00\x00\x00' '\x2a\x13\x7f\x01' '\xff\xff\xff\xff')

groups=("${SEED_GROUPS[@]}")
if [ -n "$ONLY_GROUP" ]; then
  [ -n "$(group_tc "$ONLY_GROUP")" ] || die "unknown group '$ONLY_GROUP' (${SEED_GROUPS[*]})"
  groups=("$ONLY_GROUP")
fi

# afl-cmin over <dir>, in place. @@ matters: without it the input goes through
# AFL's shared-memory path, which the AFLDriver target only honours under
# afl-fuzz - under showmap it runs on an empty buffer and the corpus collapses
# to a single file.
cmin_into() { # cmin_into <group> <dir>
  local group="$1" dir="$2" tc tmp before
  tc="$(group_tc "$group")"
  tmp="$dir.cmin.$$"
  before="$(count_files "$dir")"

  require_backend
  log "$group: afl-cmin over $before seeds, TC=$tc"
  rm -rf "$tmp"
  afl_run -n "$CONTAINER_PREFIX-cmin-$group" $(env_args "${AFL_ENV[@]}" "TC=$tc") -- \
    "afl-cmin -T all -i $(cpath "$dir") -o $(cpath "$tmp") -m none -t $TIMEOUT_FAST -- $B_BIN_FAST @@" >/dev/null

  if [ -n "$(ls -A "$tmp" 2>/dev/null)" ]; then
    rm -rf "${dir:?}"; mv "$tmp" "$dir"
    log_ok "$group: $before -> $(count_files "$dir") seeds"
  else
    rm -rf "$tmp"
    log_err "$group: afl-cmin produced nothing, keeping the $before seeds it had"
  fi
}

case "$MODE" in
  list)
    for g in "${groups[@]}"; do
      printf '%-6s %4s seeds  %-42s %s\n' \
        "$g" "$(count_files "$SEED_ROOT/$g")" "$(group_tc "$g")" "$SEED_ROOT/$g"
    done ;;

  import)
    [ -d "$IMPORT_DIR" ] || die "no such directory: $IMPORT_DIR"
    [ "${#groups[@]}" -eq 1 ] || die "--import needs --group (${SEED_GROUPS[*]})"
    g="${groups[0]}"
    dir="$SEED_ROOT/$g"
    ensure_dirs "$dir"

    n=0; added=0
    while IFS= read -r f; do
      base="$(printf '%s' "$(basename "$f")" | tr -c 'A-Za-z0-9_.' _)"
      for p in "${FLAG_PREFIXES[@]}"; do
        out="$dir/imported_$(printf '%05d' "$n")_$base"
        { printf '%b' "$p"; cat "$f"; } > "$out"
        # Anything shorter than the prefix plus one byte exercises nothing.
        [ "$(stat -c%s "$out")" -ge "$MIN_SEED_BYTES" ] && added=$((added + 1)) || rm -f "$out"
        n=$((n + 1))
      done
    done < <(find "$IMPORT_DIR" -type f -size -64k 2>/dev/null || true)

    [ "$added" -gt 0 ] || die "$g: nothing usable in $IMPORT_DIR"
    log_ok "$g: imported $added seeds from $IMPORT_DIR"
    [ -x "$BIN_FAST" ] && cmin_into "$g" "$dir" \
      || log_warn "no $BIN_FAST - skipping afl-cmin (./a build fast, then ./a seeds --cmin --group $g)" ;;

  cmin)
    [ -x "$BIN_FAST" ] || die "$BIN_FAST missing - run ./a build fast"
    for g in "${groups[@]}"; do
      [ -n "$(ls -A "$SEED_ROOT/$g" 2>/dev/null)" ] || { log_warn "$g: no seeds"; continue; }
      cmin_into "$g" "$SEED_ROOT/$g"
    done ;;
esac
