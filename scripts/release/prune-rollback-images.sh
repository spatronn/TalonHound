#!/usr/bin/env bash
# Bounded retention for TalonHound rollback image tags (deployment tooling only;
# the application never runs this).
#
#   scripts/release/prune-rollback-images.sh            # dry run (default)
#   scripts/release/prune-rollback-images.sh --apply    # remove expired tags
#
# Options / env:
#   --keep N    | TALONHOUND_ROLLBACK_KEEP (default 2, minimum 2) complete generations kept
#   --prefix P  | TALONHOUND_IMAGE_PREFIX  (default talonhound-) image repository prefix
#
# Only `<prefix>*:rollback-*` tags are considered. Images used by any container
# (running or stopped) are never removed. Tags are removed with plain
# `docker rmi <repo:tag>` (never --force); a tag whose image has other tags is
# only untagged.
set -euo pipefail

ROOT="${TALONHOUND_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
KEEP="${TALONHOUND_ROLLBACK_KEEP:-2}"
PREFIX="${TALONHOUND_IMAGE_PREFIX:-talonhound-}"
APPLY=0

while [ $# -gt 0 ]; do
  case "$1" in
    --apply) APPLY=1 ;;
    --keep) KEEP="${2:?--keep needs a value}"; shift ;;
    --prefix) PREFIX="${2:?--prefix needs a value}"; shift ;;
    -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

inventory() {
  local images in_use
  images="$(docker image ls --no-trunc --format '{{json .}}' | paste -sd, -)"
  in_use="$(docker ps -aq --no-trunc | xargs -r docker inspect -f '"{{.Image}}"' | paste -sd, -)"
  printf '{"images":[%s],"inUseImageIds":[%s]}' "$images" "$in_use"
}

# Planner runs on host Node when present, otherwise inside the backend image
# (which ships Node) with only this directory mounted read-only.
plan() {
  local script_dir="$ROOT/scripts/release"
  local args=(--keep "$KEEP" --prefix "$PREFIX" --format lines)
  if command -v node >/dev/null 2>&1; then
    node "$script_dir/rollback-image-retention.js" "${args[@]}"
  else
    docker run --rm -i --network none -v "$script_dir:/planner:ro" \
      "${TALONHOUND_PLANNER_IMAGE:-${PREFIX}backend:local}" \
      node /planner/rollback-image-retention.js "${args[@]}"
  fi
}

plan_lines="$(inventory | plan)"

echo "Rollback image retention (keep=${KEEP}, prefix=${PREFIX}, mode=$([ "$APPLY" = 1 ] && echo apply || echo dry-run))"
kept="$(printf '%s\n' "$plan_lines" | awk '$1=="KEEP"{print $2}' | paste -sd' ' -)"
echo "  kept generations: ${kept:-none}"
printf '%s\n' "$plan_lines" | awk '$1=="SKIP"{print "  skipped (in use) " $2}'

failed=0
removed=0
while read -r kind ref; do
  [ "$kind" = "REMOVE" ] || continue
  case "$ref" in
    "${PREFIX}"*:rollback-*) ;;
    *) echo "  refusing unexpected ref: $ref" >&2; failed=1; continue ;;
  esac
  removed=$((removed + 1))
  if [ "$APPLY" = 1 ]; then
    if docker rmi "$ref" >/dev/null; then
      echo "  removed $ref"
    else
      echo "  FAILED  $ref" >&2
      failed=1
    fi
  else
    echo "  would remove $ref"
  fi
done <<< "$plan_lines"

[ "$removed" -gt 0 ] || echo "  nothing to remove"
exit "$failed"
