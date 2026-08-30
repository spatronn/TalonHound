#!/usr/bin/env bash
set -euo pipefail
INTERVAL="${1:-300}"
CID="$(docker ps -q --no-trunc -f name=talonhound-db-1)"
DEV="259:0"
io_stat_path() {
  local p="/sys/fs/cgroup/system.slice/docker-${CID}.scope/io.stat"
  if [ -r "$p" ]; then echo "$p"; return; fi
  p="/sys/fs/cgroup/docker/${CID}/io.stat"
  if [ -r "$p" ]; then echo "$p"; return; fi
  echo ""
}
read_bytes() {
  local path
  path="$(io_stat_path)"
  if [ -z "$path" ]; then echo 0; return; fi
  awk -v d="$DEV" '$1==d {for(i=1;i<=NF;i++) if($i ~ /^rbytes=/) {split($i,a,"="); print a[2]}}' "$path"
}
write_bytes() {
  local path
  path="$(io_stat_path)"
  if [ -z "$path" ]; then echo 0; return; fi
  awk -v d="$DEV" '$1==d {for(i=1;i<=NF;i++) if($i ~ /^wbytes=/) {split($i,a,"="); print a[2]}}' "$path"
}
R0=$(read_bytes); W0=$(write_bytes)
sleep "$INTERVAL"
R1=$(read_bytes); W1=$(write_bytes)
DR=$((R1-R0)); DW=$((W1-W0))
python3 - <<PY
dr,dw,sec=$DR,$DW,$INTERVAL
hr=3600/sec
print(f"interval_sec={sec}")
print(f"read_GB_h={max(dr,0)/1e9*hr:.3f}")
print(f"write_GB_h={max(dw,0)/1e9*hr:.3f}")
PY
