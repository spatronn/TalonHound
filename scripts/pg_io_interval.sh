#!/usr/bin/env bash
# Capture PostgreSQL container single-device cgroup read/write rates.
set -euo pipefail
INTERVAL="${1:-900}"
OUT="/tmp/pg_io_pf_remediation_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUT"
CID="$(docker ps -qf name=talonhound-db-1)"
if [ -z "$CID" ]; then CID="$(docker ps -qf name=postgres)"; fi
DEV="259:0"
read_cgroup() {
  local key="$1"
  awk -v k="$key" -v d="$DEV" '$1==d {for(i=1;i<=NF;i++) if($i ~ "^"k"=") {split($i,a,"="); print a[2]}}' \
    "/sys/fs/cgroup/system.slice/docker-${CID}.scope/io.stat" 2>/dev/null \
    || awk -v k="$key" -v d="$DEV" '$1==d {for(i=1;i<=NF;i++) if($i ~ "^"k"=") {split($i,a,"="); print a[2]}}' \
    "/sys/fs/cgroup/docker/${CID}/io.stat" 2>/dev/null || echo 0
}
T0_R="$(read_cgroup rbytes)"; T0_W="$(read_cgroup wbytes)"
date -Is > "$OUT/start.txt"
echo "interval_sec=$INTERVAL" >> "$OUT/start.txt"
echo "rbytes0=$T0_R wbytes0=$T0_W" >> "$OUT/start.txt"
sleep "$INTERVAL"
T1_R="$(read_cgroup rbytes)"; T1_W="$(read_cgroup wbytes)"
date -Is > "$OUT/end.txt"
echo "rbytes1=$T1_R wbytes1=$T1_W" >> "$OUT/end.txt"
python3 - "$T0_R" "$T1_R" "$T0_W" "$T1_W" "$INTERVAL" "$OUT" <<'PY'
import sys
r0,r1,w0,w1,sec,out=sys.argv[1:6]
r0,r1,w0,w1,sec=float(r0),float(r1),float(w0),float(w1),float(sec)
dr, dw = max(r1-r0,0), max(w1-w0,0)
hr = 3600/sec
print(f"read_GB_h={dr/1e9*hr:.3f}")
print(f"write_GB_h={dw/1e9*hr:.3f}")
open(f"{out}/delta.txt","w").write(f"read_GB_h={dr/1e9*hr:.3f}\nwrite_GB_h={dw/1e9*hr:.3f}\n")
PY
