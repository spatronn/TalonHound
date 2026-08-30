#!/usr/bin/env bash
# 60-minute PostgreSQL container cgroup I/O benchmark for Published Feed steady state.
set -euo pipefail
INTERVAL="${1:-3600}"
OUT="/tmp/pg_io_beta_signoff_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUT"
CID="$(docker ps -q --no-trunc -f name=talonhound-db-1)"
DEV="259:0"
io_stat_path() {
  local p="/sys/fs/cgroup/system.slice/docker-${CID}.scope/io.stat"
  if [ -r "$p" ]; then echo "$p"; return; fi
  p="/sys/fs/cgroup/docker/${CID}/io.stat"
  if [ -r "$p" ]; then echo "$p"; return; fi
  echo ""
}
read_val() {
  local key="$1"
  local path
  path="$(io_stat_path)"
  if [ -z "$path" ]; then echo 0; return; fi
  awk -v k="$key" -v d="$DEV" '$1==d {for(i=1;i<=NF;i++) if($i ~ "^"k"=") {split($i,a,"="); print a[2]}}' "$path"
}
date -Is | tee "$OUT/start.txt"
R0=$(read_val rbytes); W0=$(read_val wbytes)
RI0=$(read_val rios); WI0=$(read_val wios)
if [ "${R0:-0}" = "0" ] && [ "${W0:-0}" = "0" ]; then
  echo "ERROR: cgroup io.stat unreadable for container $CID" >&2
  exit 1
fi
echo "rbytes0=$R0 wbytes0=$W0 rios0=$RI0 wios0=$WI0 interval_sec=$INTERVAL" >> "$OUT/start.txt"
sleep "$INTERVAL"
date -Is | tee "$OUT/end.txt"
R1=$(read_val rbytes); W1=$(read_val wbytes)
RI1=$(read_val rios); WI1=$(read_val wios)
echo "rbytes1=$R1 wbytes1=$W1 rios1=$RI1 wios1=$WI1" >> "$OUT/end.txt"
python3 - "$R0" "$R1" "$W0" "$W1" "$INTERVAL" "$OUT/delta.txt" <<'PY'
import sys
r0, r1, w0, w1, sec, out = sys.argv[1:7]
r0, r1, w0, w1, sec = float(r0), float(r1), float(w0), float(w1), float(sec)
hr = 3600 / sec
dr, dw = max(r1 - r0, 0), max(w1 - w0, 0)
text = (
    f"interval_sec={sec}\n"
    f"read_GB_h={dr / 1e9 * hr:.3f}\n"
    f"write_GB_h={dw / 1e9 * hr:.3f}\n"
    f"rbytes_delta={int(dr)}\n"
    f"wbytes_delta={int(dw)}\n"
)
open(out, 'w').write(text)
print(text)
PY
echo "OUT=$OUT"
