#!/usr/bin/env bash
# Isolated end-to-end test of Threat Library worker startup recovery with real
# PostgreSQL, Redis/BullMQ and the real threat-library-worker.js process:
#
#   1. a "previous" worker process takes two analyses and is killed, leaving
#      their BullMQ jobs `active` under a 2 h lock (B owned + stale heartbeat,
#      C claimed but never owned); A is queued and never claimed
#   2. PostgreSQL is stopped and the new worker starts → recovery retries
#   3. PostgreSQL comes back after ~45 s → recovery completes on its own
#   4. every stranded job is delivered exactly once; the stale BullMQ jobs are
#      failed; the concurrency limit holds; a restart adds no deliveries
#
# Throwaway containers on an internal network only; no compose project, named
# volume or host port. Env: TALONHOUND_E2E_IMAGE (default talonhound-backend:local).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${TALONHOUND_E2E_IMAGE:-talonhound-backend:local}"
RUN="th-tlw-e2e-$$"
NET="$RUN-net"
WORK="$(mktemp -d "/tmp/${RUN}.XXXX")"
PGPW="p$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
RDPW="r$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
OUTAGE_SECONDS="${OUTAGE_SECONDS:-45}"

cleanup() {
  docker rm -f "$RUN-worker" "$RUN-worker2" "$RUN-pg" "$RUN-redis" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  docker run --rm -v "$WORK:/w" alpine:latest sh -c 'rm -rf /w/* /w/.[!.]*' >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT
step() { printf '\n[e2e] %s\n' "$*"; }
fail() { echo "[e2e] FAIL: $*" >&2; exit 1; }

docker network create --internal "$NET" >/dev/null
mkdir -p "$WORK/pgdata" "$WORK/tl"
docker run -d --name "$RUN-pg" --network "$NET" --network-alias pg -v "$WORK/pgdata:/var/lib/postgresql/data" \
  -e POSTGRES_USER=talonhound -e POSTGRES_PASSWORD="$PGPW" -e POSTGRES_DB=talonhound postgres:16-alpine >/dev/null
docker run -d --name "$RUN-redis" --network "$NET" --network-alias redis --tmpfs /data \
  redis:7-alpine redis-server --requirepass "$RDPW" --save "" >/dev/null
wait_pg() { for _ in $(seq 1 60); do docker exec "$RUN-pg" pg_isready -U talonhound -d talonhound >/dev/null 2>&1 && return 0; sleep 1; done; return 1; }
wait_pg || fail "postgres did not start"

ENV_ARGS=(-e DB_HOST=pg -e DB_USER=talonhound -e DB_PASSWORD="$PGPW" -e DB_NAME=talonhound
  -e REDIS_HOST=redis -e REDIS_PASSWORD="$RDPW" -e THREAT_LIBRARY_QUEUE_NAME=threat-library
  -e THREAT_LIBRARY_STORAGE_DIR=/work/tl -e THREAT_LIBRARY_WORKER_CONCURRENCY=2)
# This checkout's backend, next to the image's node_modules.
APP='cp -r /src/backend /tmp/app && rm -rf /tmp/app/node_modules && ln -s /app/node_modules /tmp/app/node_modules && cd /tmp/app'
node_run() { docker run --rm -i --network "$NET" -v "$ROOT:/src:ro" -v "$WORK:/work" "${ENV_ARGS[@]}" "$IMAGE" sh -c "$APP && \"\$@\"" sh "$@"; }

step "migrate"
node_run node migrate.js >/dev/null

step "seed: A queued; B owned+stale and C claimed, both active under a dead worker's 2 h lock"
node_run node --input-type=module -e '
import crypto from "node:crypto";
import pg from "pg";
import { Queue, Worker } from "bullmq";
import IORedis from "ioredis";
import { createThreatReport, createJob } from "./lib/threatLibrary/store.js";
import { claimJobOwnership } from "./lib/threatLibrary/jobOwnership.js";
import { getRedisUrl } from "./lib/redis-url.js";
const pool = new pg.Pool({ host: "pg", user: "talonhound", password: process.env.DB_PASSWORD, database: "talonhound" });
const mk = async (n) => { const r = await createThreatReport(pool, { title: "e2e " + n, source_type: "url", source_url: "https://e2e.invalid/" + n }); return createJob(pool, { reportId: r.id, jobType: "analyze" }); };
const A = await mk("A"), B = await mk("B"), C = await mk("C");
const conn = new IORedis(getRedisUrl(), { maxRetriesPerRequest: null });
const queue = new Queue("threat-library", { connection: conn });
const bB = await queue.add("analyze", { reportId: B.report_id, jobId: B.id, jobType: "analyze" });
const bC = await queue.add("analyze", { reportId: C.report_id, jobId: C.id, jobType: "analyze" });
await claimJobOwnership(pool, { jobId: B.id, ownerToken: crypto.randomUUID(), bullmqJobId: String(bB.id) });
await pool.query("UPDATE threat_library_jobs SET heartbeat_at = NOW() - INTERVAL \x2710 minutes\x27 WHERE id = $1", [B.id]);
await pool.query("UPDATE threat_library_jobs SET bullmq_job_id = $2 WHERE id = $1", [C.id, String(bC.id)]);
let taken = 0;
// The "previous worker": takes both jobs, then dies without releasing its locks.
new Worker("threat-library", async () => { taken += 1; if (taken === 2) setTimeout(() => process.exit(0), 300); await new Promise(() => {}); },
  { connection: new IORedis(getRedisUrl(), { maxRetriesPerRequest: null }), concurrency: 2, lockDuration: 7200000 });
console.log(JSON.stringify({ A: A.id, B: B.id, C: C.id, bullB: bB.id, bullC: bC.id }));
' | grep '^{"A":' | tee "$WORK/seed.json"
[ -s "$WORK/seed.json" ] || fail "seed failed"
sleep 3
node_run node --input-type=module -e '
import { Queue } from "bullmq"; import IORedis from "ioredis"; import { getRedisUrl } from "./lib/redis-url.js";
const q = new Queue("threat-library", { connection: new IORedis(getRedisUrl(), { maxRetriesPerRequest: null }) });
const active = await q.getJobs(["active"]); console.log("active before restart:", active.map((j) => j.id).join(","));
process.exit(active.length === 2 ? 0 : 1);' || fail "dead worker did not leave two active jobs"

step "stop PostgreSQL, start the new worker"
docker stop "$RUN-pg" >/dev/null
sleep 3  # the new worker must start strictly after the dead one's jobs
docker run -d --name "$RUN-worker" --network "$NET" -v "$ROOT:/src:ro" -v "$WORK:/work" "${ENV_ARGS[@]}" "$IMAGE" \
  sh -c "$APP && exec node threat-library-worker.js" >/dev/null
sleep "$OUTAGE_SECONDS"
docker logs "$RUN-worker" > "$WORK/w1-outage.log" 2>&1
retries=$(grep -c 'startup recovery failed; retrying' "$WORK/w1-outage.log" || true)
echo "[e2e] retries during ${OUTAGE_SECONDS}s outage: $retries"
[ "$retries" -ge 3 ] || fail "expected repeated retries while PostgreSQL is down"
grep -q 'startup recovery completed' "$WORK/w1-outage.log" && fail "recovery cannot complete without PostgreSQL"
docker exec "$RUN-redis" redis-cli -a "$RDPW" --no-auth-warning GET talonhound:worker-state:threat_library_startup_recovery | tee "$WORK/state-outage.json"
grep -q '"state":"retrying"' "$WORK/state-outage.json" || fail "health state should be retrying"

step "start PostgreSQL again; recovery must complete without intervention"
docker start "$RUN-pg" >/dev/null
wait_pg || fail "postgres did not restart"
for _ in $(seq 1 90); do docker logs "$RUN-worker" 2>&1 | grep -q 'startup recovery completed' && break; sleep 1; done
sleep 20  # let the dispatched analyses run (they fail fast: no network)
docker logs "$RUN-worker" > "$WORK/w1.log" 2>&1
grep -q 'startup recovery completed' "$WORK/w1.log" || { tail -40 "$WORK/w1.log"; fail "recovery did not complete after PostgreSQL returned"; }
grep 'scheduler recovered' "$WORK/w1.log" | head -1
grep 'scheduler recovered' "$WORK/w1.log" | head -1 | grep -q '"staleActive":2' || fail "both stale active jobs should be force-failed"

step "verify: stale BullMQ jobs failed, each stranded job delivered exactly once, limit held"
node_run node --input-type=module -e '
import fs from "node:fs";
import pg from "pg"; import { Queue } from "bullmq"; import IORedis from "ioredis"; import { getRedisUrl } from "./lib/redis-url.js";
const seed = JSON.parse(fs.readFileSync("/work/seed.json", "utf8"));
const log = fs.readFileSync("/work/w1.log", "utf8").split("\n").filter((l) => l.includes("\"job started\""));
const starts = {};
for (const l of log) { const j = JSON.parse(l.slice(l.indexOf("{"))); starts[j.jobId] = (starts[j.jobId] || 0) + 1; }
const q = new Queue("threat-library", { connection: new IORedis(getRedisUrl(), { maxRetriesPerRequest: null }) });
const states = { B: await (await q.getJob(String(seed.bullB))).getState(), C: await (await q.getJob(String(seed.bullC))).getState() };
const pool = new pg.Pool({ host: "pg", user: "talonhound", password: process.env.DB_PASSWORD, database: "talonhound" });
const { rows } = await pool.query("SELECT id, status FROM threat_library_jobs WHERE id = ANY($1) ORDER BY id", [[seed.A, seed.B, seed.C]]);
const claims = fs.readFileSync("/work/w1.log", "utf8").split("\n").filter((l) => l.includes("\"report claimed\"")).map((l) => JSON.parse(l.slice(l.indexOf("{"))));
const maxOccupied = Math.max(0, ...claims.map((c) => c.occupied));
const limit = claims[0]?.limit;
const out = { staleBullStates: states, startsPerJob: { A: starts[seed.A] || 0, B: starts[seed.B] || 0, C: starts[seed.C] || 0 }, dbStatus: rows, maxOccupied, limit };
console.log(JSON.stringify(out));
const ok = states.B === "failed" && states.C === "failed"
  && out.startsPerJob.A === 1 && out.startsPerJob.B === 1 && out.startsPerJob.C === 1
  && rows.every((r) => !["queued", "running"].includes(r.status))
  && maxOccupied <= limit;
process.exit(ok ? 0 : 1);' || fail "stranded jobs were not recovered exactly once"

step "restart the worker: recovery completes first try and delivers nothing new"
docker stop -t 15 "$RUN-worker" >/dev/null
docker run -d --name "$RUN-worker2" --network "$NET" -v "$ROOT:/src:ro" -v "$WORK:/work" "${ENV_ARGS[@]}" "$IMAGE" \
  sh -c "$APP && exec node threat-library-worker.js" >/dev/null
for _ in $(seq 1 60); do docker logs "$RUN-worker2" 2>&1 | grep -q 'startup recovery completed' && break; sleep 1; done
sleep 5
docker logs "$RUN-worker2" > "$WORK/w2.log" 2>&1
grep 'startup recovery completed' "$WORK/w2.log" | grep -q '"attempts":1' || fail "second start should recover on the first attempt"
seedA=$(sed -n 's/.*"A":\([0-9]*\).*/\1/p' "$WORK/seed.json")
seedB=$(sed -n 's/.*"B":\([0-9]*\).*/\1/p' "$WORK/seed.json")
seedC=$(sed -n 's/.*"C":\([0-9]*\).*/\1/p' "$WORK/seed.json")
for id in "$seedA" "$seedB" "$seedC"; do
  grep '"job started"' "$WORK/w2.log" | grep -q "\"jobId\":$id[,}]" && fail "job $id delivered again after restart"
done
docker exec "$RUN-redis" redis-cli -a "$RDPW" --no-auth-warning GET talonhound:worker-state:threat_library_startup_recovery | grep -q '"state":"completed"' || fail "health state should be completed"
echo "[e2e] restart: recovered on attempt 1, no re-delivery"

echo
echo "[e2e] PASS"
