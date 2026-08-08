# RCE Analysis Results: TalonHound

**Assessment date:** 2026-08-08  
**Repo HEAD:** `99e1d3482aa2f9aee83a89bc966bfadd8bd03c67`  
**Method:** Static analysis only (read-only; no live exploit against running services)  
**Skill:** `sast-rce` (`utkusen/sast-skills` @ `db52227eab1043bf122cbff7206fac6708b4d6c9`)  
**Scope note:** Admin/worker privilege does not eliminate impact scoring; reachability and mitigations are proven per sink.

## Executive Summary

- Sinks analyzed: **9**
- Vulnerable: **0**
- Likely Vulnerable: **0**
- Not Vulnerable (Rejected): **9**
- Needs Manual Review: **0**

| Bucket | Count | Finding IDs |
|---|---|---|
| Confirmed | 0 | — |
| Probable | 0 | — |
| Rejected | 9 | RCE-01 … RCE-09 |
| N/A (class surface absent) | covered under RCE-07–RCE-09 | eval/`Function`/`vm`, unsafe deserializer packages |

**Verdict:** No Remote Code Execution vulnerabilities identified. Application `child_process` usage is argv list-form without `shell: true`; DB/tool args come from env or server-generated IDs; no `eval`/`Function`/`vm` code sinks; dynamic `import()`/`require()` paths are static literals; deserialization is JSON-only (no gadget-prone loaders).

---

## Confirmed

None.

## Probable

None.

## Needs Manual Review

None.

---

## Rejected

### [NOT VULNERABLE] RCE-01 — `tar` archive create/extract/list via `spawn`

- **Finding ID:** RCE-01
- **Category:** OS Command Injection
- **File:** `backend/lib/backup/archive.js` (lines 12–33, 39–84)
- **Sink:** `spawn(cmd, args, { stdio: [...] })` — **no `shell: true`**
- **Call sites:**
  - `createTarGzAtomic` → `run('tar', ['-czf', tmpArchive, '-C', bundleParent, bundleName])`
  - `extractTarGz` → `run('tar', ['-xzf', archivePath, '-C', destDir])`
  - `listTarGz` → `run('tar', ['-tzf', archivePath])`
- **Endpoint / function:** Backup worker / verify path (`executeBackupJob` → pack; `verifyBackupArchive` → list/extract). HTTP: admin can only **enqueue** a backup (`POST` via `backend/routes/backups.js`); restore/extract of arbitrary client uploads is **not** an HTTP API (`architecture.md`: restore is CLI/host only).
- **Taint trace:**
  1. Manual backup: authenticated admin → `enqueueBackup` → `generateBackupId()` (`backend/lib/backup/ids.js`: `backup-${utcStamp}-${randomHex}`) stored in DB → BullMQ job `{ backupRowId, backupId }` → `executeBackupJob`.
  2. Paths: `bundleDir` / `plainPath` / tmp names derived from `cfg.backupDir` (env `BACKUP_DIR`) + server `backupId` + `process.pid` / `Date.now()`.
  3. Verify path: `archivePath` is a path already under backup storage / tmp after decrypt — not raw HTTP body bytes fed as a shell string.
- **Why rejected:** Command name is literal `'tar'`. Arguments are separate argv elements (list form). No shell metacharacter interpretation. Attacker-controlled HTTP body fields do not become command string concatenation. Even path-shaped values cannot inject `;`, `|`, `$()`, etc. into a shell.
- **Related non-RCE note:** Hostile crafted **archives** could still be a path/symlink unpack concern on CLI restore (`scripts/lib/backup-common.sh` has member validation); that is path/filesystem abuse, not OS command injection / RCE via `spawn`.

### [NOT VULNERABLE] RCE-02 — `pg_dump` via `spawn` (backup dump)

- **Finding ID:** RCE-02
- **Category:** OS Command Injection
- **File:** `backend/lib/backup/pgDump.js` (lines 39–98)
- **Sink:** `spawn('pg_dump', args, { env, stdio: [...] })` — **no `shell: true`**
- **Dynamic arguments:** `host`, `port`, `user`, `database` in argv; `password` only in `env.PGPASSWORD` (not argv)
- **Endpoint / function:** `runPgDump` ← `executeBackupJob` (`backend/lib/backup/runBackup.js`)
- **Taint trace:**
  1. `getBackupConfig().db` ← `process.env.DB_HOST` / `DB_PORT` / `DB_USER` / `DB_PASSWORD` / `DB_NAME` only (`backend/lib/backup/config.js:53-59`).
  2. HTTP `/api/backups*` enqueue does **not** accept connection parameters from `req.body`.
  3. BullMQ payload carries `backupRowId` / `backupId` only — not DB credentials.
- **Why rejected:** List-form spawn; credentials originate from deployment env (operator trust), not from remote attacker HTTP/API input. Shell injection impossible. Changing `DB_*` requires host/env compromise (out of RCE-via-app-input scope).

### [NOT VULNERABLE] RCE-03 — `pg_restore --list` via `spawn` (verify)

- **Finding ID:** RCE-03
- **Category:** OS Command Injection
- **File:** `backend/lib/backup/pgDump.js` (lines 101–134)
- **Sink:** `spawn('pg_restore', ['--list', dumpPath], ...)` — **no `shell: true`**
- **Dynamic arguments:** `dumpPath` (filesystem path under bundle / tmp)
- **Endpoint / function:** `pgRestoreList` ← `verifyBundleDirectory` / `verifyBackupArchive`
- **Taint trace:** `dumpPath` = `path.join(bundleDir, 'database', 'postgres.dump')` (or legacy layout) where `bundleDir` is created by the backup job or extracted under a server tmp root during verify — not `req.body` / query.
- **Why rejected:** Fixed binary name + list argv. Path is an argument to `pg_restore`, not a shell string. No remote attacker string reaches the command as injectable shell syntax. (Hostile dump **content** affecting `pg_restore` behavior is outside classic argv injection / not app-level code eval.)

### [NOT VULNERABLE] RCE-04 — `which`/`where` probe for pg client tools

- **Finding ID:** RCE-04
- **Category:** OS Command Injection
- **File:** `backend/lib/backup/pgDump.js` (lines 8–17, 20–33)
- **Sink:** `spawn(process.platform === 'win32' ? 'where' : 'which', [name], ...)`
- **Dynamic arguments:** `name` — always literal `'pg_dump'` or `'pg_restore'` from `assertPgClientTools()`
- **Why rejected:** Both command and argument are constants at the only production call site. No user input.

### [NOT VULNERABLE] RCE-05 — `git rev-parse HEAD` via `spawnSync`

- **Finding ID:** RCE-05
- **Category:** OS Command Injection
- **File:** `backend/lib/backup/runBackup.js` (lines 29–37)
- **Sink:** `spawnSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' })`
- **Dynamic arguments:** none (all literals). Fallback: `process.env.GIT_SHA` / `SOURCE_COMMIT` for manifest metadata only (not executed).
- **Why rejected:** Fully constant argv; result written into `manifest.json` as data. No attacker control of command or args.

### [NOT VULNERABLE] RCE-06 — Dev DB test harness `docker`/`spawn` (non-production)

- **Finding ID:** RCE-06
- **Category:** OS Command Injection
- **File:** `backend/scripts/fileArtifactDbTests.js` (lines 75–91, 140–148, et al.)
- **Sink:** `spawn(cmd, args, { shell: false, ... })` — explicitly `shell: false`
- **Args:** docker image/name constants; env-derived port/user/password plugged into argv elements like `` `POSTGRES_PASSWORD=${cfg.password}` `` as a **single argv string** (still not shell-interpreted).
- **Preconditions:** `ALLOW_FILE_ARTIFACT_DB_TESTS=1`, localhost DB guards, not production `NODE_ENV` (`dbTestGuard`).
- **Why rejected:** Not an HTTP entry point; operator/dev CLI only. List-form + `shell: false`. Not reachable by remote attackers through the Express API.

### [NOT VULNERABLE] RCE-07 — `eval` / `new Function` / `vm.*` / string `setTimeout`

- **Finding ID:** RCE-07
- **Category:** Code Injection
- **Recon:** Repo-wide search of `backend/`, `frontend/src/`, `integration/` for `\beval(`, `new Function`, `vm.runIn*`, `require('vm')`, and string-form `setTimeout`/`setInterval`.
- **Result:** **No** application sinks. All `setTimeout`/`setInterval` usages pass function callbacks, not code strings. No `vm` module usage in app code.
- **Why rejected:** No code-evaluation sink exists for attacker data to reach. Class surface: absent.

### [NOT VULNERABLE] RCE-08 — Dynamic `import()` / `require(variable)`

- **Finding ID:** RCE-08
- **Category:** Code Injection (dynamic module load)
- **Recon:** `await import(...)` occurrences; `require(` with non-literal; `createRequire` in `backend/routes/apiDocs.js` for static Swagger asset resolution.
- **Result:** Every runtime `import()` uses a **string literal** module path (e.g. `'./lib/systemTime.js'`, `'./fileArtifacts/dualWrite.js'`). No `import(userControlled)`. No `require(variable)` of external input.
- **Why rejected:** Module paths are developer constants; attacker HTTP/queue data does not select which JS module loads.

### [NOT VULNERABLE] RCE-09 — Unsafe deserialization

- **Finding ID:** RCE-09
- **Category:** Unsafe Deserialization
- **Recon:** No dependencies or call sites for `node-serialize`, `js-yaml` `yaml.load`, `pickle`, `marshal`, Java/`ObjectInputStream`, PHP `unserialize`, Ruby `Marshal`, `BinaryFormatter`, `v8.deserialize`, etc. Package.json files (`backend`, `frontend`, `integration`) do not declare unsafe serializer libs.
- **Observed parsing:** Widespread `JSON.parse` / Express `express.json()` / PostgreSQL JSONB — **safe formats** (no native code-execution gadgets per skill guidance).
- **Why rejected:** No unsafe deserializer sink. JSON/JSONB on user/feed/queue data is not RCE.

---

## Additional surfaces checked (non-findings)

| Surface | Evidence | RCE disposition |
|---|---|---|
| `shell: true` anywhere in JS | Grep: **zero** matches | N/A |
| `child_process.exec` / `execSync` / `execFile` | Not used in app | N/A |
| HTTP backup create body → argv | `enqueueBackup` ignores connection fields; ID server-generated | Rejected (feeds RCE-01/02) |
| CLI restore `scripts/restore-stack.sh` | Operator `--file` / `--backup-id`; quoted paths; not HTTP | Out of remote RCE; host operator trust |
| Feed/CSV/JSON responses | Parsed into DB fields / `JSON.parse` | Not RCE (see SSRF/XSS classes) |

---

## Skill classification summary

### Vulnerable

None.

### Likely Vulnerable

None.

### Needs Manual Review

None.

### Not Vulnerable

RCE-01, RCE-02, RCE-03, RCE-04, RCE-05, RCE-06, RCE-07, RCE-08, RCE-09.

---

## Methodology notes

1. Read `sast/architecture.md` (RCE subsection + backup flow).
2. Structural sink hunt: `child_process`, eval-likes, dynamic import/require, unsafe deserializers.
3. Forward/backward taint on backup path from HTTP enqueue → queue → `executeBackupJob` → `runPgDump` / `createTarGzAtomic` / `gitSha` / verify helpers.
4. Classifications follow sast-rce rules: list-form spawn without shell is **not** command injection; JSON is not unsafe deserialization.
