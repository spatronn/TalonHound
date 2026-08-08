# Path Traversal Analysis Results: TalonHound

**Assessment date:** 2026-08-08  
**Repo HEAD:** `99e1d3482aa2f9aee83a89bc966bfadd8bd03c67`  
**Method:** Static analysis (skill `sast-pathtraversal`); focused sinks: `pathSafety`, `resolveExportFilePath`, backup download, archive extract, swagger static  
**CWE:** CWE-22 (Path Traversal) / ZipSlip variant where noted

## Executive Summary
- Sinks analyzed: 5
- Vulnerable: 0
- Likely Vulnerable: 0
- Not Vulnerable: 4
- Needs Manual Review: 1

| Bucket | Count | Areas |
|---|---|---|
| Vulnerable | 0 | — |
| Likely Vulnerable | 0 | — |
| Needs Manual Review | 1 | Archive extract (`extractTarGz` / verify) |
| Not Vulnerable | 4 | `pathSafety`, export `resolveExportFilePath` download, backup download, swagger static |

---

## Findings

### [NEEDS MANUAL REVIEW] Archive extract (`extractTarGz`) lacks ZipSlip member validation

- **File**: `backend/lib/backup/archive.js` (lines 74-78); callers `backend/lib/backup/verify.js` (lines 46-47), `backend/routes/backups.js` (verify route ~212-233)
- **Endpoint / function**: `extractTarGz(archivePath, destDir)`; used by `verifyBackupArchive` → `POST /api/backups/:id/verify` (admin). Restore CLI uses a separate shell path with member validation (`scripts/lib/backup-common.sh` `validate_tar_members`).
- **Uncertainty**: Node extract runs `tar -xzf <archive> -C <destDir>` with **no** per-entry allowlist, no rejection of `..` / absolute members / symlinks before extract. HTTP clients cannot upload archives; `runBackup` creates archives from server-controlled bundle trees, so remote HTTP input does not clearly reach tar entry names. Residual risk if a malicious `.tar.gz` is already present under the backup volume (FS write, compromised worker, or poisoned row pointing at an attacker-readable archive) and an admin triggers verify.
- **Related inconsistency**: Verify opens `row.archive_path` from the DB without re-running `assertSafeRelativeName` / `resolveBackupPath`, whereas download resolves only via `archive_filename` through storage. Absolute paths written by `markCompleted` are normally `placed.absolutePath` under the backup root; if `system_backups.archive_path` were ever poisoned, verify would read that path as the archive source.
- **Suggestion**: Align Node verify with restore CLI: list members (`tar -tzf` / `listTarGz`), reject absolute paths, `..`, symlink/hardlink entries, then extract into a confined tmp dir; resolve the archive file via `storage.resolveAbsolutePath(row.archive_filename)` (same as download) rather than trusting `archive_path` alone. Optionally prefer `fs.realpath` + prefix checks on the archive path.

---

### [NOT VULNERABLE] Backup `pathSafety` filename / id guards

- **File**: `backend/lib/backup/pathSafety.js` (lines 1-31); used by `backend/lib/backup/storage/local.js` (`absolutePath` / `resolveAbsolutePath`)
- **Endpoint / function**: `assertSafeRelativeName`, `isValidArchiveFilename`, `isValidBackupId`, `isValidRowId` (helpers; not a standalone HTTP sink)
- **Reason**: Traversal-shaped names are rejected before join (`/`, `\`, `..`, NUL, leading `.`). Storage `absolutePath` then passes the sanitized name through `resolveBackupPath`, which does `path.resolve(base, name)` and requires `resolved === base` or `resolved.startsWith(base + path.sep)`. Server-generated archive names (`archiveFilenameFor`) match the tight id/filename regexes. Unit tests cover `../x` and `a/b` rejection. This is an effective basename-style + resolve/prefix control for download/delete sinks that call it.

---

### [NOT VULNERABLE] IOC search export download via `resolveExportFilePath`

- **File**: `backend/lib/iocSearchExport/exportConfig.js` (lines 35-41); `backend/routes/iocSearchExports.js` (lines 288-336, `basenameOnly` 412-416); writer `backend/ioc-search-export-worker.js` (~127-128)
- **Endpoint / function**: `GET /api/iocs/search-exports/:id/download`
- **Reason**: Path param is only the export UUID (DB lookup + `canAccessExport`). On-disk name comes from `row.storage_path` after `basenameOnly` (strips directory components including `\`→`/`). Result is passed to `resolveExportFilePath`, which uses `path.resolve` + `startsWith(base + path.sep)` and throws on escape. Worker writes `${row.id}.csv[.gz]` via the same helper. Client cannot choose the filesystem path. Tests in `exportConfig.test.js` assert rejection of `../../etc/passwd`, `../secret.csv`, and absolute `/etc/passwd`.

---

### [NOT VULNERABLE] Backup archive download

- **File**: `backend/routes/backups.js` (lines 264-308); `backend/lib/backup/storage/local.js` (35-38, 76-77); `backend/lib/backup/config.js` (`resolveBackupPath`, 82-89)
- **Endpoint / function**: `GET /api/backups/:id/download` (admin)
- **Reason**: Route validates UUID with `isValidRowId`, loads row, then resolves **only** `row.archive_filename` through `createStorageProvider(...).resolveAbsolutePath` → `assertSafeRelativeName` + `resolveBackupPath`. Comment and tests state client paths are not trusted; `backups.test.js` (`download path traversal via filename is blocked`) plants `archive_filename: '../evil.tar.gz'` and expects 400/404. Privilege is admin-only; path escape from HTTP id/body is not achievable.

---

### [NOT VULNERABLE] Swagger / OpenAPI static assets

- **File**: `backend/routes/apiDocs.js` (lines 62-94)
- **Endpoint / function**: `GET /api/docs/static/talonhound.css` (`res.sendFile(themePath)`); `app.use('/api/docs/static', express.static(distPath, …))`; HTML/OpenAPI endpoints are string/JSON builders
- **Reason**: Theme path is fully hardcoded (`path.resolve(__dirname, '../assets/api-docs/swagger-ui-talonhound.css')`). Static root is `getSwaggerUiDistPath()` from `require.resolve('swagger-ui-dist/package.json')` — not user-controlled. Options set `index: false`, `dotfiles: 'deny'`, `fallthrough: false`. URL suffixes under the mount are mediated by Express `static`/`send`, which constrain resolution to the configured root; there is no concatenation of `req.query` / path params into a custom `fs`/`sendFile` argument beyond the framework mount. Unauthenticated surface discloses API docs assets only, not arbitrary filesystem paths.

---

## Notes (out of scope for counts)

- No multipart/file-upload handlers were in scope; architecture confirms no classical upload→save-as-`originalname` path.
- Host restore (`scripts/restore-stack.sh` / `validate_tar_members`) rejects unsafe tar members — stronger than Node `extractTarGz`; residual gap is the Node verify path only.
- `path.resolve` + prefix checks (export/backup) do not follow symlinks (`fs.realpath`); symlink escape would require planting a link under the storage volume (not available via these HTTP APIs alone).
