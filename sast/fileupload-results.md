# File Upload Analysis Results: TalonHound

**Assessment date:** 2026-08-08  
**Repo HEAD:** `99e1d3482aa2f9aee83a89bc966bfadd8bd03c67`  
**Skill:** `sast-fileupload` (Phase 1 — zero user file-upload receive/store sites)  
**Method:** Static analysis only

## Executive Summary

- **Class status:** N/A
- Upload sites analyzed: **0**
- Vulnerable: **0**
- Likely Vulnerable: **0**
- Not Vulnerable: **0**
- Needs Manual Review: **0**

No file upload sites found.

## Evidence (absence)

### Dependencies / middleware

- Searched for `multer`, `busboy`, `formidable`, `multiparty`, `express-fileupload`: **no package.json dependencies** and **no code usages** in `backend/`, `frontend/`, `integration/`
- No `multipart/form-data` upload handlers; body stack is `express.json()` (`backend/server.js`)

### Upload receive patterns

- No `req.file` / `req.files` / `upload.single` / `upload.array` handlers
- Frontend `FormData` usage in `frontend/src/main.jsx` (~1830) is the **login form** reading `email`/`password` fields only — not a file input upload

### Related file I/O (not user uploads)

These write files but do **not** accept client-uploaded multipart/binary filenames into storage as upload endpoints:

| Path | Role |
|---|---|
| `backend/ioc-search-export-worker.js` | Server-generated CSV export under `/data/ioc-search-exports` |
| `backend/lib/backup/*` | Operator/admin backup archives (`pg_dump` / tar / encrypt) under `/data/backups` |
| Feed sync workers | Fetch remote feed **body into memory/DB**, not client file uploads |

Architecture documents: no multipart upload middleware; CSV import via operator scripts/API JSON is off-path for classic upload RCE.

## Findings

None. Phases 2–3 skipped (zero upload sites).
