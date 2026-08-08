# Current-head remediation matrix (Phase 0)

**HEAD:** `be7686adc736cb6eb7705a4666367b9f9fbb7954` (`main`)  
**Baseline date:** 2026-08-08  
**Pre-existing dirty worktree:** `M memory/2026-08-08.md`, `?? sast/` (preserved)

| Finding | Original status | Current-head status | Evidence | Action |
|---|---|---|---|---|
| JWT-01 | Confirmed → Fixed | ALREADY RESOLVED | `effectiveRoleFromPayload` fail-closed; tests pass | Regression only |
| JWT-02 | Confirmed → Fixed | ALREADY RESOLVED | passwordChangeGate fail-closed on missing userId; tests pass | Regression only |
| AUTH-01 | Confirmed | CONFIRMED | `ipEnrichment.js` PUT/test/remove-key lack `requireRole(ADMIN)` | Fix Group A |
| AUTH-02 | Confirmed | CONFIRMED | `server.js` VT PUT/remove/test lack `requireRole(ADMIN)` | Fix Group A |
| SSRF-03 | Confirmed | CONFIRMED | IPinfo PUT accepts arbitrary `base_url`; `fetchIpinfoLite` uses it + query token | Fix Group A |
| SSRF-01 | Confirmed | CONFIRMED | `validateFeedUrl` blocklist-only; `redirect:'follow'` | Fix Group B |
| SSRF-02 | Probable | PROBABLE / NEEDS RUNTIME VERIFICATION | IPv4-mapped check incomplete in utils | Prove+fix Group B |
| AUTH-03 | Confirmed | CONFIRMED | `rbacHttpPolicy` early-return for `authVia==='bearer'` | Fix Group C |
| AUTH-04 | Confirmed | CONFIRMED | ingest synthetic admin; `isAdminUser` role-only | Fix Group C |
| SECRET-01 | Confirmed | CONFIRMED | `DEFAULT_ADMIN_PASSWORD = 'admin'` | Fix Group D |
| JWT-03 | Confirmed | CONFIRMED | no token_version / revoke on reset | Fix Group E |
| SECRET-02 | Confirmed | CONFIRMED | compose/ensure-redis default `dev-insecure-redis` | Fix Group F |
| AUTH-05 | Confirmed | CONFIRMED | setup/complete unauthenticated | Fix Group G |
| AUTH-06 | Probable | CONFIRMED → FIXED | PUT/POST credentials now `requireRole(ADMIN)`; run-now unchanged | Group H |
| AUTH-07 | Probable | CONFIRMED → FIXED | GET `/api/api-keys` (+ profiles) admin-only; no plaintext secrets | Group H |
| IDOR-01 | Probable | CONFIRMED → FIXED | Authorize by `requested_by_id`; list/dedupe/concurrency by id; email-only historical not grantable | Group H |
| JWT-05 | Probable | CONFIRMED → FIXED | Production Secure unconditional; `AUTH_COOKIE_SECURE=0` cannot downgrade prod | Group I |
| Path traversal NMR | NMR | FIXED (defense-in-depth) | Host tar rejected `..` escape; `assertSafeTarMembers` + extract tests | Group J |

Note: original report severity totals vs de-duplicated IDs may differ; remediation uses IDs above.
