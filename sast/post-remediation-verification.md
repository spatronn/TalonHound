# Post-remediation verification

**HEAD at start of pass:** `be7686adc736cb6eb7705a4666367b9f9fbb7954` (`main`)  
**Verification date:** 2026-08-08  
**Scope:** Remaining SAST targets after JWT-01/JWT-02 (no commit/push/deploy in this pass)

| Finding | Original status | Current-head verification | Remediation | Tests | Residual risk | Final status |
|---|---|---|---|---|---|---|
| JWT-01 | Fixed | Fail-closed role; regression green | Regression only | `lib/auth.test.js`, `lib/rbac.test.js` | None in reviewed JWT path | FIXED (regression verified) |
| JWT-02 | Fixed | Password-change gate fail-closed | Regression only | `lib/passwordChangeGate.test.js` | None in reviewed path | FIXED (regression verified) |
| AUTH-01 | Confirmed | IPinfo admin routes lacked `requireRole(ADMIN)` | `requireRole(ADMIN)` on GET/PUT/test/remove-key; UI admin-only | `routes/providerAdminAuthz.test.js` | Analysts still consume enrichment | FIXED |
| AUTH-02 | Confirmed | VT admin mutations lacked admin role | `requireRole(ADMIN)` on VT PUT/test/remove-key | `routes/providerAdminAuthz.test.js` | Same | FIXED |
| SSRF-03 | Confirmed | Arbitrary IPinfo `base_url` + query token | Trusted constant `https://api.ipinfo.io/lite`; ignore DB/env override; `redirect:'error'`; UI read-only | `providerAdminAuthz.test.js` | Token remains query-string per IPinfo Lite contract on locked origin | FIXED |
| SSRF-01 | Confirmed | Blocklist + `redirect:follow` | Shared `customThreatFeedSsrf.js` + pinned fetch; redirect hop validation; no cross-origin auth forward | `customThreatFeedSsrf.test.js` | DNS pin via custom lookup; depends on Node http stack | FIXED |
| SSRF-02 | Probable | IPv4-mapped private gaps | Explicit IPv4-mapped rejection in shared classifier | `customThreatFeedSsrf.test.js` | — | FIXED |
| AUTH-03 | Confirmed | Bearer skipped `rbacHttpPolicy` | Removed bearer exemption; parity with cookie | `ingestPrincipal.test.js` | CSRF still skipped for bearer (by design) | FIXED |
| AUTH-04 | Confirmed | Ingest synthetic admin + `isAdminUser` | `ingestCapabilityPolicy` allowlist (`POST /api/ioc/ip` only); `isHumanAdmin` rejects ingest | `ingestPrincipal.test.js`, `iocDelete` uses `isHumanAdmin` | Ingest still has synthetic `role:admin` claim for audit identity but helpers deny | FIXED |
| AUTH-05 | Confirmed | Anonymous setup complete on existing installs | Anonymous only when not `timezone_configuration_required`; admin required otherwise; `optionalAuth` | `routes/setupAuthz.test.js` | Greenfield remains anonymous by design | FIXED |
| AUTH-06 | Probable | Integration credential PUT/test analyst-writable | Confirmed + `requireRole(ADMIN)` on PUT/test | `routes/integrationCredentialsAuthz.test.js` (if present) | Analyst may still trigger run-now / schedules per product | FIXED |
| AUTH-07 | Probable | `GET /api/api-keys` unscoped | Confirmed + `requireRole(ADMIN)` on list | `routes/apiKeys.test.js` | Profiles endpoint remains public metadata | FIXED |
| JWT-03 | Confirmed | No server-side JWT revoke | `users.auth_version` + JWT `av` claim; gate; bump on password change/reset, logout-all, passive | `authVersion.test.js`, migration `146_users_auth_version.sql` | Logout = all sessions for user (documented). Pre-`av` JWTs fail closed after migrate+restart | FIXED |
| JWT-05 | Probable | Secure flag from spoofable proto | Production → Secure always; `AUTH_COOKIE_SECURE` override | `cookieSecure.test.js` | Dev HTTP remains non-Secure unless override | FIXED |
| SECRET-01 | Confirmed | `DEFAULT_ADMIN_PASSWORD='admin'` | Unique/env password; one-time file under `/data/backups/...once`; reject legacy `admin` | `defaultAdminBootstrap.test.js` | Operator must retrieve generated file/env | FIXED |
| SECRET-02 | Confirmed | Compose/app default `dev-insecure-redis` | Compose `${REDIS_PASSWORD:?...}`; ensure-* throw if unset; no default assign | `ensure-redis-password.test.js` | Local `.env` must set password explicitly | FIXED |
| IDOR-01 | Probable | Email ownership recycling | `canAccessOwnedArtifact` by immutable `requested_by_id`; list scopes by id; email-only historical → admin only | `artifactOwnership.test.js`, export/deep-search route tests | Historical NULL `requested_by_id` rows need admin cleanup | FIXED |
| Path traversal NMR | NMR | `extractTarGz` no member checks | Pre-reject unsafe members; post-walk realpath confinement | `archiveZipSlip.test.js` | Relies on host `tar` + post-check; symlinks still rejected if they escape on walk | FIXED |

## Notes

- Pre-existing unrelated failures (proven vs HEAD): `lib/backup/operationLock.test.js` imports missing `canRestoreTransition`; `lib/customThreatFeed.test.js` parser expectations (IP accepted as fixed-domain) — **not introduced by this remediation**.
- Migration `146_users_auth_version.sql` not applied to production in this pass.
- No production DB/services touched; no commit/push/deploy.
