# TalonHound SAST Assessment Metadata

## Assessment scope

- **Project:** TalonHound
- **Repository path:** `C:\Proje\TalonHound`
- **Assessment type:** Read-only interim static security assessment (detection only)
- **Assessment date:** 2026-08-08
- **Phase:** Detection only — no remediation

## Git baseline (Phase 0)

| Field | Value |
|---|---|
| Branch | `main` |
| HEAD | `99e1d3482aa2f9aee83a89bc966bfadd8bd03c67` |
| Pre-assessment `git status --short` | `M memory/2026-08-08.md` |

### Pre-existing local changes (must not be overwritten)

- `memory/2026-08-08.md` (modified) — pre-existing user/agent daily notes; preserved.

No other untracked or modified application files were present in the Phase 0 baseline snapshot.

## Skill source / integrity

| Field | Value |
|---|---|
| Upstream URL | `https://github.com/utkusen/sast-skills` |
| Clone location (outside source tree) | `C:\Users\Hostname\.cursor\tmp-sast-skills` |
| Branch | `main` |
| Commit (`git rev-parse HEAD`) | `db52227eab1043bf122cbff7206fac6708b4d6c9` |
| Skill path used | `sast-files/.agents/skills/*/SKILL.md` |
| Orchestration reference | `sast-files/AGENTS.md` |

## Mandatory skills

| Skill | Expected output | Notes |
|---|---|---|
| `sast-analysis` | `sast/architecture.md` | Architecture-first |
| `sast-sqli` | `sast/sqli-results.md` | |
| `sast-graphql` | `sast/graphql-results.md` | N/A with evidence if no GraphQL |
| `sast-xss` | `sast/xss-results.md` | |
| `sast-rce` | `sast/rce-results.md` | |
| `sast-ssrf` | `sast/ssrf-results.md` | High-priority for feed/enrichment |
| `sast-idor` | `sast/idor-results.md` | |
| `sast-xxe` | `sast/xxe-results.md` | N/A with evidence if no XML parser surface |
| `sast-ssti` | `sast/ssti-results.md` | N/A with evidence if no template engine surface |
| `sast-jwt` | `sast/jwt-results.md` | |
| `sast-missingauth` | `sast/missingauth-results.md` | |
| `sast-pathtraversal` | `sast/pathtraversal-results.md` | |
| `sast-fileupload` | `sast/fileupload-results.md` | N/A with evidence if no upload surface |
| `sast-businesslogic` | `sast/businesslogic-results.md` | |
| `sast-hardcodedsecrets` | `sast/hardcodedsecrets-results.md` | Required even if AGENTS.md omits it |
| `sast-report` | `sast/final-report.md` | After all results + verification |

## Safety / scope constraints applied

- No application source/config/migration/test/dependency/Docker/CI modifications
- No commit, push, merge, migrate, deploy, or production attack
- No exploit payloads to live services
- Only `sast/` artifacts may be created/changed in this repository
- Pre-existing user changes preserved

## Assessment limitations (pre-declared)

- Static analysis only; runtime verification against production/LAN targets is out of scope
- No request sent to metadata endpoints, private networks, or production APIs
- Local unit/integration tests may be run only if non-mutating to production/external systems; default is static evidence

## Phase 4 completion

| Field | Value |
|---|---|
| Architecture | `sast/architecture.md` |
| Verification | `sast/verification-summary.md` |
| Final report | `sast/final-report.md` |
| Post-assessment note | Only `sast/` artifacts added by this assessment; pre-existing `memory/2026-08-08.md` left intact |
