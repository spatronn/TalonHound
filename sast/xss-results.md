# XSS Analysis Results: TalonHound

**Assessment date:** 2026-08-08  
**Repo HEAD:** `99e1d3482aa2f9aee83a89bc966bfadd8bd03c67`  
**Method:** Static analysis only (skill `sast-xss`)  
**Stack:** React 18 SPA + Express JSON API; Swagger docs HTML is a static constant string.

## Executive Summary

- Candidates analyzed: **8**
- Vulnerable (Confirmed): **0**
- Likely Vulnerable (Probable): **0**
- Not Vulnerable (Rejected): **8**
- Needs Manual Review: **0**
- N/A: **0** (XSS class applies; UI/HTML surfaces exist)

| Bucket | Count | Finding IDs |
|---|---|---|
| Confirmed | 0 | — |
| Probable | 0 | — |
| Rejected | 8 | XSS-R01 … XSS-R08 |
| N/A | 0 | — |

**Verdict:** No confirmed XSS in reviewed code. React default escaping covers primary IOC/feed/provider text rendering; no `dangerouslySetInnerHTML` / `innerHTML` / `document.write` found under `frontend/`. URL-valued attributes reviewed use allowlisted logos, constants, or `http(s)`-validated analyst references.

---

## Confirmed

None.

## Probable

None.

---

## Rejected

### [NOT VULNERABLE] XSS-R01 — No `dangerouslySetInnerHTML` / DOM sink APIs in frontend

- **Evidence:** Ripgrep across `frontend/` for `dangerouslySetInnerHTML`, `innerHTML`, `document.write`, `DOMPurify`: **0 matches**.
- **Reason:** React text interpolation escapes by default for stored IOC notes, names, error strings, etc.

### [NOT VULNERABLE] XSS-R02 — Swagger / API docs HTML

- **Files:lines:** `backend/routes/apiDocs.js:24-49` (`buildApiDocsHtml`)
- **Reason:** Compile-time constant template literal with **no** `${...}` user interpolation. Assets are same-origin static paths under `/api/docs/static/`. Not reflected HTML XSS.

### [NOT VULNERABLE] XSS-R03 — Provider logos `src={src}`

- **Files:lines:** `frontend/src/components/enrichmentProviders/ProviderLogo.jsx:9-37`
- **Reason:** `src` resolved from hard-coded imported asset map (`LOGO_BY_KEY`); not user-supplied URL.

### [NOT VULNERABLE] XSS-R04 — Analyst intelligence reference `href={item.url}`

- **Files:lines:** `frontend/src/intelligenceTab.jsx:440-443`; `backend/lib/analystIntelligence.js:45-52` (`URL_RE` requires `http://` or `https://`)
- **Reason:** Stored URL must pass server-side scheme allowlist before persistence; React encodes attribute context. Not `javascript:` capable via validated create/update path.

### [NOT VULNERABLE] XSS-R05 — VirusTotal permalink `href={s.permalink}`

- **Files:lines:** `frontend/src/main.jsx:~12105`
- **Reason:** Permalink originates from VirusTotal API client mapping (hardcoded VT host elsewhere). Not attacker-authored arbitrary scheme in app storage path reviewed. Residual supply-chain trust is out of class for classic XSS.

### [NOT VULNERABLE] XSS-R06 — Export download / API docs anchors

- **Files:lines:** `frontend/src/main.jsx` (`/api/iocs/search-exports/${row.id}/download`, `API_DOCS_PATH` constant)
- **Reason:** Path constructed from numeric/server id or fixed constant; not free-form HTML.

### [NOT VULNERABLE] XSS-R07 — Blob download URLs

- **Files:lines:** `frontend/src/main.jsx` `URL.createObjectURL(new Blob([res.data]))`
- **Reason:** Blob URL for same-session CSV download; not injecting HTML into DOM as markup.

### [NOT VULNERABLE] XSS-R08 — Stored IOC / feed display text

- **Reason:** Architecture + spot checks show text nodes / React children for notes, observables, provider messages. Without raw HTML sinks, default escaping applies. Feed-sourced content in DB does not become HTML without an active sink.

---

## N/A areas

None for the XSS class (surface exists; clean after review).
