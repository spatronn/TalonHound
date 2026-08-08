# SSTI Analysis Results: TalonHound

**Assessment date:** 2026-08-08  
**Repo HEAD:** `99e1d3482aa2f9aee83a89bc966bfadd8bd03c67`  
**Skill:** `sast-ssti` (Phase 1 — zero dynamic template-engine render sites)  
**Method:** Static analysis only

## Executive Summary

- **Class status:** N/A
- Rendering sites analyzed: **0**
- Vulnerable: **0**
- Likely Vulnerable: **0**
- Not Vulnerable: **0**
- Needs Manual Review: **0**

No vulnerabilities found. No server-side template engine surface for SSTI.

## Evidence (absence)

### Dependencies

Searched package manifests for template engines (`ejs`, `nunjucks`, `handlebars`, `pug`/`jade`, `mustache`, `swig`, `twig`, lodash template, etc.): **no matches** in app `package.json` files.

Express API returns JSON; React SPA uses JSX (client-side). No Express `res.render` view engine is configured.

### Engine / render API usage

- Code search for `ejs`, `nunjucks`, `handlebars`, `mustache`, `pug.render`, `_.template`, `renderString`, `createTemplate`, `render_template_string`, `from_string`, `res.render(`: **no matches** in app JS under `backend/`, `frontend/`, `integration/`

### Closest HTML emission (reviewed, not SSTI)

`backend/routes/apiDocs.js` — `buildApiDocsHtml()` returns a **compile-time constant** template literal (no `${...}` interpolation). Served at `GET /api/docs` via `res.send(html)`. This is static HTML string building, not a template engine evaluating user-controlled template source — **out of class for SSTI** (per skill: HTML string builders ≠ SSTI engine).

## Findings

None. Phases 2–3 skipped (zero candidate rendering sites).
