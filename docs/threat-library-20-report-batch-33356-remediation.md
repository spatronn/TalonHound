# Threat Library: 20-report batch audit (33356–33375) remediation

Audit date: 2026-10-27. Scope: the 20 reports imported 2026-10-26 20:29Z – 2026-10-27 15:46Z
(13 Huntress, 6 Unit 42, 1 Check Point Research). Production was at `d9af1da`
(`tl-candidates-v40`, `THREAT_LIBRARY_SCOPE_ENGINE=section_tree`).

## Method

Ground truth comes from the retained publisher HTML, not from stored candidates. Each page was
converted with an independent stdlib parser (table cells, in-cell paragraphs, link targets), then
refanged and swept with regexes. Every IOC section, publisher-declared indicator section and body
observable was reviewed one by one. Linked GitHub and gist resources were checked: they are Sigma
rules, YARA rules, tool repositories and code snippets. None is an IOC dataset, and none of the 20
reports has a linked IOC Source.

## Result

| | Expected | TP | FN | FP |
|---|--:|--:|--:|--:|
| Stored (`tl-candidates-v40`) | 430 | 428 | 2 | 6 |
| Fixed (`tl-candidates-v41`, offline replay) | 430 | 430 | 0 | 0 |

The extraction truth (430) includes 4 publisher-listed values that are legitimate. The analyst
sets them to Context Only, which leaves 426 Indicators to approve:

- the official `cloudflared` GitHub release URL (33359);
- two "Signed OpenAI & Anthropic binaries" SHA-1s (33370);
- the C2 certificate Subject CN `justwatch.com` (33374).

## Root causes

| # | Defect | Reports | Fix |
|---|---|---|---|
| D1 | An IPv6 prefix (`2607:99c0::/32`) was tokenized as the host `2607:99c0::`; the prefix was lost | 33358 | `candidateExtraction`: an IPv6 token followed by `/len` (≤128) is a `cidr` |
| D2 | A defender resource ("Community-driven resources like lolrmm.io help …") was a MODE B Indicator | 33364 | `indicatorScope`: `DEFENDER_RESOURCE_RE` makes it a reference relation |
| D3 | `host[.]onion:443 51.89.228[.]250:21668` in one cell: the port lookahead rejected whitespace before a digit, so the host fell into the `key: value` branch (`config_context`) and stayed defanged | 33370 | `observableTypeResolver` v18: `(?!\d)` applies only to a `.` boundary |
| D4 | A bare SHA-1 listed under "XCSSET v40 SSL Thumbprint" was a file hash: list items took a digest scope only from a colon lead-in | 33373 | List scope label falls back to the governing heading |
| D5 | MD5s in an `Imphash \| Cluster \| Role` table were file hashes: the label window crossed the row break into "Role", and the column header was ignored | 33374 | `classifyHexDigest` takes `columnHeader`; a non-file kind there governs the cell |

## Verification

- 12 regression tests in `twentyReportBatch33356Regressions.test.js`, one per defect plus a negative
  control. Every defect test fails on `d9af1da`.
- 20 real-report labels (`audit_20_2026_10_27`). Benchmark: 190/190 exact, TP 5154, FP 0, FN 0.
- Corpus replay of all 239 stored reports: membership changes only in 33358 (+1), 33364 (−1),
  33370 (+1), 33373 (−1) and 33374 (−4). No finalized report changes.
