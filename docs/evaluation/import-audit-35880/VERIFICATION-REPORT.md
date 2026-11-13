# Verification — import audit 35880–35889

Independent re-check of the first-pass audit claims against the retained publisher
evidence and the extractor's own decision traces. The first audit is not treated as
ground truth; two of its claims are corrected below.

## Summary

| # | Claim from first audit | Verdict | Disposition |
|---|---|---|---|
| 1 | Elastic 35881: 4 IP-lookup services are false-positive C2 Indicators | **Confirmed** | Fixed (tl-candidates-v67, IP-echo lead-in stance) |
| 2 | RL 35888: 26 publisher values held in `needs_review` | **Partly wrong** | 20 publisher E-table / seed values were *detached by the HTML extractor* (fixed, threat_library_html_v12). 17 appendix-table hashes are an intentional MODE A gate. The first audit undercounted the E table (it lists 28 rows, not 4) |
| 3 | RL 35888: one table row split (918fa… member, be99857… not) | **Confirmed, root cause corrected** | The split came from the truncated table (fix 2). With the full table both seed hashes are treated alike; no separate fix |
| 4 | Group-IB 35887: filename tokens typed as domains | **Confirmed** | Fixed (tl-type-resolver-v28, directory-tree listing entries) |
| 5 | Symantec 35886: publication date null | **Confirmed** | Fixed (tl-published-at-v5, sibling reading-time byline) |
| 6 | ASEC 35889: publication day 11 vs page 12 | **Not a defect** | JSON-LD states the instant `2026-11-11T15:00:00+00:00` (Nov 12 00:00 KST). The documented source ranking (JSON-LD outranks the visible date) applies |
| 7 | Fortinet 35883: `7Cxmr-ru.kryptex.network` | **Confirmed** | Fixed (tl-candidates-v67, percent escapes) |
| 8 | ASEC 35889: `aewn.Buzz` typed as artifact | **Confirmed, not fixed** | The generic fix conflicts with an existing contract (obfuscated mixed-case spellings in prose stay artifacts). No membership impact: it is an email-address domain (Context Only by policy) |
| 9 | ESET 35880: approving the GitHub folder would import unrelated Turla campaigns | **Not confirmed** | The existing campaign scope (tl-ioc-source-scope-v8) restricts both linked sources to the 18 Cereal SHA-1 |

## 1. Elastic 35881 — IP-echo services as C2

**Publisher evidence:** "To establish the host's public IP, SANSAR queries four external services in order, with a five-second deadline per attempt, stopping at the first valid response:" followed by `api.ipify.org`, `ifconfig.me/ip`, `icanhazip.com`, `checkip.amazonaws.com`. These are third-party IP-echo utilities, not operator infrastructure.

**Root cause (two layers):**
1. *Scope:* H3 "SANSAR analysis: anti-debugging and the encoded onion C2 domain" opens `c2_section` (heading cue `c2`, ≤64 chars, followed by a value line). H4 "Host and GPU enumeration" inherits it as an indicator *group*, because the bare group word "host" in `GROUP_LABEL_RE` qualifies any heading (section-tree trace: `b054 push zone=c2_section subgroup=true`). The four one-value paragraph lines are then `standalone_indicator_row` → rule `R10_publisher_assertion` → `explicit_c2`.
2. *Stance:* the existing IP-echo lead-in rule (tl-candidates-v53) recognises "public IP address identification services" phrasing only, and lead-in stance was applied to list items, never to one-value paragraph lines.

**Fix (layer 2 only):** a colon lead-in whose purpose clause says the listed services are queried to learn the host's own public IP marks them as IP-echo utilities (`R20_publisher_stance` → Context Only), also over a run of one-value paragraph lines. Only the words that qualify the services can veto it ("three attacker-controlled services"), not the sentence subject ("the loader queries …"). On paragraph lines only this narrow rule runs; the general list-stance cues stay list-only.

**Layer 1 not changed.** A section-tree rule ("a heading whose head noun is a technique is never an indicator group" plus "no re-inheritance under a blocking heading") fixed Elastic but failed the corpus blast radius. It demoted analyst-approved Indicators in 35620 ("Table 5: … Subdomain Enumeration" over an IOC table) and 35521 ("Persistence and bot execution"), and re-opened authority over a marketing heading in 35761. It was withdrawn; the section tree stays at tl-section-tree-v19. The scope leak is now harmless for this shape because the stance decides first, but it is recorded as a known limitation.

## 2–3. ReversingLabs 35888

**Root cause:** the page is React streaming SSR (Next.js App Router). The server sends the first rows of each appendix table inline and the rest as deferred segments after the article (`<table hidden><tbody id="S:x">…`), moved into `<template id="P:x">` placeholders by `$RS("S:x","P:x")`. The extractor read the segments in source order, so **E. Network indicators** kept 4 of its 28 rows. The other 24 rows became single-row tables trailing the article, outside the explicit IOC section (blocks b300–b392 of the stored document).

**Fix:** `htmlBlocks.parseHtml` applies the page's own `$RS` / `$RC` instructions before blocks are read (threat_library_html_v12). Only explicit instructions are applied; pages without them are untouched.

**Per-value disposition of the 26 first-audit values plus the 11 E rows it missed** (see `fp-fn-disposition.json`):

| Group | Values | Publisher evidence | Disposition |
|---|---|---|---|
| E. Network indicators rows 4–25 | 213.145.86.112, 104.145.210.184, 104.194.151.133, 104.194.159.55, 38.146.28.75, 107.189.26.194, 104.194.159.150, 38.146.28.132, ms365-device.com, m365-owa.com, wa-meeting.com, chathamhouse.eu, chamber-ua.org, cdncounter.net, `/s?r=7ed4bb1d`, `vendor-9f3a1c.min.js?ref=0f511e19&stub=1`, `…?ref=95766022&stub=1`, `polyfill-7e2b.min.js`, `/t/event` | Rows of the publisher's "Indicator \| Type \| Description" table, e.g. `213[.]145[.]86[.]112 \| IPv4 \| Stager hosting and beacon endpoint … Microsoft: ChocoShell C2` | **Extraction defect, fixed.** Members after fix (19) |
| Seed SHA-256 `be99857…` | 1 | "SHA-256 \| be99857… \| 918fa…" (seed samples table) | **Fixed as consequence** (both seed columns read alike once the table is whole) |
| E rows 26–27 (emails) | `anna.manager@russianearabroad.net`, `events@embassy-protocol.int` | "Email \| Phishing persona address" | Intentional: email addresses are unsupported; their domains stay non-members |
| A. Seed sample detail, C. Related files and confidence tiers, B (seventh YARA match) | 937e75e0…, 510af9bb…, c6f4df18…, fba867df…, ca3be588…, 154d8cfd…, 20e20b07…, 7acb7082…, 5bc3c615…, 9c5c5391…, 92cf0b88…, e82a7c86…, 1b97e0df…, 99f2eac2…, 04b64591…, 6e5c6582…, 28f62202… | Tables under headings that do not declare an indicator inventory. The publisher's own tiers hedge part of them ("Moderate confidence same operator; a second party reusing the stager template cannot be excluded") | **Intentional MODE A gate** (R40 `structured_rows_outside_curated_section`): surfaced to the analyst in `needs_review`, flagged by quality codes `appendix_heading_nonmember_rows` / `authoritative_table_not_interpreted` |
| Hunting lead | 192.142.52.31 | "Hunting lead (validate before blocking)" | Intentional `needs_review` |

**Appendix scope A–D:** the parent H2 "Indicators and research data" is not an inventory declaration. It mixes indicators with research pivots, MITRE, YARA, Sigma and hunting queries, and the publisher's markup puts C, D, E and F at H2, as *siblings* of the parent rather than children. Granting it authority would assert YARA metadata, hunting-query terms and pivot results. This is a review gate, not an implementation defect.

**Side effect found and fixed:** once the pivots table was whole, its cell `imphash:4e2bd2c4… (goodware and malicious splits)` sat in a line holding several `<hex> (` runs. The trailing note then overrode the bound `imphash:` prefix and typed it `md5` (needs_review). A key prefix bound to a digest now labels it, except algorithm-only prefixes (`sha256:` …), where the parenthetical still names the subject.

## 4. Group-IB 35887 — filename tokens

**Evidence:** a `tree` listing of a recovered Python source tree: `│ ├── Makefile.pre.in`, `│ ├── configure.ac`, `│ ├── pyconfig.h.in`, `│ └── MANIFEST.in`, beside `README.rst`, `aclocal.m4`, `LICENSE`. `.in` and `.ac` are delegated ccTLDs.

**Fix:** a dotted token led by a directory-tree glyph (`├──`, `└──`, ASCII `|--`, `` `-- ``) is a listing entry (`technical_artifact`, `directory_listing_entry`), unless defanged or in a stated network relation (tl-type-resolver-v28). Their 4 `needs_review` rows (finalize blockers) disappear; membership is unchanged.

## 5–6. Publication dates

- **Symantec 35886:** `<li class="metadata__item">12 Nov 2026</li><li class="metadata__item">20 Min Read</li>`. The reading-time cue sits in the next sibling item, so no visible-date rule fired. A date-only item followed by a short reading-time item is now the byline date. Related-post cards with the same layout sit in `related-…` noise containers and stay excluded (tl-published-at-v5). Result: 2026-11-12, `visible_date`, precision `date`. The other 9 reports are unchanged.
- **ASEC 35889:** not changed (see table).

## 7. Fortinet 35883 — percent escapes

**Evidence:** `GET /tj/xmr.php?data=DESKTOP-4OLCMRN%7C1985.71%7C1%7C0%7Cxmr-ru.kryptex.network%3A7029…`. The domain scan matched `7Cxmr-ru.kryptex.network`.

**Fix:** a match right after `%` whose first two characters decode to a printable ASCII separator drops them. Double encoding (`%252F`) is followed. `LIKE '%activation-form…%'` (`%ac`) and printf `%08x` are not escapes and are left alone; both shapes were found in the corpus.

## 9. ESET 35880 — linked-source scope

Verified offline against the publisher's files (sha256 in FREEZE.md):

- **GitHub `turla/` folder:** `selectCampaignScope` reads the README as multi-campaign and keeps only "Exchange for breakfast: Turla's Cereal tricks are not for kids - Indicators of Compromise" (18 SHA-1). The other 11 Turla campaign sections are excluded. `samples.{md5,sha1,sha256}` are deselected as unattributable folder hash lists. The seven `misp-turla-*-event.json` files are MISP API responses (`{"response":[{"Event":…}]}`), which no parser supports (`unsupported_json_schema`, zero values). YARA and `.py` files are not eligible.
- **White paper PDF:** pdf_v7 rebuilds all 18 SHA-1, which the IOCS table wraps across two lines (20 + 20 hex). Result: 18/18 found, 0 extra.

No change needed. Both sources are still `discovered` and pending, by design.

## Regression and blast radius

| Check | Result |
|---|---|
| New suite `importAudit35880Regressions.test.js` | 19 tests (positive + negative per change, plus corpus-shape guards) — pass |
| Full threat-library suite | 2304 tests, 0 failures (HEAD: 2285, 0 failures) |
| Benchmark (all tiers, layout variants) vs committed baseline | "no Indicator membership change"; baseline refreshed for the version stamps only |
| 10 audited reports, stored documents | only 35881 changes membership (−4 IP-echo services) |
| 10 audited reports, re-extracted from retained HTML | 35881 −4; 35888 +20 (E table + seed); 35887 −4 `needs_review` |
| Full production corpus, stored documents (794 reports) | membership changes only in 35881. 38 candidate outcomes change in 14 reports; all except 35881 are non-member (typing corrections, Context Only rows, removed junk/filename rows) |
| Streaming-SSR reports in production (39 with `$RS`/`$RC` in retained HTML), re-extracted | outcome changes only in 35888 (intended) and 35800 (4 excluded artifacts no longer emitted; Indicators unchanged) |

## Known limitations (recorded, not changed)

- **Section tree:** a C2-titled analysis heading (≤64 chars) followed by a value line opens `c2_section`, and a deeper heading containing a group word ("Host …") inherits it. No generalisable fix survived the corpus (see §1).
- Transposed record tables (`Field | Sample A | Sample B`) are read column-wise; with few type-labelled rows a sample column can become "description". No failing case remains after the HTML fix.
- `aewn.Buzz` (§8).
- Securelist 35885: the "Incident indicators" heading is not an IOC-section cue. Its table rows are members anyway, but read at tier C with assessment `unknown` for 3 IPs.
