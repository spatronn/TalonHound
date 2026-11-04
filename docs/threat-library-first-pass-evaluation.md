# First-pass evaluation protocol

How to measure Threat Library first-pass quality on the next 30–50 reports. Until a sealed set meets this protocol, `first_pass_accuracy` stays `not_yet_validated`, and no replay or regression figure stands in for it.

**Dependency:** this needs qualified human reviewers. The tooling can draw the sample and check the labels. It cannot produce them.

## Steps

| # | Who | What |
|---|---|---|
| 1 | Coordinator | Before reading any report, write the candidate list and record it (`population.json`). |
| 2 | Coordinator | Freeze the code. Draw the sample with a recorded seed. The manifest stores the contract fingerprint. |
| 3 | Coordinator | Generate one empty packet per report; about a fifth get a second one. |
| 4 | Labelers | Label each report from the publisher's source, independently, without opening TalonHound. |
| 5 | Coordinator | Compare double-labelled reports and resolve each disagreement against the source. |
| 6 | Coordinator | Validate, then import the sampled reports with no code changes. |
| 7 | Coordinator | Score the frozen code once. Record the score before any fix is written. |
| 8 | Engineers | Fix what the score shows. A case used for a fix leaves the sealed set for good. |

```bash
node scripts/threat-library-eval.js sample population.json --seed batch-2026-11 --size 40 --out manifest.json
```

```bash
node scripts/threat-library-eval.js packets manifest.json --out packets/
```

```bash
node scripts/threat-library-eval.js agreement first.json second.json
```

```bash
node scripts/threat-library-eval.js validate
```

```bash
npm run benchmark:threat-library -- --scorecard
```

## Sample

`population.json` lists every report being considered: `[{ id, url, title, publisher, format, package_announced }]`.

The draw is seeded and stratified by publisher, format and whether a package is announced. Each stratum gets a report before any gets a second. Fix the size in advance. Don't redraw because a sample looks hard; if a report is unusable, record why and draw the next one.

## Labeling

Label what the publisher states, working from the article and any package it links. Leave out what you know from elsewhere.

**Never use** TalonHound output, approved Indicators, IOC rows or a model's opinion. `validate` refuses a case whose method names them, but this rule relies on the labeler: the check catches wording, not behaviour.

| Field | Content |
|---|---|
| `ground_truth.indicators` | Values the publisher presents as indicators of this report's activity |
| `ground_truth.context_only` | Values named but not asserted: victims, legitimate services, references, placeholders |
| `ground_truth.ambiguous` | Genuinely unclear, with a rationale. Not scored as right or wrong |
| `ground_truth.linked_packages` | Each package the publisher links: `url`, `expected_identities`. Empty if none |
| each value | `type`, `value`, `role`, `evidence` (where in the source: section, table and row, or quoted sentence) |
| `provenance` | `method`, `verified_by`, `verified_at`, `coverage_note` (what was and was not read) |

Roles: `command_and_control`, `malware_download`, `phishing`, `malware_sample`, `staging`, `exfiltration`, `victim`, `legitimate_service`, `reference`, `placeholder`, `other`.

Document-only and package ground truth stay separate: `indicators` covers the document, `linked_packages` the packs.

## Independent review

At least 20% of reports get a second labeler who has not seen the first set of labels. Record the agreement figure. Resolve each disagreement against the publisher's source and note the outcome in `provenance.disagreement_resolution`. Don't resolve one by checking what TalonHound did.

## Valid score

`validate` must pass and `first_pass_accuracy` flips to validated only with at least 30 valid reports, the second-labeler share met, and labels against the fingerprint of the code being scored. If the contract changes before scoring, the sealed labels stay valid as labels but the score is for the new code, so record both.

## What the scorecard reports

Per tier: precision, recall, F1, report exact match, document-only coverage, linked package discovery recall, type accuracy, classification accuracy, review queue volume, silent evidence loss, provenance completeness and per-stage failure rates, plus comparison with the baseline.

**Known gap:** linked package coverage measures whether discovery reaches a labelled package. Whether every identity in that package was extracted needs the fetched pack files and is not scored yet. `expected_identities` is collected now so it can be.

## What other tiers can say

| Tier | Says | Does not say |
|---|---|---|
| Development | Structure handling works on synthetic layouts | Anything about real reports |
| Regression | Past fixes still hold | Accuracy on unseen reports: labelled alongside the fix |
| Held-out | An indication on a small, partly contaminated set | A validated accuracy |
| Private source scoring | Real reports score against committed labels, where the private store is present | Skipped in CI. A skip is "not evaluated", never a pass |
| Corpus replay | What a contract change would alter | Whether the change is right |
