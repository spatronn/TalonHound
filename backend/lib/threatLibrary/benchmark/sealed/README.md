# Sealed evaluation set

This is the only tier that measures first-pass extraction quality. It is empty until independent labels exist, and the scorecard reports `not_yet_validated` until it holds enough reports.

## Rules

1. **Sample before looking.** Pick reports at import time by a recorded random, stratified method: publisher, format, and whether a package is announced. Never pick them because they looked hard or easy.
2. **Label before scoring.** A person labels the whole report from the publisher's source, including linked packages. Do not read TalonHound's output first.
3. **Never derive labels from TalonHound.** Approved Indicators, current membership and extractor output are not ground truth.
4. **Score the frozen code.** Record the first-pass score with the contract fingerprint before any fix is written.
5. **Keep it sealed.** Do not read sealed reports or their failures while writing extraction rules. A case used for tuning moves to `../cases/` and is replaced with a new sample.
6. **Record agreement.** Label at least 20% of cases twice and record where the labelers disagreed.

## Case format

Same schema as `../cases/`, plus:

| Field | Meaning |
|---|---|
| `publisher` | Source publisher |
| `sampling` | `{ method, drawn_at, stratum }` |
| `ground_truth.provenance` | `{ method, verified_by, verified_at, coverage_note, second_labeler? }` |
| `ground_truth.linked_packages` | Publisher packages the report points to, each with its URL and expected identities |

`npm run benchmark:threat-library -- --scorecard` prints every tier.
