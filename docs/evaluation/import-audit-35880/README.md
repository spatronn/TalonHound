# Import audit 35880–35889

Ten never-before-imported public reports were imported through MCP on production
`cab54b1` (2026-11-13). Their first-pass extraction was captured unchanged, then
audited and independently verified against the publishers' own evidence.

- [FREEZE.md](FREEZE.md): contract fingerprint, source artifact hashes, and the files of the frozen first pass.
- [first-pass-captures/](first-pass-captures/): per-report candidate roster with membership outcome, rule and evidence excerpt, as persisted.
- [first-pass-extraction-runs.jsonl](first-pass-extraction-runs.jsonl): the extraction run of each report (contract bundle, counts, artifacts).
- [VERIFICATION-REPORT.md](VERIFICATION-REPORT.md): verified defects versus intentional policy, root causes, fixes, regression and blast-radius results.
- [fp-fn-disposition.json](fp-fn-disposition.json): every discrepancy with its category.

## Reproduce

The private files (`_corpus/`, `_source_html/`, `_linked_sources/`) are gitignored
because they hold publisher content. They are restored from the production artifact
store and database by the sha256 values in FREEZE.md.

```bash
# stored documents (exactly what the first pass computed from)
node backend/scripts/threat-library-corpus-replay.js docs/evaluation/import-audit-35880/_corpus/first-pass-35880-35889.jsonl --out /tmp/replay.json
```

At `cab54b1` the replay reproduces stored membership for all 10 reports.

## Separation

`sealed_eligible: false`. Nothing here feeds the sealed benchmark, and no frozen
dataset was modified. No candidate was approved, no IOC created and no report
finalized or refreshed by this work.
