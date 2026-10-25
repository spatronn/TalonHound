# Held-out pilot corpus (2026-10-25)

| id | publisher | format | labels | notes |
|---|---|---|---|---|
| heldout-talos-uat-9686 | Cisco Talos | html | verified extract | Public blog IOC section |
| heldout-talos-uat-7237 | Cisco Talos | html | verified extract | Public blog IOC block |
| heldout-eset-promptspy | ESET | html | verified extract | IoCs tables (file subset + network) |
| heldout-unit42-panos-cve | Unit 42 | html | verified extract | IP list under Indicators of the Activity |
| heldout-cisa-aa24-290a | CISA | html | verified extract | Appendix B hashes + IP subset |
| heldout-unknown-nested-appendix | synthetic | html | constructed | Nested appendix structure |
| heldout-unknown-benign-near-malicious | synthetic | html | constructed | Benign near malicious |
| heldout-unknown-empty-appendix | synthetic | html | constructed | Empty IOC appendix / quality |
| heldout-unknown-three-unlabelled-rows | synthetic | html | constructed | Section-tree no MODE A from 3 rows |

**Target:** 10 pilot / 30–50 expanded. **Actual labeled:** 9.

None of these IDs appear in `../cases/` or `../real-reports/`. Once a case is used to tune extraction, move it out of `heldOut/cases/` into regression and replace it.
