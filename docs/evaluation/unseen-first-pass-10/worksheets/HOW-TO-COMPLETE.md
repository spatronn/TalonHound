# Unseen first-pass-10 — source-only labeling (Evidence-First)

This experiment is **separate** from the sealed 40-report benchmark and from the Qwen pilot packets.

## Goal

Measure production first-pass extraction on **10 never-imported** reports. Label from publisher source only. Do not open TalonHound or first-pass captures until your packet GT is filled.

## Files

| Item | Path |
|---|---|
| Manifest | `../manifest.json` |
| Packets (empty GT) | `../packets/unseen-*.json` |
| Retained HTML | `../_source_html/` (sha256 in packet) |
| Freeze | `../FREEZE.md`, `../freeze-contract.json` |
| First-pass captures | `../first-pass-captures/` (**coordinator only after labeling**) |

## Evidence-First (required)

For every accepted observable, record separately:

1. Raw + normalized value + type  
2. Exact publisher evidence + location  
3. Publisher assertion (`explicit` / `operational` / `context`) + evidence role → sealed `role`  
4. Policy decision → `IOC` / `Context Only` / `Needs Review` / `Unsupported`  
5. Confidence + rationale  

Do **not** derive policy from role alone. Map:

| Policy | Packet |
|---|---|
| IOC | `ground_truth.indicators[]` |
| Context Only | `ground_truth.context_only[]` |
| Needs Review | `ground_truth.ambiguous[]` + `rationale` |
| Unsupported | `provenance.coverage_note` only |

Full field map: `../../annotation-packet-guide.md` and the pilot Evidence-First HOW-TO under `../../pilot-qwen-candidates/worksheets/HOW-TO-COMPLETE.md`.

## Process

1. Open only the publisher URL or matching `_source_html/*.html`.  
2. Prefer IOC tables/appendices; still label narrative-asserted values.  
3. Add linked IOC packs under `linked_packages` when the publisher links them.  
4. Fill provenance.  
5. Only then may the coordinator open `first-pass-captures/` for scoring.

## Hard rules

- No TalonHound / Claude / Qwen as GT.  
- No auto-approve / finalize during the experiment.  
- Do not copy packets into `sealed/cases/`.  
- Record uncertainty and unsupported types.
