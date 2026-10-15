# Threat Library extraction: architecture audit conclusions

Audit of IOC extraction on main `7757c5d`, followed by this branch's P0 work. The question: why does TalonHound keep needing report-specific extraction fixes?

**Labels:**
- **[V]** verified in code, tests or the benchmark
- **[H]** hypothesis that is not yet measured on real reports
- **[R]** recommendation

## Verdict

**Moderately fragile.** The policy core is sound; the structural layer is brittle, and its failures were silent until now.

What is sound **[V]**:
- Deterministic-first design.
- The model can never add an Indicator (`extractionStages.mergeAiCandidateUpdates` ignores unknown identities) or downgrade an explicit one.
- One membership contract with JS/SQL/frontend parity (`indicatorMembership.js`, `indicatorMembership.parity.test.js`).
- An AI-free Refresh extraction.

## 1. The three principal weaknesses

1. **Flat, linear scope instead of a heading tree.** **[V]**
   - `documentZones.annotateDocumentZones` walks blocks with single slots: `currentZone`, `opening`, `suspended`, and (since `7757c5d`) `appendixAnchor`. Every scope fix adds another slot or predicate; zones went v2→v9 in about a month.
   - Two "is this an indicator row?" checks disagree. `documentZones.isIndicatorRowBlock` rejects `loader.exe <md5>` lines, which `indicatorScope.isIndicatorRowShape` accepts. That disagreement is the cause of 5 of the 10 known benchmark failures.
2. **Normalization drops the structure that scope needs.** **[V]**
   - `pdfLayout.linesToBlocks` emits `heading` blocks without a `level`, although it computes font and height. Every `Number.isInteger(level)` hierarchy rule is therefore HTML-only (2 known failures).
   - PDF "filename hash" lines merge into one paragraph that is read as narrative (3 known failures).
   - HTML bold labels are discarded and later re-guessed from text shape.
3. **A document-wide MODE switch makes Indicator membership depend entirely on scope, and the failure was silent.** **[V]**
   - `indicatorScope.discoverDocumentIndicatorScope` sets MODE A as soon as any block is authoritative. In MODE A, membership needs a publisher assertion that only scope can grant.
   - A scope miss therefore drops publisher IOCs out of Indicators, and before this branch no diagnostic noticed. The pre-existing `structuralCompleteness` only looks inside curated zones.

## 2. Structural parsing versus Qwen reasoning

**What Qwen does [V]** (`ai/analyze.js`, `ai/prompts.js`, model `qwen3.5:9b` per code comments, Ollama, JSON-schema grammar):
- Classifies `ai_needed` candidates.
- Extracts entities and relationships.
- Writes summaries and tags.

**What Qwen does not do [V]:** zones, tables, typing, MODE, or **any MODE A membership**. The parity case `mode_a_body_mention_malicious` is a non-member even when the model says malicious.

**Benchmark evidence [V]:**
- All 40 false negatives are "extracted but not a member" (0 not extracted, 0 wrong type).
- Every one comes from structure: scope or row recognition.
- None is a semantic judgement a model would get right where the rules got it wrong.

**[H]** About 50–60% of past fix commits were structural, about 20–25% lexical typing, about 10–15% semantic (where Qwen helps) and about 10% persistence or contracts. This comes from classifying 38 fix-commit subjects by hand, not from a benchmark.

## 3. Should Qwen usage change?

**[R] Change how Qwen is used; do not increase it overall.**
- Structural failures are fixed by structure, not by more model calls.
- Worth evaluating: a narrow, grounded verifier for ambiguous sections (unknown heading over indicator rows, a level-less PDF appendix). It would receive a small section packet and return a role plus a quoted source span.
- It may never create candidates or override hard gates.
- Decouple an AI failure from deterministic review: today a model failure fails the whole report (`pipeline.js`).
- Measure first: the benchmark (A) against a section-tree variant without Qwen (A2) against A2 plus the verifier (B), on labeled real reports.

## 4. What to implement first

Done on this branch:
- The benchmark with metamorphic layouts and a known-failure ratchet.
- Deterministic quality warnings.
- The refresh membership guard with preview-bound acceptance.

**[R] Next, in order:**
1. Score 20–30 privately labeled real reports, and run the read-only quality scan on production with `--clean` to measure real false-warning rates.
2. Make the two indicator-row checks agree (5 known failures, one shared predicate). Coordinate with the owner of the scope work.
3. PDF heading rank: persist a level estimate from font height, bold and numbering (2 known failures).
4. Line-structure preservation for PDF value lists (3 known failures).

Each fix retires its entries in `knownFailures.js` and refreshes the baseline.

## 5. Detecting extraction anomalies automatically

`extractionQuality.assessExtractionQuality` (`tl-quality-v3`) **[V]** runs after every extraction and never reclassifies anything. It covers:
- Row-shaped IOC values right after an authoritative section but outside it.
- An appendix with zero or few hash Indicators.
- Authoritative sections without Indicators.
- Structural-completeness and table inconsistencies.
- Suspicious Indicators: example, legitimate-marker, publisher-domain, email-only, missing provenance.
- Indicators whose only authority is structural discovery: an IOC-shaped body table header, or an unlabelled observable list not governed by a publisher IOC heading (v3).

On the benchmark it flags all 10 failing cases and warns on none of the 33 correct ones. That figure is optimistic, because several rules were refined on these same synthetic failures (see `docs/threat-library-benchmark.md`).

Supporting tools:
- `scripts/threat-library-quality-scan.js` measures the same signal read-only over stored reports.
- The refresh guard turns parser regressions on stored reports into visible, blocked diffs instead of silent losses.

## 6. Minimal long-term changes to reduce report-specific fixes

**[R]**
1. **Section tree** instead of slot-based scope: each block gets a `section_path`, and scope comes from the nearest authoritative ancestor.
   - Inputs: HTML levels plus a PDF heading rank.
   - Run it in shadow mode against the benchmark and production previews before switching.
2. **One membership decision record** (`decideMembership()` with reason codes, persisted), so SQL and frontend read a decision instead of re-deriving it.
3. **A structural "needs review" state** for MODE A rows that look like publisher IOC rows but have no authoritative ancestor. Today these are silent drops; they would become visible review items without being promoted automatically.
4. **A benchmark gate on every extractor version bump.**

Avoid adding new heading keyword lists or per-publisher rules. Each failure class should land as a benchmark case first.
