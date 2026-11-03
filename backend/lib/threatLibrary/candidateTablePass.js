/**
 * Typed indicator tables: every valid row is a source assertion with row provenance.
 */

import { normalizeCandidateValue } from './candidateValue.js';
import { parseIndicatorCell } from './tableSemantics.js';
import { RESOLVED_TYPES } from './observableTypeResolver.js';
import { buildRowObservation } from './sourceObservation.js';
import { descriptionClauseAssertsRole, tableColumnLabels, versionColumnTokens, OCCURRENCE_FORMS, HISTORICAL_RESOLUTION_ROW_RE, candidateKey, relatedValuesFromDescription } from './candidateHelpers.js';

/**
 * @param {object[]} blocks zone-annotated blocks
 * @param {ReturnType<import('./candidateAccumulator.js').createCandidateAccumulator>} acc
 * @param {{
 *   diagnostics: object, explicitTableAssertions: object, tableHandled: Set, referenceColumnValues: Map,
 *   networkEndpoints: Array, slashDateOrder: string|null, observationNotAfter: string|null, noteRejectedToken: Function
 * }} ctx
 */
export function readTypedTables(blocks, acc, ctx) {
  const { add, deferTruncatedDigest } = acc;
  const { diagnostics, explicitTableAssertions, tableHandled, referenceColumnValues, networkEndpoints, slashDateOrder, observationNotAfter, noteRejectedToken } = ctx;
  // Pass 0: typed indicator tables — every valid row is a source assertion with row provenance.
  for (let blockIndex = 0; blockIndex < blocks.length; blockIndex += 1) {
    const block = blocks[blockIndex];
    if (block.type !== 'table' || !block.table) continue;
    const t = diagnostics.explicit_tables;
    t.tables_seen += 1;
    const interp = block.ioc_table;
    const summary = {
      table_id: block.id,
      page: block.page ?? null,
      zone: block.zone || null,
      section_heading: block.section_heading || null,
      kind: interp?.kind || 'not_ioc_table',
      explicit: Boolean(interp?.explicit),
      reason: interp?.reason || null,
      columns: Array.isArray(interp?.columns) ? interp.columns.map((c) => ({ index: c.index, header: c.header, intent: c.intent, method: c.method })) : [],
      rows_seen: interp?.stats?.rows_seen ?? 0,
      rows_valid: interp?.stats?.rows_valid ?? 0,
      rows_rejected: interp?.stats?.rows_rejected ?? 0,
      rejection_reasons: interp?.stats?.rejection_reasons || {},
      rejected_rows: []
    };
    t.tables.push(summary);
    if (!interp || (interp.kind !== 'ioc_table' && interp.kind !== 'artifact_table')) {
      // A table without indicator columns is read by the regex passes; the
      // values of its reference columns ("Handle | Repository | Role":
      // where a tool is published / who is credited) stay provenance there
      // too, even under an IOC heading (tl-candidates-v52).
      const refValues = new Set();
      for (const col of (interp?.columns || []).filter((c) => c.attribute_kind === 'reference')) {
        for (const row of block.table.rows || []) {
          const cell = String((Array.isArray(row) ? row : row?.cells || [])[col.index] || '').trim();
          if (!cell) continue;
          for (const v of parseIndicatorCell(cell, null).values) {
            const n = v.is_ioc === false ? null : normalizeCandidateValue(v.refanged, v.candidate_type);
            if (n?.ok) refValues.add(`${n.candidateType}:${n.normalizedValue.toLowerCase()}`);
          }
        }
      }
      if (refValues.size) referenceColumnValues.set(block.id, refValues);
      continue;
    }
    if (interp.kind === 'ioc_table') t.ioc_tables += 1;
    if (interp.explicit) t.explicit_tables += 1;
    tableHandled.add(block.id);
    t.rows_seen += summary.rows_seen;
    t.rows_valid += summary.rows_valid;
    t.rows_rejected += summary.rows_rejected;
    for (const [reason, n] of Object.entries(summary.rejection_reasons)) {
      t.rejection_reasons[reason] = (t.rejection_reasons[reason] || 0) + n;
    }
    const columnLabels = tableColumnLabels(interp, blocks[blockIndex - 1]);
    for (const row of interp.rows || []) {
      if (row.status !== 'valid') {
        if (summary.rejected_rows.length < 12) summary.rejected_rows.push({ row_index: row.row_index, reason: row.reason });
        continue;
      }
      // Classification haystack (typing / credential / embedded-host checks)
      // stays the asserted cells; evidence shows the publisher's whole row.
      const rowText = [row.type_cell, row.values[0]?.indicator_cell, row.description].filter(Boolean).join(' | ');
      const rowCells = Array.isArray(row.cells) ? row.cells : [];
      const fullRowText = rowCells.filter(Boolean).join(' | ') || rowText;
      const observation = buildRowObservation({
        cells: rowCells,
        headers: columnLabels,
        indicatorColumns: interp.indicator_columns,
        slashOrder: slashDateOrder,
        notAfter: observationNotAfter
      });
      const attributeKinds = new Map((interp.columns || []).filter((c) => c.attribute_kind).map((c) => [c.index, c.attribute_kind]));
      const contextCells = rowCells
        .map((text, index) => ({
          column_index: index,
          header: columnLabels?.[index] || null,
          text,
          // Certificate / fuzzy-hash attribute of the row's sample (never an Indicator).
          ...(attributeKinds.has(index) ? { attribute_kind: attributeKinds.get(index) } : {})
        }))
        .filter((c) => c.text && !interp.indicator_columns.includes(c.column_index))
        .slice(0, 8)
        .map((c) => ({ ...c, text: c.text.slice(0, 160) }));
      const related = relatedValuesFromDescription(row.description);
      for (const v of row.values) {
        t.values_asserted += 1;
        // A hosts-file mapping entry names a host the sample blocks, not its
        // infrastructure: row context, never the row's assertion (tl-table-v12).
        // A digest the publisher truncated is a prefix of another value, not
        // an assertion of its own (resolved against the report's full digests).
        // A row the publisher describes as the historical resolution of another
        // name ("Historical resolution for example[.]com.") lists a passive-DNS
        // pivot, not an address the publisher attributes to the actor: row
        // context like a "Resolved IP" column (tl-candidates-v54). Firm
        // C2 / staging / case-observed rows of the same table keep asserting.
        const historicalPivot =
          v.is_ioc !== false &&
          ['ip', 'ipv6', 'domain'].includes(v.candidate_type) &&
          HISTORICAL_RESOLUTION_ROW_RE.test(String(row.description || ''));
        const assertedIoc =
          Boolean(interp.explicit) && v.is_ioc !== false && v.hosts_file_entry !== true && !v.truncated_digest && !historicalPivot;
        if (assertedIoc && v.candidate_type && v.normalized_value) {
          explicitTableAssertions.rememberAsserted(v.candidate_type, v.normalized_value);
        }
        const tableRow = {
          table_id: block.id,
          page: block.page ?? null,
          row_index: row.row_index,
          source_row_index: row.source_row_index,
          column_index: v.column_index,
          // Publisher header of the value's own column ("Domain / IP", "URL").
          column_header: columnLabels?.[v.column_index] || null,
          declared_type: v.declared_type || null,
          type_cell: row.type_cell,
          indicator_cell: v.indicator_cell,
          raw_value: v.raw,
          description: row.description,
          explicit: Boolean(interp.explicit),
          declared_type_mismatch: v.declared_type_mismatch === true || undefined,
          related_values: related.length ? related : undefined,
          resolved_type: v.resolved_type || v.candidate_type,
          typing_reason: v.typing_reason || undefined,
          cells: contextCells.length ? contextCells : undefined,
          observation: observation || undefined,
          // Mixed cell provenance: the file identity and the hash(es) it carries.
          cell_companions: v.cell_companions?.length ? v.cell_companions : undefined,
          cell_residual: v.cell_residual || undefined,
          // Publisher conventions that named the host (tl-table-v17).
          wildcard_apex: v.wildcard_apex || undefined,
          endpoint_scheme: v.endpoint_scheme || undefined,
          certificate_cn: v.certificate_cn || undefined
        };
        if (v.cell_companions?.length && v.is_ioc !== false) t.mixed_cells.recovered_values += 1;
        if (v.cell_companions?.length && v.is_ioc === false) t.mixed_cells.decomposed += 1;
        if (v.cell_residual) {
          t.mixed_cells.residual_unparsed += 1;
          for (const id of v.residual_observables || []) {
            if (t.mixed_cells.residual_observables.length < 24) {
              t.mixed_cells.residual_observables.push({ table_id: block.id, row_index: row.row_index, identity: id, zone: block.zone || null });
            }
          }
        }
        const valueExtra = {
          form: OCCURRENCE_FORMS.TABLE_ROW,
          port: v.port ?? null,
          originalValue: v.raw,
          tableRow,
          rowText,
          evidenceRowText: fullRowText,
          typeLabel: v.type_label !== undefined ? v.type_label : row.type_cell || null,
          declaredType: v.declared_type || null,
          typing: {
            typing_reason: v.typing_reason || null,
            artifact_kind: v.artifact_kind || null,
            typing_signals: v.typing_signals || null
          },
          explicitTable: Boolean(interp.explicit),
          ...(v.wildcard_apex === true ? { wildcardApex: true } : {}),
          ...(v.hosts_file_entry === true ? { hostsFileEntry: true } : {}),
          ...(historicalPivot
            ? {
                form: OCCURRENCE_FORMS.STANDALONE,
                explicitTable: false,
                referenceCell: true,
                typingReason: 'resolution_column',
                typing: { typing_reason: 'resolution_column' }
              }
            : {})
        };
        if (v.truncated_digest) {
          // Link to the report's full digest when it is unique; otherwise the
          // cell reads as before.
          deferTruncatedDigest(v.truncated_digest, block, valueExtra, () => add(v.refanged, v.candidate_type, block, valueExtra));
          continue;
        }
        const entry = add(v.refanged, v.candidate_type, block, valueExtra);
        if (v.endpoint_scheme && entry && v.normalized_value && v.raw) {
          // The publisher's "tcp://host:port" spelling stays on the host identity.
          networkEndpoints.push([v.candidate_type, v.normalized_value, String(v.raw).slice(0, 200)]);
        }
        if (assertedIoc && entry?.digest_kind && entry.candidate_type !== v.candidate_type) {
          explicitTableAssertions.rememberReclassified(v.candidate_type, v.normalized_value, entry.candidate_type);
        }
        if (assertedIoc && !entry) {
          explicitTableAssertions.rememberDropped(
            v.candidate_type,
            v.normalized_value,
            acc.lastRejection() || 'rejected'
          );
        }
      }
    }
    // Description cells: observables written in a row's prose cell. One whose
    // own clause gives it an actor-infrastructure role ("evil.example (C2
    // SystemBC)") in an explicit IOC table is that row's assertion; any other
    // is Context Only provenance — kept, never dropped (tl-candidates-v37).
    const descriptionCols = (interp.columns || []).filter((c) => c.intent === 'description');
    for (const row of interp.rows || []) {
      const rowValues = new Set((row.values || []).map((v) => candidateKey(v.candidate_type, v.normalized_value)));
      for (const col of descriptionCols) {
        const cell = String(row.cells?.[col.index] || '').trim();
        if (!cell) continue;
        const parsedCell = parseIndicatorCell(cell, null);
        // A digest this cell shows cut short with an ellipsis ("SHA256: e76f54…")
        // belongs to the one full digest the report states elsewhere: the row
        // then carries that digest as its own value (tl-candidates-v54).
        for (const trunc of parsedCell.truncated_digests || []) {
          const truncRowText = (row.cells || []).filter(Boolean).join(' | ');
          const lookalike = parsedCell.values.find((v) => v.truncated_digest === trunc);
          deferTruncatedDigest(
            trunc,
            block,
            {
              form: OCCURRENCE_FORMS.TABLE_ROW,
              rowText: truncRowText,
              evidenceRowText: truncRowText,
              tableRow: {
                table_id: block.id,
                page: block.page ?? null,
                row_index: row.row_index,
                source_row_index: row.source_row_index,
                column_index: col.index,
                column_header: columnLabels?.[col.index] || null,
                declared_type: null,
                type_cell: row.type_cell || null,
                indicator_cell: cell,
                raw_value: trunc.spelling,
                description: row.description,
                explicit: Boolean(interp.explicit),
                description_value: true
              },
              explicitTable: Boolean(interp.explicit)
            },
            // Unlinked: the look-alike stays the row's description context.
            lookalike && !rowValues.has(candidateKey(lookalike.candidate_type, lookalike.normalized_value))
              ? () =>
                  add(lookalike.refanged, lookalike.candidate_type, block, {
                    form: OCCURRENCE_FORMS.STANDALONE,
                    originalValue: lookalike.raw,
                    rowText: truncRowText,
                    descriptionCell: true
                  })
              : null
          );
        }
        for (const v of parsedCell.values) {
          if (v.truncated_digest) continue;
          if (v.is_ioc === false || rowValues.has(candidateKey(v.candidate_type, v.normalized_value))) continue;
          if (v.candidate_type === 'domain' && !String(v.normalized_value).includes('.')) continue;
          const rowText = (row.cells || []).filter(Boolean).join(' | ');
          if (Boolean(interp.explicit) && descriptionClauseAssertsRole(cell, v.refanged)) {
            explicitTableAssertions.rememberAsserted(v.candidate_type, v.normalized_value);
            add(v.refanged, v.candidate_type, block, {
              form: OCCURRENCE_FORMS.TABLE_ROW,
              port: v.port ?? null,
              originalValue: v.raw,
              rowText,
              evidenceRowText: rowText,
              tableRow: {
                table_id: block.id,
                page: block.page ?? null,
                row_index: row.row_index,
                column_index: col.index,
                column_header: columnLabels?.[col.index] || null,
                declared_type: null,
                type_cell: row.type_cell || null,
                indicator_cell: cell,
                raw_value: v.raw,
                description: row.description,
                explicit: true,
                description_value: true
              },
              explicitTable: true
            });
          } else {
            // Context only: the value is related row metadata, so an endpoint
            // port written beside it is not recorded as the value's port.
            add(v.refanged, v.candidate_type, block, {
              form: OCCURRENCE_FORMS.STANDALONE,
              originalValue: v.raw,
              rowText,
              descriptionCell: true
            });
          }
        }
      }
    }
    // Reference columns ("Source" / "Download" / "Homepage" links of a tool
    // table): provenance of the row's subject, kept as Context Only values
    // and never asserted, whatever section the table sits in (tl-table-v9).
    // Resolution columns ("Resolved IP") are the same kind of provenance: the
    // row domain's DNS answer, not an actor address (tl-table-v11).
    for (const col of (interp.columns || []).filter((c) => c.attribute_kind === 'reference' || c.attribute_kind === 'resolution')) {
      const typingReason = col.attribute_kind === 'resolution' ? 'resolution_column' : 'reference_column';
      for (const row of interp.rows || []) {
        const cell = String(row.cells?.[col.index] || '').trim();
        if (!cell) continue;
        for (const v of parseIndicatorCell(cell, null).values) {
          if (v.is_ioc === false) continue;
          add(v.refanged, v.candidate_type, block, {
            form: OCCURRENCE_FORMS.STANDALONE,
            originalValue: v.raw,
            rowText: (row.cells || []).filter(Boolean).join(' | '),
            referenceCell: true,
            typingReason,
            typing: { typing_reason: typingReason }
          });
        }
      }
    }
    // Attribute columns (a certificate thumbprint or fuzzy hash beside the
    // sample) are never read as rows: record what their cells hold and why.
    for (const col of (interp.columns || []).filter((c) => c.attribute_kind && c.attribute_kind !== 'reference' && c.attribute_kind !== 'resolution')) {
      for (const row of interp.rows || []) {
        const cell = String(row.cells?.[col.index] || '').trim();
        if (cell) noteRejectedToken(cell, 'attribute_cell', block, `attribute_column:${col.attribute_kind}`, 'unsupported');
      }
    }
    // Version-column release numbers of an indicator table are never row
    // values (tl-table-v5); keep them as version metadata, as the text pass does.
    const versionTokens = versionColumnTokens(block);
    for (const value of versionTokens?.inVersion || []) {
      if (versionTokens.elsewhere.has(value)) continue;
      add(value, RESOLVED_TYPES.TECHNICAL_ARTIFACT, block, {
        form: OCCURRENCE_FORMS.STANDALONE,
        originalValue: value,
        typing: { typing_reason: 'version_column', artifact_kind: 'metadata' }
      });
    }
  }
}
