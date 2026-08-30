import { getSearchTimezone } from './config.js';
import { likeEscape, normalizeIocValue } from './normalize.js';
import { isFileArtifactsReadEnabled } from '../fileArtifacts/flags.js';

// Compiles a validated AST into a single boolean SQL expression plus a positional
// parameter array. EVERY user-derived value is bound as a parameter — no DSL token is
// ever concatenated into SQL text. Column/table/operator SQL is chosen exclusively
// from the whitelisted field registry, so the AST cannot introduce arbitrary SQL.
//
// The generated expression references the ioc_items row via the alias `i`; callers
// must select `FROM ioc_items i`.

const IOC_ALIAS = 'i';

/** Resolved active artifact id from a link row (follows merge tombstones). */
const RESOLVED_ARTIFACT_ID_SQL = `COALESCE(
  CASE
    WHEN fa.status = 'merged' AND fa.merged_into_artifact_id IS NOT NULL
      THEN fa.merged_into_artifact_id
    ELSE fa.id
  END,
  fa.id
)`;

function normalizeTagValue(value) {
  return String(value).trim().replace(/\s+/g, ' ').toLowerCase();
}

class Builder {
  constructor(tz, { fileArtifactsReadEnabled = false } = {}) {
    this.params = [];
    this.tz = tz;
    this.fileArtifactsReadEnabled = Boolean(fileArtifactsReadEnabled);
  }

  bind(value) {
    this.params.push(value);
    return `$${this.params.length}`;
  }

  // A date literal becomes either a plain timestamptz (when it carried an explicit
  // offset/Z) or a wall-clock timestamp interpreted in the configured timezone. The
  // timezone name is itself bound, so the comparison never depends on session state.
  dateExpr(parsed) {
    if (parsed.hasTimezone) {
      return `${this.bind(parsed.value)}::timestamptz`;
    }
    const valuePh = this.bind(parsed.value);
    const tzPh = this.bind(this.tz);
    return `(${valuePh}::timestamp AT TIME ZONE ${tzPh})`;
  }

  build(node) {
    switch (node.type) {
      case 'and':
        return `(${node.children.map((c) => this.build(c)).join(' AND ')})`;
      case 'or':
        return `(${node.children.map((c) => this.build(c)).join(' OR ')})`;
      case 'not':
        return `(NOT ${this.build(node.child)})`;
      case 'condition':
        return this.buildCondition(node);
      default:
        throw new Error(`Unknown AST node type: ${node.type}`);
    }
  }

  buildCondition(node) {
    switch (node.field) {
      case 'ioc':
        return this.buildIoc(node);
      case 'tag':
        return this.buildTag(node);
      case 'source':
        return this.buildSource(node);
      case 'threat_actor':
        return this.buildThreatActor(node);
      case 'classification':
        return this.buildClassification(node);
      case 'type':
        return this.buildType(node);
      case 'known_hash_type':
        return this.buildKnownHashType(node);
      case 'md5':
      case 'sha1':
      case 'sha256':
        return this.buildFileHash(node);
      case 'imphash':
      case 'tlsh':
      case 'ssdeep':
        return this.buildNonIdentityAttr(node);
      case 'status':
        return this.buildSimpleEnum(node, `COALESCE(${IOC_ALIAS}.status, 'active')`, { lower: false });
      case 'confidence':
        return this.buildSimpleEnum(node, `${IOC_ALIAS}.confidence`, { lower: true });
      case 'first_seen':
        return this.buildFirstSeen(node);
      case 'created_at':
        return this.buildItemDate(node, `${IOC_ALIAS}.created_at`);
      case 'last_changed':
        return this.buildLastChanged(node);
      default:
        throw new Error(`Unsupported field in builder: ${node.field}`);
    }
  }

  // ---- text: ioc --------------------------------------------------------
  buildIoc(node) {
    const raw = node.values[0];
    const norm = normalizeIocValue(raw);
    const col = `${IOC_ALIAS}.observable`;
    switch (node.operator) {
      case 'contains':
        return `${col} ILIKE ${this.bind(`%${likeEscape(norm)}%`)} ESCAPE '\\'`;
      case 'not_contains':
        return `${col} NOT ILIKE ${this.bind(`%${likeEscape(norm)}%`)} ESCAPE '\\'`;
      case 'starts_with':
        return `${col} ILIKE ${this.bind(`${likeEscape(norm)}%`)} ESCAPE '\\'`;
      case 'ends_with':
        return `${col} ILIKE ${this.bind(`%${likeEscape(norm)}`)} ESCAPE '\\'`;
      // Case-insensitive exact match expressed as a wildcard-free ILIKE so it uses the
      // observable trigram GIN index. LOWER(col) = $ cannot use that index and forces a
      // multi-million-row walk of the created_at index (measured ~1.7s vs ~28ms here).
      case 'equals':
        return `${col} ILIKE ${this.bind(likeEscape(norm))} ESCAPE '\\'`;
      case 'not_equals':
        return `${col} NOT ILIKE ${this.bind(likeEscape(norm))} ESCAPE '\\'`;
      default:
        throw new Error(`Unsupported operator for ioc: ${node.operator}`);
    }
  }

  // ---- text: source -----------------------------------------------------
  // Matches what the IOC list Source badge shows, without hard-coding aliases:
  //   1) ioc_items.source_name (canonical / stored identifier)
  //   2) integration_feeds.name via ioc_feed_memberships (feed display name)
  //   3) ioc_sources.name for manual IOC sources
  // Equals / in are case-insensitive exact matches on any of those identities.
  // Multiple feeds sharing one display name all contribute their member IOCs.
  // Negations invert the whole disjunction (NOT (A OR B OR C)).
  buildSource(node) {
    const negativeToPositive = {
      not_contains: 'contains',
      not_equals: 'equals',
      not_in: 'in'
    };
    if (Object.prototype.hasOwnProperty.call(negativeToPositive, node.operator)) {
      return `(NOT ${this.buildSourcePositive({
        ...node,
        operator: negativeToPositive[node.operator]
      })})`;
    }
    return this.buildSourcePositive(node);
  }

  buildSourcePositive(node) {
    const onSourceName = this.buildTextColumn(node, `${IOC_ALIAS}.source_name`);
    const onFeedName = this.buildTextColumn(node, 'f.name');
    const onManualName = this.buildTextColumn(node, 's.name');
    const viaFeedDisplay = `EXISTS (
      SELECT 1
      FROM ioc_feed_memberships m
      JOIN integration_feeds f ON f.integration_id = m.feed_id
      WHERE m.ioc_item_id = ${IOC_ALIAS}.id
        AND m.ioc_observable_type = ${IOC_ALIAS}.observable_type
        AND (${onFeedName})
    )`;
    const viaManualSource = `EXISTS (
      SELECT 1
      FROM ioc_sources s
      WHERE s.id = ${IOC_ALIAS}.ioc_source_id
        AND (${onManualName})
    )`;
    return `(${onSourceName} OR ${viaFeedDisplay} OR ${viaManualSource})`;
  }

  buildTextColumn(node, col) {
    switch (node.operator) {
      case 'contains':
        return `${col} ILIKE ${this.bind(`%${likeEscape(node.values[0])}%`)} ESCAPE '\\'`;
      case 'not_contains':
        return `${col} NOT ILIKE ${this.bind(`%${likeEscape(node.values[0])}%`)} ESCAPE '\\'`;
      case 'starts_with':
        return `${col} ILIKE ${this.bind(`${likeEscape(node.values[0])}%`)} ESCAPE '\\'`;
      case 'ends_with':
        return `${col} ILIKE ${this.bind(`%${likeEscape(node.values[0])}`)} ESCAPE '\\'`;
      // Case-insensitive exact match via wildcard-free ILIKE so it uses the source_name
      // trigram GIN index instead of forcing LOWER(col) = $ (which cannot).
      case 'equals':
        return `${col} ILIKE ${this.bind(likeEscape(node.values[0]))} ESCAPE '\\'`;
      case 'not_equals':
        return `${col} NOT ILIKE ${this.bind(likeEscape(node.values[0]))} ESCAPE '\\'`;
      case 'in':
        return `LOWER(${col}) = ANY(${this.bind(node.values.map((v) => v.toLowerCase()))}::text[])`;
      case 'not_in':
        return `LOWER(${col}) <> ALL(${this.bind(node.values.map((v) => v.toLowerCase()))}::text[])`;
      default:
        throw new Error(`Unsupported operator for text column: ${node.operator}`);
    }
  }

  // ---- text: tag (EXISTS over ioc_tags + tags) --------------------------
  buildTag(node) {
    const base = (cond) =>
      `EXISTS (SELECT 1 FROM ioc_tags it JOIN tags t ON t.id = it.tag_id ` +
      `WHERE it.ioc_id = ${IOC_ALIAS}.id AND it.ioc_observable_type = ${IOC_ALIAS}.observable_type ` +
      `AND ${cond})`;
    switch (node.operator) {
      case 'contains':
        return base(`t.name ILIKE ${this.bind(`%${likeEscape(normalizeTagValue(node.values[0]))}%`)} ESCAPE '\\'`);
      case 'not_contains':
        return `NOT ${base(`t.name ILIKE ${this.bind(`%${likeEscape(normalizeTagValue(node.values[0]))}%`)} ESCAPE '\\'`)}`;
      case 'starts_with':
        return base(`t.name ILIKE ${this.bind(`${likeEscape(normalizeTagValue(node.values[0]))}%`)} ESCAPE '\\'`);
      case 'ends_with':
        return base(`t.name ILIKE ${this.bind(`%${likeEscape(normalizeTagValue(node.values[0]))}`)} ESCAPE '\\'`);
      case 'equals':
        return base(`t.name = ${this.bind(normalizeTagValue(node.values[0]))}`);
      case 'not_equals':
        return `NOT ${base(`t.name = ${this.bind(normalizeTagValue(node.values[0]))}`)}`;
      case 'in':
        return base(`t.name = ANY(${this.bind(node.values.map(normalizeTagValue))}::text[])`);
      case 'not_in':
        return `NOT ${base(`t.name = ANY(${this.bind(node.values.map(normalizeTagValue))}::text[])`)}`;
      default:
        throw new Error(`Unsupported operator for tag: ${node.operator}`);
    }
  }

  // ---- text: threat_actor (EXISTS over ioc_threat_actors junction) -------
  buildThreatActor(node) {
    const base = (cond) =>
      `EXISTS (SELECT 1 FROM ioc_threat_actors ita ` +
      `JOIN threat_actors ta ON ta.id = ita.threat_actor_id ` +
      `WHERE ita.ioc_id = ${IOC_ALIAS}.id AND ita.ioc_observable_type = ${IOC_ALIAS}.observable_type ` +
      `AND ${cond})`;
    const v = node.values[0];
    switch (node.operator) {
      case 'contains':
        return base(`ta.name ILIKE ${this.bind(`%${likeEscape(v)}%`)} ESCAPE '\\'`);
      case 'not_contains':
        return `NOT ${base(`ta.name ILIKE ${this.bind(`%${likeEscape(v)}%`)} ESCAPE '\\'`)}`;
      case 'starts_with':
        return base(`ta.name ILIKE ${this.bind(`${likeEscape(v)}%`)} ESCAPE '\\'`);
      case 'ends_with':
        return base(`ta.name ILIKE ${this.bind(`%${likeEscape(v)}`)} ESCAPE '\\'`);
      case 'equals':
        return base(`LOWER(ta.name) = ${this.bind(v.toLowerCase())}`);
      case 'not_equals':
        return `NOT ${base(`LOWER(ta.name) = ${this.bind(v.toLowerCase())}`)}`;
      case 'in':
        return base(`LOWER(ta.name) = ANY(${this.bind(node.values.map((x) => x.toLowerCase()))}::text[])`);
      case 'not_in':
        return `NOT ${base(`LOWER(ta.name) = ANY(${this.bind(node.values.map((x) => x.toLowerCase()))}::text[])`)}`;
      default:
        throw new Error(`Unsupported operator for threat_actor: ${node.operator}`);
    }
  }

  // ---- enum: classification (EXISTS over multi table, slug OR label) ----
  buildClassification(node) {
    const base = (cond) =>
      `EXISTS (SELECT 1 FROM ioc_threat_classifications itc ` +
      `LEFT JOIN threat_classifications tc ON tc.slug = itc.classification_slug ` +
      `WHERE itc.ioc_id = ${IOC_ALIAS}.id AND itc.ioc_observable_type = ${IOC_ALIAS}.observable_type ` +
      `AND ${cond})`;
    switch (node.operator) {
      case 'equals': {
        const ph = this.bind(node.values[0].toLowerCase());
        return base(`(itc.classification_slug = ${ph} OR LOWER(tc.name) = ${ph})`);
      }
      case 'not_equals': {
        const ph = this.bind(node.values[0].toLowerCase());
        return `NOT ${base(`(itc.classification_slug = ${ph} OR LOWER(tc.name) = ${ph})`)}`;
      }
      case 'in': {
        const ph = this.bind(node.values.map((v) => v.toLowerCase()));
        return base(`(itc.classification_slug = ANY(${ph}::text[]) OR LOWER(tc.name) = ANY(${ph}::text[]))`);
      }
      case 'not_in': {
        const ph = this.bind(node.values.map((v) => v.toLowerCase()));
        return `NOT ${base(`(itc.classification_slug = ANY(${ph}::text[]) OR LOWER(tc.name) = ANY(${ph}::text[]))`)}`;
      }
      default:
        throw new Error(`Unsupported operator for classification: ${node.operator}`);
    }
  }

  // ---- enum: type/status/confidence (single column) ---------------------
  buildSimpleEnum(node, col, { lower }) {
    const expr = lower ? `LOWER(${col})` : col;
    const val = (v) => (lower ? v.toLowerCase() : v.toLowerCase());
    switch (node.operator) {
      case 'equals':
        return `${expr} = ${this.bind(val(node.values[0]))}`;
      case 'not_equals':
        return `${expr} <> ${this.bind(val(node.values[0]))}`;
      case 'in':
        return `${expr} = ANY(${this.bind(node.values.map(val))}::text[])`;
      case 'not_in':
        return `${expr} <> ALL(${this.bind(node.values.map(val))}::text[])`;
      default:
        throw new Error(`Unsupported operator for enum: ${node.operator}`);
    }
  }

  /**
   * type: when FILE_ARTIFACTS_READ_ENABLED, match canonical displayed type
   * (primary hash type on linked artifact; otherwise raw observable_type).
   * When read is off, keep raw i.observable_type (legacy).
   */
  buildType(node) {
    if (!this.fileArtifactsReadEnabled) {
      return this.buildSimpleEnum(node, `${IOC_ALIAS}.observable_type`, { lower: false });
    }
    return this.buildArtifactHashTypeEnum(node, { primaryOnly: true });
  }

  /**
   * known_hash_type: any known exact hash on the linked artifact (alias/forensic),
   * or raw observable_type when the IOC is not linked.
   */
  buildKnownHashType(node) {
    return this.buildArtifactHashTypeEnum(node, { primaryOnly: false });
  }

  buildArtifactHashTypeEnum(node, { primaryOnly }) {
    const values = (node.values || []).map((v) => String(v).toLowerCase());
    const hashMatch = primaryOnly
      ? `ph.is_primary = TRUE AND ph.hash_type = __PH__`
      : `h.hash_type = __PH__`;
    const hashJoin = primaryOnly
      ? `JOIN file_artifact_hashes ph
           ON ph.artifact_id = ${RESOLVED_ARTIFACT_ID_SQL}
          AND ph.is_primary = TRUE`
      : `JOIN file_artifact_hashes h
           ON h.artifact_id = ${RESOLVED_ARTIFACT_ID_SQL}`;

    const oneValue = (typeValue) => {
      const ph = this.bind(typeValue);
      const matchSql = hashMatch.replace('__PH__', ph);
      return `(
        EXISTS (
          SELECT 1
          FROM file_artifact_ioc_links fal
          JOIN file_artifacts fa ON fa.id = fal.artifact_id
          ${hashJoin}
          WHERE fal.ioc_item_id = ${IOC_ALIAS}.id
            AND fal.ioc_observable_type = ${IOC_ALIAS}.observable_type
            AND ${matchSql}
        )
        OR (
          NOT EXISTS (
            SELECT 1 FROM file_artifact_ioc_links fal2
            WHERE fal2.ioc_item_id = ${IOC_ALIAS}.id
              AND fal2.ioc_observable_type = ${IOC_ALIAS}.observable_type
          )
          AND ${IOC_ALIAS}.observable_type = ${ph}
        )
      )`;
    };

    switch (node.operator) {
      case 'equals':
        return oneValue(values[0]);
      case 'not_equals':
        return `(NOT ${oneValue(values[0])})`;
      case 'in':
        return `(${values.map((v) => oneValue(v)).join(' OR ')})`;
      case 'not_in':
        return `(${values.map((v) => `(NOT ${oneValue(v)})`).join(' AND ')})`;
      default:
        throw new Error(`Unsupported operator for hash type enum: ${node.operator}`);
    }
  }

  // ---- hash: md5 / sha1 / sha256 (exact file-hash identity) --------------
  // Selects the ioc_items rows that match this exact hash two ways, and lets the
  // canonical page/probe SQL (searchPageSql.js) resolve every matched row to its
  // file-artifact identity (SHA256 primary) and dedupe:
  //   1) Direct hash IOC: an ioc_items row of this hash type whose observable equals the
  //      value. observable_type is a whitelisted literal (never user text), so the partial
  //      expression index idx_ioc_items_<type>_lower_observable is usable.
  //   2) Artifact known-hash identity (FA read only): every IOC linked to the file
  //      artifact that owns this exact (hash_type, value), driven from the global-unique
  //      hash index and resolved through any merge tombstone (mirrors read-path semantics).
  //
  // The two identity sources are combined as a single row-wise membership test
  // `(observable_type, id) IN (<direct> UNION <artifact>)`, NOT `direct OR (… IN …)`.
  // The OR form forces Postgres to sequential-scan every ioc_items partition (~3M rows,
  // ~1.9s measured) because it cannot bitmap-combine an indexable predicate with a
  // semi-join. The UNION-of-ids form keeps both branches index-only and the outer
  // membership a keyed lookup on the ioc_items primary key (~2ms measured). id alone is
  // not unique across type partitions, so the key is the full (observable_type, id).
  // Only `equals` reaches here (registry whitelist); the value is already trimmed,
  // lowercased and length/hex-validated by the parser, and is still bound as a parameter.
  buildFileHash(node) {
    const HASH_TYPE_LITERAL = { md5: 'md5', sha1: 'sha1', sha256: 'sha256' };
    const hashType = HASH_TYPE_LITERAL[node.field];
    if (!hashType) {
      throw new Error(`Unsupported hash field in builder: ${node.field}`);
    }
    if (node.operator !== 'equals') {
      throw new Error(`Unsupported operator for ${node.field}: ${node.operator}`);
    }
    const value = String(node.values[0]).trim().toLowerCase();
    const valuePh = this.bind(value);

    const directIoc =
      `(${IOC_ALIAS}.observable_type = '${hashType}' AND LOWER(${IOC_ALIAS}.observable) = ${valuePh})`;

    // Without the file-artifact read/canonical layer there is no artifact identity to
    // resolve to and no dedup, so a direct exact hash IOC is the only sound match. This
    // bare predicate already uses the partial hash index directly (no OR to defeat it).
    if (!this.fileArtifactsReadEnabled) {
      return directIoc;
    }

    return `(${IOC_ALIAS}.observable_type, ${IOC_ALIAS}.id) IN (
      SELECT d.observable_type, d.id
        FROM ioc_items d
       WHERE d.observable_type = '${hashType}' AND LOWER(d.observable) = ${valuePh}
      UNION
      SELECT fal.ioc_observable_type, fal.ioc_item_id
        FROM file_artifact_hashes h
        JOIN file_artifacts hfa ON hfa.id = h.artifact_id
        JOIN file_artifact_ioc_links fal
          ON fal.artifact_id = COALESCE(
               CASE
                 WHEN hfa.status = 'merged' AND hfa.merged_into_artifact_id IS NOT NULL
                   THEN hfa.merged_into_artifact_id
                 ELSE hfa.id
               END,
               hfa.id
             )
       WHERE h.hash_type = '${hashType}' AND h.normalized_hash_value = ${valuePh}
    )`;
  }

  // ---- attr: imphash / tlsh / ssdeep (non-identity file-artifact attribute) --
  // These are NOT IOC identities and never appear as ioc_items rows — they live only on
  // file artifacts (file_artifact_non_identity_attrs). A match selects every IOC linked to
  // the artifact(s) carrying this exact attribute value, resolved through merge tombstones;
  // the canonical page/probe SQL (searchPageSql.js) then resolves each matched IOC to its
  // artifact identity (SHA256 primary) and dedupes. One attribute value can legitimately
  // sit on many artifacts (weak signal), yielding several distinct canonical IOCs — while
  // the same artifact reached more than once collapses to a single result.
  //
  // Same index-friendly row-wise membership as buildFileHash (no `OR`, no per-row EXISTS):
  // a NON-correlated semi-join driven by the (attr_type, attr_value) lookup index, then an
  // ioc_items primary-key membership. attr_type is a whitelisted literal (never user text);
  // the value is validated/normalized by the parser and bound as a parameter.
  //
  // Case-folding per attr type (see normalize.js): imphash/tlsh are hex → compared case-
  // insensitively (parser already lowercased; tlsh also lowers the column via the
  // lower(attr_value) index); ssdeep is base64 → compared case-SENSITIVELY on the raw column.
  buildNonIdentityAttr(node) {
    const ATTR_TYPE_LITERAL = { imphash: 'imphash', tlsh: 'tlsh', ssdeep: 'ssdeep' };
    const attrType = ATTR_TYPE_LITERAL[node.field];
    if (!attrType) {
      throw new Error(`Unsupported attribute field in builder: ${node.field}`);
    }
    if (node.operator !== 'equals') {
      throw new Error(`Unsupported operator for ${node.field}: ${node.operator}`);
    }
    const value = String(node.values[0]);
    const valuePh = this.bind(value);
    // tlsh: case-insensitive hex → LOWER(attr_value) (backed by the (attr_type, lower(attr_value))
    // index; the parser already lowercased the bound value). imphash/ssdeep: compared on the
    // raw column (imphash value pre-lowercased by the parser; ssdeep kept case-exact).
    const valuePred = attrType === 'tlsh'
      ? `LOWER(na.attr_value) = ${valuePh}`
      : `na.attr_value = ${valuePh}`;

    return `(${IOC_ALIAS}.observable_type, ${IOC_ALIAS}.id) IN (
      SELECT fal.ioc_observable_type, fal.ioc_item_id
        FROM file_artifact_non_identity_attrs na
        JOIN file_artifacts nfa ON nfa.id = na.artifact_id
        JOIN file_artifact_ioc_links fal
          ON fal.artifact_id = COALESCE(
               CASE
                 WHEN nfa.status = 'merged' AND nfa.merged_into_artifact_id IS NOT NULL
                   THEN nfa.merged_into_artifact_id
                 ELSE nfa.id
               END,
               nfa.id
             )
       WHERE na.attr_type = '${attrType}' AND ${valuePred}
    )`;
  }

  // ---- date: item-level columns -----------------------------------------
  buildItemDate(node, col) {
    switch (node.operator) {
      case 'after':
        return `${col} > ${this.dateExpr(node.dates[0])}`;
      case 'before':
        return `${col} < ${this.dateExpr(node.dates[0])}`;
      case 'between':
        return `(${col} >= ${this.dateExpr(node.dates[0])} AND ${col} <= ${this.dateExpr(node.dates[1])})`;
      default:
        throw new Error(`Unsupported operator for date: ${node.operator}`);
    }
  }

  // ---- date: first_seen (analyst "First seen in source") ----------------
  // IOC-level value is MIN(first_seen_in_feed) over ioc_feed_memberships, falling back
  // to ioc_items.first_seen_at when the IOC has no feed membership. Identical to the
  // export column so filter and export agree.
  buildFirstSeen(node) {
    const membershipFilter =
      `m.ioc_item_id = ${IOC_ALIAS}.id AND m.ioc_observable_type = ${IOC_ALIAS}.observable_type`;
    const firstSeenExpr =
      `COALESCE((SELECT MIN(m.first_seen_in_feed) FROM ioc_feed_memberships m WHERE ${membershipFilter}), ${IOC_ALIAS}.first_seen_at)`;
    switch (node.operator) {
      case 'after':
        return `${firstSeenExpr} > ${this.dateExpr(node.dates[0])}`;
      case 'before':
        return `${firstSeenExpr} < ${this.dateExpr(node.dates[0])}`;
      case 'between':
        return `(${firstSeenExpr} >= ${this.dateExpr(node.dates[0])} AND ${firstSeenExpr} <= ${this.dateExpr(node.dates[1])})`;
      default:
        throw new Error(`Unsupported operator for first_seen: ${node.operator}`);
    }
  }

  // ---- date: last_changed (per-membership analyst semantic) -------------
  // IOC-level value is MAX(COALESCE(last_changed_in_source, first_seen_in_feed)) over
  // ioc_feed_memberships. last_seen_in_feed (technical presence) is never referenced.
  //   after  -> EXISTS a membership newer than cutoff (equivalent to MAX > cutoff)
  //   before -> IOC-level MAX < cutoff (scalar subquery; no-membership IOCs excluded)
  //   between-> IOC-level MAX within [from, to]
  buildLastChanged(node) {
    const membershipFilter =
      `m.ioc_item_id = ${IOC_ALIAS}.id AND m.ioc_observable_type = ${IOC_ALIAS}.observable_type`;
    const changedExpr = 'COALESCE(m.last_changed_in_source, m.first_seen_in_feed)';
    if (node.operator === 'after') {
      return (
        `EXISTS (SELECT 1 FROM ioc_feed_memberships m WHERE ${membershipFilter} ` +
        `AND ${changedExpr} > ${this.dateExpr(node.dates[0])})`
      );
    }
    const maxSub =
      `(SELECT MAX(${changedExpr}) FROM ioc_feed_memberships m WHERE ${membershipFilter})`;
    if (node.operator === 'before') {
      return `${maxSub} < ${this.dateExpr(node.dates[0])}`;
    }
    if (node.operator === 'between') {
      return `(${maxSub} >= ${this.dateExpr(node.dates[0])} AND ${maxSub} <= ${this.dateExpr(node.dates[1])})`;
    }
    throw new Error(`Unsupported operator for last_changed: ${node.operator}`);
  }
}

// Build the WHERE expression + params for an AST.
// Returns { sql, params }. `sql` is a single boolean expression referencing alias `i`.
export function buildWhereClause(ast, {
  timezone = getSearchTimezone(),
  fileArtifactsReadEnabled = isFileArtifactsReadEnabled()
} = {}) {
  const builder = new Builder(timezone, { fileArtifactsReadEnabled });
  const sql = builder.build(ast);
  return { sql, params: builder.params };
}
