/**
 * Historical IOC observable-type integrity.
 *
 * The pre-networkObservable create path (`inferObservableType`) stored an
 * IPv6 address as `domain` and a CIDR as `url`, ignoring the type the caller
 * had already validated. `resolveIocStorageIdentity` is the creation path now.
 * This module classifies rows already stored, and repairs only the proven
 * Threat Library case: an IPv6 value persisted as `domain` by that inference,
 * corroborated by the candidate that created it.
 *
 * A repair keeps the IOC id and public_id. It moves the row between list
 * partitions (PostgreSQL implements that as delete + insert, which records a
 * published-feed tombstone for the old type) and rewrites the denormalized
 * type copies that point at the same id.
 */
import { parseNetworkObservable } from './networkObservable.js';
import { IOC_SOURCE_NAME } from './threatLibrary/constants.js';

export const THREAT_LIBRARY_NOTE_RE =
  /^Threat Library report ([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}): [a-z_]+ \((malicious|suspicious)\)$/;

/**
 * Strict network mismatch. Confirmed only when the value is a valid host or
 * CIDR and the stored type is a different type. Same-type formatting drift is
 * reported and not rewritten. Ordinary domains and URLs return null.
 * @param {{ observable_type?: string, observable?: string }} row
 */
export function classifyStoredNetworkRow(row) {
  const storedType = String(row?.observable_type || '');
  const raw = String(row?.observable || '');
  const parsed = parseNetworkObservable(raw);
  if (!parsed || parsed.ok !== true) return null;
  if (parsed.type === storedType && parsed.value === raw) return null;
  if (parsed.type === storedType) {
    return {
      defect: `${parsed.type}_${parsed.kind}_noncanonical`,
      expected_type: parsed.type,
      canonical: parsed.value,
      kind: parsed.kind,
      confirmed: false,
      reason: 'same_type_noncanonical_form'
    };
  }
  return {
    defect: `${parsed.type}_${parsed.kind}_as_${storedType}`,
    expected_type: parsed.type,
    canonical: parsed.value,
    kind: parsed.kind,
    confirmed: true,
    reason: 'strict_network_validator'
  };
}

/**
 * Whether one confirmed mismatch is the Threat Library IPv6-as-domain defect
 * and can be retyped in place. Everything else is left untouched.
 * @param {object} row joined IOC + creating candidate
 * @param {{ collision?: boolean }} [context]
 */
export function planHistoricalTypeRepair(row, context = {}) {
  const cls = classifyStoredNetworkRow(row);
  if (!cls) return { action: 'unchanged', change: false };
  if (!cls.confirmed) {
    return { action: 'unchanged', change: false, defect: cls.defect, reason: cls.reason };
  }
  const note = String(row?.note || '');
  const noteMatch = THREAT_LIBRARY_NOTE_RE.exec(note);
  const reportPublicId = noteMatch ? noteMatch[1] : null;
  const eligible = cls.expected_type === 'ipv6'
    && String(row?.observable_type) === 'domain'
    && String(row?.source_name) === IOC_SOURCE_NAME
    && String(row?.created_origin) === 'manual_add'
    && reportPublicId
    && String(row?.report_public_id || '') === reportPublicId
    && String(row?.candidate_type) === 'ipv6'
    && String(row?.review_status) === 'approved'
    && String(row?.normalized_value || '') === String(row?.observable || '')
    && String(row?.matched_ioc_observable_type || '') === 'domain'
    && row?.matched_ioc_id != null
    && Number(row.matched_ioc_id) === Number(row.id);
  if (!eligible) {
    return {
      action: 'out_of_scope',
      change: false,
      defect: cls.defect,
      expected_type: cls.expected_type,
      canonical: cls.canonical,
      reason: 'not_threat_library_ipv6_inference'
    };
  }
  if (context.collision) {
    return {
      action: 'blocked',
      change: false,
      defect: cls.defect,
      expected_type: cls.expected_type,
      canonical: cls.canonical,
      reason: 'correct_ipv6_identity_already_exists'
    };
  }
  return {
    action: 'retype',
    change: true,
    defect: cls.defect,
    expected_type: cls.expected_type,
    canonical: cls.canonical,
    kind: cls.kind,
    reason: 'threat_library_ipv6_inferred_as_domain'
  };
}

function asPlans(plans) {
  const list = Array.isArray(plans) ? plans : [];
  if (!list.length) throw new Error('No repair plans');
  for (const plan of list) {
    if (plan?.action !== 'retype' || plan.expected_type !== 'ipv6' || !plan.canonical) {
      throw new Error(`Refusing plan ${plan?.id}: ${plan?.action || 'missing'}`);
    }
  }
  return list;
}

/**
 * Move eligible domain rows onto the ipv6 partition. Caller owns the transaction.
 * Preserves id and public_id. Does not change review_status, assessment, or
 * matched_ioc_id.
 */
export async function retypeThreatLibraryIpv6(client, plans, snapshot) {
  const list = asPlans(plans);
  const ids = list.map((p) => Number(p.id));
  const observables = list.map((p) => String(p.observable));
  const canonicals = list.map((p) => String(p.canonical));
  const publicIds = list.map((p) => String(p.public_id));

  const locked = await client.query(
    `SELECT id, observable_type, observable, public_id::text AS public_id
     FROM ioc_items
     WHERE id = ANY($1::bigint[])
     FOR UPDATE`,
    [ids]
  );
  if (locked.rows.length !== list.length) {
    throw new Error(`Locked ${locked.rows.length} IOC rows, expected ${list.length}`);
  }
  const lockedById = new Map(locked.rows.map((r) => [Number(r.id), r]));
  for (const plan of list) {
    const row = lockedById.get(Number(plan.id));
    if (!row || row.observable_type !== 'domain' || row.observable !== plan.observable || row.public_id !== plan.public_id) {
      throw new Error(`IOC ${plan.id} changed before repair`);
    }
  }

  const collision = await client.query(
    `SELECT id, observable FROM ioc_items
     WHERE observable_type = 'ipv6' AND observable = ANY($1::text[])`,
    [canonicals]
  );
  if (collision.rows.length) {
    throw new Error(`Correct ipv6 identity already exists for ${collision.rows.map((r) => r.observable).join(', ')}`);
  }

  const projection = Array.isArray(snapshot?.published_feed_items) ? snapshot.published_feed_items : [];
  const removed = await client.query(
    `DELETE FROM published_feed_items p
     USING unnest($1::bigint[], $2::text[], $3::text[]) AS u(feed_id, snapshot_window, identity_key)
     WHERE p.feed_id = u.feed_id
       AND p.snapshot_window = u.snapshot_window
       AND p.identity_key = u.identity_key
       AND p.observable_type = 'domain'
       AND p.ioc_item_id = ANY($4::bigint[])`,
    [
      projection.map((r) => Number(r.feed_id)),
      projection.map((r) => r.snapshot_window),
      projection.map((r) => r.identity_key),
      ids
    ]
  );
  if (Number(removed.rowCount) !== projection.length) {
    throw new Error(`Removed ${removed.rowCount} projection rows, expected ${projection.length}`);
  }

  const observablesUpdated = await client.query(
    `UPDATE ioc_observables o
     SET observable_type = 'ipv6', observable_value = lower(u.canonical)
     FROM unnest($1::uuid[], $2::text[]) AS u(public_id, canonical)
     WHERE o.ioc_public_id = u.public_id
       AND o.observable_type = 'domain'
       AND o.observable_value = lower(u.canonical)
     RETURNING o.ioc_public_id`,
    [publicIds, canonicals]
  );
  if (observablesUpdated.rows.length !== list.length) {
    throw new Error(`Updated ${observablesUpdated.rows.length} observable index rows, expected ${list.length}`);
  }

  const candidates = await client.query(
    `UPDATE threat_report_candidates c
     SET matched_ioc_observable_type = 'ipv6'
     FROM unnest($1::bigint[], $2::text[]) AS u(id, canonical)
     WHERE c.matched_ioc_id = u.id
       AND c.matched_ioc_observable_type = 'domain'
       AND c.candidate_type = 'ipv6'
       AND c.normalized_value = u.canonical
       AND c.review_status = 'approved'
     RETURNING c.id, c.matched_ioc_id, c.review_status, c.assessment, c.promotion_outcome`,
    [ids, canonicals]
  );
  if (candidates.rows.length !== list.length) {
    throw new Error(`Updated ${candidates.rows.length} candidate links, expected ${list.length}`);
  }

  const moved = await client.query(
    `UPDATE ioc_items i
     SET observable_type = 'ipv6', observable = u.canonical
     FROM unnest($1::bigint[], $2::text[], $3::text[], $4::uuid[]) AS u(id, old_observable, canonical, public_id)
     WHERE i.id = u.id
       AND i.observable_type = 'domain'
       AND i.observable = u.old_observable
       AND i.public_id = u.public_id
     RETURNING i.id, i.observable_type, i.observable, i.public_id::text AS public_id`,
    [ids, observables, canonicals, publicIds]
  );
  if (moved.rows.length !== list.length) {
    throw new Error(`Moved ${moved.rows.length} IOC rows, expected ${list.length}`);
  }
  for (const row of moved.rows) {
    const plan = list.find((p) => Number(p.id) === Number(row.id));
    if (row.observable_type !== 'ipv6' || row.observable !== plan.canonical || row.public_id !== plan.public_id) {
      throw new Error(`IOC ${row.id} did not keep its identity`);
    }
  }
  return {
    retyped: moved.rows.length,
    candidate_links: candidates.rows.length,
    observable_index: observablesUpdated.rows.length,
    projection_rows_removed: Number(removed.rowCount)
  };
}

/**
 * Reverse a repair from the snapshot captured before it. Caller owns the transaction.
 * Restores type, candidate link type, observable index, and projection rows.
 * Review columns are not in the snapshot write path.
 */
export async function restoreIocTypeSnapshot(client, snapshot) {
  const items = snapshot?.ioc_items || [];
  if (!items.length) throw new Error('Snapshot has no IOC rows');
  const ids = items.map((r) => Number(r.id));
  const restored = await client.query(
    `UPDATE ioc_items i
     SET observable_type = u.observable_type, observable = u.observable
     FROM unnest($1::bigint[], $2::text[], $3::text[], $4::uuid[]) AS u(id, observable_type, observable, public_id)
     WHERE i.id = u.id
       AND i.public_id = u.public_id
       AND i.observable_type = 'ipv6'
     RETURNING i.id`,
    [
      ids,
      items.map((r) => r.observable_type),
      items.map((r) => r.observable),
      items.map((r) => r.public_id)
    ]
  );
  if (restored.rows.length !== items.length) {
    throw new Error(`Restored ${restored.rows.length} IOC rows, expected ${items.length}`);
  }

  const candidates = snapshot.candidates || [];
  if (candidates.length) {
    const candidateRestored = await client.query(
      `UPDATE threat_report_candidates c
       SET matched_ioc_observable_type = u.matched_ioc_observable_type
       FROM unnest($1::bigint[], $2::text[], $3::bigint[]) AS u(id, matched_ioc_observable_type, matched_ioc_id)
       WHERE c.id = u.id
         AND c.matched_ioc_id = u.matched_ioc_id
       RETURNING c.id`,
      [
        candidates.map((r) => Number(r.id)),
        candidates.map((r) => r.matched_ioc_observable_type),
        candidates.map((r) => Number(r.matched_ioc_id))
      ]
    );
    if (candidateRestored.rows.length !== candidates.length) {
      throw new Error(`Restored ${candidateRestored.rows.length} candidates, expected ${candidates.length}`);
    }
  }

  const observables = snapshot.observables || [];
  if (observables.length) {
    const observableRestored = await client.query(
      `UPDATE ioc_observables o
       SET observable_type = u.observable_type, observable_value = u.observable_value
       FROM unnest($1::uuid[], $2::text[], $3::text[]) AS u(public_id, observable_type, observable_value)
       WHERE o.ioc_public_id = u.public_id
         AND o.observable_value = u.observable_value
       RETURNING o.id`,
      [
        observables.map((r) => r.ioc_public_id),
        observables.map((r) => r.observable_type),
        observables.map((r) => r.observable_value)
      ]
    );
    if (observableRestored.rows.length !== observables.length) {
      throw new Error(`Restored ${observableRestored.rows.length} observable index rows, expected ${observables.length}`);
    }
  }

  const projection = snapshot.published_feed_items || [];
  for (const row of projection) {
    await client.query(
      `INSERT INTO published_feed_items (
         feed_id, snapshot_window, identity_key, ioc_item_id, observable, observable_type,
         recency_ts, confidence, category, confidence_rank, txt_value, item_json,
         content_fingerprint, partition_identity, chunk_key, reconciliation_bucket
       ) VALUES (
         $1, $2, $3, $4, $5, $6,
         $7, $8, $9, $10, $11, $12::jsonb,
         $13, $14, $15, $16
       )
       ON CONFLICT (feed_id, snapshot_window, identity_key) DO NOTHING`,
      [
        row.feed_id,
        row.snapshot_window,
        row.identity_key,
        row.ioc_item_id,
        row.observable,
        row.observable_type,
        row.recency_ts,
        row.confidence,
        row.category,
        row.confidence_rank,
        row.txt_value,
        row.item_json == null ? null : JSON.stringify(row.item_json),
        row.content_fingerprint,
        row.partition_identity,
        row.chunk_key,
        row.reconciliation_bucket
      ]
    );
  }
  return { restored: restored.rows.length, projection_rows: projection.length };
}
