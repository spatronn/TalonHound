-- Canonical last source observation for feed memberships.
--
-- ioc_feed_memberships.last_seen_in_feed is the last source observation/publication
-- time (monotonic MAX). Snapshot unchanged re-imports do not write it (fingerprint
-- guard). Event feeds such as ThreatFox write provider observation time, not import
-- wall-clock.
--
-- last_changed_in_source remains metadata/state change (or reactivation).
-- fixed_ttl expiration uses last_seen_in_feed, falling back to first_seen_in_feed.
--
-- SOURCE ISOLATION (critical):
-- ioc_items.last_seen_at is PER ROW / typically PER source_name — not a global
-- aggregate across sources. Multiple ioc_items may share one observable.
-- This backfill MUST NEVER copy another source's last_seen into a ThreatFox
-- membership (that would extend ThreatFox TTL from OTX/USOM/ET activity).
-- Authoritative sources, in order:
--   1) ThreatFox note last_seen= / first_seen= on a ThreatFox-sourced item
--   2) that ThreatFox-sourced item's own last_seen_at / first_seen_at
-- Memberships anchored on a non-ThreatFox ioc_item are matched by observable to
-- sibling ThreatFox-sourced item(s). If no ThreatFox-scoped observation can be
-- proven, the membership timestamps are left unchanged.

COMMENT ON COLUMN public.ioc_feed_memberships.last_seen_in_feed IS
  'ANALYST-VISIBLE last source observation (MAX). Snapshot unchanged polls must not advance this. Distinct from last_changed_in_source. Source-isolated: never inherit another feed''s observation time.';

COMMENT ON COLUMN public.ioc_feed_memberships.last_changed_in_source IS
  'ANALYST-VISIBLE. Advances only on genuine source content change or reactivation. NULL falls back to first_seen_in_feed as the pre-tracking baseline (initial membership creation).';

WITH threatfox_row_obs AS (
  SELECT
    tf.observable,
    tf.observable_type,
    COALESCE(
      NULLIF(substring(tf.note FROM 'last_seen=([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:\.]+Z?)'), '')::timestamptz,
      NULLIF(substring(tf.note FROM 'first_seen=([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:\.]+Z?)'), '')::timestamptz,
      tf.last_seen_at
    ) AS observed_at,
    COALESCE(
      NULLIF(substring(tf.note FROM 'first_seen=([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:\.]+Z?)'), '')::timestamptz,
      tf.first_seen_at
    ) AS first_observed_at
  FROM ioc_items tf
  WHERE tf.source_name LIKE 'ThreatFox:%'
),
threatfox_obs AS (
  -- MAX/MIN only across ThreatFox-sourced rows for the same observable — never
  -- across USOM/OTX/ET/other sibling ioc_items.
  SELECT
    observable,
    observable_type,
    MAX(observed_at) AS observed_at,
    MIN(first_observed_at) AS first_observed_at
  FROM threatfox_row_obs
  WHERE observed_at IS NOT NULL
  GROUP BY observable, observable_type
)
UPDATE ioc_feed_memberships m
SET first_seen_in_feed = CASE
      WHEN o.first_observed_at IS NULL THEN m.first_seen_in_feed
      ELSE LEAST(m.first_seen_in_feed, o.first_observed_at)
    END,
    last_seen_in_feed = o.observed_at
FROM integration_feeds f
JOIN ioc_items anchor
  ON anchor.id = m.ioc_item_id
 AND anchor.observable_type = m.ioc_observable_type
JOIN threatfox_obs o
  ON o.observable = anchor.observable
 AND o.observable_type = anchor.observable_type
WHERE f.integration_id = m.feed_id
  AND f.key = 'threatfox-abusech'
  AND (
    (o.first_observed_at IS NOT NULL
      AND m.first_seen_in_feed IS DISTINCT FROM LEAST(m.first_seen_in_feed, o.first_observed_at))
    OR m.last_seen_in_feed IS DISTINCT FROM o.observed_at
  );
