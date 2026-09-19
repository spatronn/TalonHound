// Analyst-visible source timestamps.
//
// last_seen_in_feed is the canonical last source observation (MAX). Snapshot feeds do
// not advance it on unchanged re-imports (fingerprint guard), so rendering it as
// "Last seen in source" does not revive poll-churn as analyst activity.
//
// "Last changed in source" is backed by last_changed_in_source, which advances only on
// a genuine source-content change or a reactivation. Rows predating migration 121 fall
// back to first_seen_in_feed as the documented baseline.
//
// IOC-level presence confirmation (summary.last_confirmed_at) remains the same MAX of
// last_seen_in_feed; the detail Overview now also exposes it as last_seen_in_source.
export const IOC_SOURCE_TIMESTAMP_PRESENTATION = Object.freeze({
  first: Object.freeze({
    label: 'First seen in source',
    tooltip: 'Earliest known source observation of this IOC in this source.'
  }),
  imported: Object.freeze({
    label: 'Inserted into Platform',
    tooltip: 'First time this IOC was inserted into TalonHound. This value does not change on re-import.'
  }),
  lastSeen: Object.freeze({
    label: 'Last seen in source',
    tooltip: 'Most recent source observation in this source, even if metadata did not change.'
  }),
  last: Object.freeze({
    label: 'Last changed in source',
    tooltip: 'Last time the IOC data meaningfully changed in this source.'
  })
});
