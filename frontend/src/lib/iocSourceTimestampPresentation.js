// Analyst-visible source timestamps.
//
// last_seen_in_feed is the canonical last source observation (MAX). Snapshot feeds do
// not advance it on unchanged re-imports (fingerprint guard), so rendering it as
// "Last seen in source" does not revive poll-churn as analyst activity.
//
// last_changed_in_source remains on the API / DSL / export backend for compatibility
// but is no longer a normal analyst-facing lifecycle label in the UI.
//
// IOC-level presence confirmation (summary.last_confirmed_at) remains the same MAX of
// last_seen_in_feed; the detail Overview exposes it as last_seen_in_source.
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
  })
});
