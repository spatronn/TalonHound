// Analyst-visible source timestamps.
//
// "Last confirmed in source" was removed deliberately from the sources table. It was
// backed by ioc_feed_memberships.last_seen_in_feed, which advanced on every successful
// poll even when nothing about the IOC changed — so an unchanged re-import looked like
// new analyst-relevant activity. That field is technical presence bookkeeping and must
// not be rendered as a per-source analyst column.
//
// "Last changed in source" is backed by last_changed_in_source, which advances only on
// a genuine source-content change or a reactivation. Rows predating migration 121 fall
// back to first_seen_in_feed as the documented baseline.
//
// IOC-level presence confirmation belongs on the dedicated "Last confirmed / Last seen"
// timestamp card (summary.last_confirmed_at), never as a sources-table column.
export const IOC_SOURCE_TIMESTAMP_PRESENTATION = Object.freeze({
  first: Object.freeze({
    label: 'First seen in source',
    tooltip: 'First time this IOC was observed in this source.'
  }),
  imported: Object.freeze({
    label: 'Inserted into Platform',
    tooltip: 'First time this IOC was inserted into TalonHound. This value does not change on re-import.'
  }),
  last: Object.freeze({
    label: 'Last changed in source',
    tooltip: 'Last time the IOC data meaningfully changed in this source.'
  })
});
