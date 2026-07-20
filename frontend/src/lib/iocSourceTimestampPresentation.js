// Analyst-visible source timestamps.
//
// "Last confirmed in source" was removed deliberately. It was backed by
// ioc_feed_memberships.last_seen_in_feed, which advanced on every successful poll even
// when nothing about the IOC changed — so an unchanged re-import looked like new
// analyst-relevant activity. That field is technical presence bookkeeping and must not
// be rendered.
//
// "Last changed in source" is backed by last_changed_in_source, which advances only on
// a genuine source-content change or a reactivation. Rows predating migration 121 fall
// back to first_seen_in_feed as the documented baseline.
//
// The technical "we polled the feed and it was still there" fact belongs at feed/run
// level ("Feed last successful run"), never per IOC.
export const IOC_SOURCE_TIMESTAMP_PRESENTATION = Object.freeze({
  first: Object.freeze({
    label: 'First seen in source',
    tooltip: 'The time TalonHound first observed this IOC in this source.'
  }),
  last: Object.freeze({
    label: 'Last changed in source',
    tooltip: 'The latest time the content TalonHound receives from this source actually changed. Re-importing the same IOC unchanged does not move this date.'
  })
});
