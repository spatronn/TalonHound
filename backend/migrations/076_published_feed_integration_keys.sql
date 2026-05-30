-- Published feeds: select IOC sources by integration feed key (Feeds page).

ALTER TABLE published_feeds
  ADD COLUMN IF NOT EXISTS include_feed_keys JSONB;
