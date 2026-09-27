-- 032_published_feed_failure_backoff.sql
--
-- Failure streak for Published Feed generation.
--
-- `last_error` holds only the latest failure, so a feed that keeps failing loses the
-- error that started the streak (it was later overwritten by secondary errors such as
-- disk exhaustion). The streak columns keep that first error and when it began, and
-- `consecutive_failures` lets the scheduler back off a feed that keeps failing instead of
-- retrying it at its normal refresh cadence indefinitely. All three reset on the next
-- successful (or unchanged) generation. A manual Regenerate is never delayed by backoff.
--
-- Additive only: constant-default / nullable columns, no rewrite of existing rows.

ALTER TABLE published_feeds
  ADD COLUMN IF NOT EXISTS consecutive_failures integer NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS failing_since timestamptz,
  ADD COLUMN IF NOT EXISTS first_failure_error text;

COMMENT ON COLUMN published_feeds.consecutive_failures IS
  'Scheduled/forced generations that failed in a row; 0 after any success. Drives scheduler backoff.';
COMMENT ON COLUMN published_feeds.failing_since IS
  'Completion time of the first failure in the current failure streak; NULL when healthy.';
COMMENT ON COLUMN published_feeds.first_failure_error IS
  'Error of the first failure in the current streak (bounded); NULL when healthy.';
