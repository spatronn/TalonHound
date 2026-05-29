-- URLhaus/MalwareBazaar import recent.csv (incremental deltas), not full snapshots.
UPDATE integration_feeds
SET feed_update_mode = 'incremental'
WHERE key IN ('urlhaus-abusech', 'malwarebazaar-abusech');

-- Allow queue jobs to record intentional skips (same_hash, min_interval, lock_not_acquired).
ALTER TABLE integration_queue_jobs
  DROP CONSTRAINT IF EXISTS integration_queue_jobs_status_check;

ALTER TABLE integration_queue_jobs
  ADD CONSTRAINT integration_queue_jobs_status_check
  CHECK (status IN ('queued', 'running', 'success', 'failed', 'skipped'));
