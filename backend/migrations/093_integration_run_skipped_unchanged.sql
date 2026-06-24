-- Allow integration runs to record unchanged URLHaus (and future) export skips.

ALTER TABLE integration_runs DROP CONSTRAINT IF EXISTS integration_runs_status_check;
ALTER TABLE integration_runs
  ADD CONSTRAINT integration_runs_status_check
  CHECK (status IN ('running', 'success', 'failed', 'skipped_unchanged'));
