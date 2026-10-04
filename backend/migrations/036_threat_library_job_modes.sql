-- 036_threat_library_job_modes.sql
--
-- Threat Library job modes (lib/threatLibrary/jobModes.js): a deterministic
-- "Refresh extraction" job and an explicit "Re-run AI analysis" job join the
-- existing analyze / retry / thib_import types, so an operator can tell from
-- threat_library_jobs.job_type (and the analysis audit event that copies it)
-- whether a report was retried after a failure, refreshed without AI, or
-- deliberately re-analysed by the model.
--
-- Constraint-only change: no data is rewritten and existing rows already
-- satisfy the widened check.

ALTER TABLE public.threat_library_jobs
  DROP CONSTRAINT IF EXISTS threat_library_jobs_job_type_check;

ALTER TABLE public.threat_library_jobs
  ADD CONSTRAINT threat_library_jobs_job_type_check
  CHECK (job_type = ANY (ARRAY[
    'analyze'::text,
    'thib_import'::text,
    'retry'::text,
    'refresh_extraction'::text,
    'rerun_ai'::text
  ]));
