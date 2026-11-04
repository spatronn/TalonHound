-- 054_threat_report_finalize_exceptions.sql
--
-- An administrator's reasoned exception to a finalize obligation of a newly
-- imported report. Append-only. Reports without a first-pass extraction run predate
-- the obligations and are not affected.

CREATE TABLE IF NOT EXISTS public.threat_report_finalize_exceptions (
    id bigserial PRIMARY KEY,
    report_id bigint NOT NULL REFERENCES public.threat_reports(id) ON DELETE CASCADE,
    obligation_code text NOT NULL,
    reason text NOT NULL CHECK (length(btrim(reason)) >= 12),
    detail jsonb NOT NULL DEFAULT '{}'::jsonb,
    actor_public_id uuid,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_threat_report_finalize_exceptions_report
  ON public.threat_report_finalize_exceptions (report_id, id DESC);

COMMENT ON TABLE public.threat_report_finalize_exceptions IS
  'Reasoned administrator exceptions to finalize obligations. Append-only; the matching audit row commits with it.';

DROP TRIGGER IF EXISTS threat_report_finalize_exceptions_immutable ON public.threat_report_finalize_exceptions;
CREATE TRIGGER threat_report_finalize_exceptions_immutable
    BEFORE UPDATE OR DELETE ON public.threat_report_finalize_exceptions
    FOR EACH ROW EXECUTE FUNCTION public.threat_library_reject_ledger_mutation();
