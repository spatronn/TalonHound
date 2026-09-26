-- 031_threat_report_import_identity.sql
--
-- Import identity for Threat Library URL / PDF deduplication.
--
-- URL reports: `source_url_canonical` is the conservative canonical form of the
-- URL as submitted for import (lib/threatLibrary/importIdentity.js). It is set
-- once at import and never edited; `source_url` remains the analyst-editable
-- provenance value. Historical URL rows are filled by the idempotent JS
-- backfill migrate.js runs after SQL migrations (same canonicalizer), which
-- writes only this new column.
--
-- PDF reports: the identity is the existing `source_sha256` (SHA-256 of the
-- original uploaded bytes, written by every PDF import). No new hash column.
--
-- No UNIQUE constraint: historical duplicates may exist and are reported, not
-- merged or deleted. Concurrent imports serialise on a transaction-scoped
-- advisory lock on the identity instead. The partial indexes below keep the
-- per-import duplicate lookup off a full table scan.
--
-- Additive only: nullable column + indexes, no rewrite of existing data.

ALTER TABLE public.threat_reports
    ADD COLUMN IF NOT EXISTS source_url_canonical text;

COMMENT ON COLUMN public.threat_reports.source_url_canonical IS
    'Canonical URL import identity (URL reports only); set at import, never edited. source_url is the editable provenance value.';

CREATE INDEX IF NOT EXISTS idx_threat_reports_url_import_identity
    ON public.threat_reports (source_url_canonical)
    WHERE source_type = 'url' AND deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_threat_reports_pdf_import_identity
    ON public.threat_reports (source_sha256)
    WHERE source_type = 'pdf' AND deleted_at IS NULL;
