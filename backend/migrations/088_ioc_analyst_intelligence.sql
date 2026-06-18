-- Analyst-added intelligence references for IOCs (OSINT, vendor reports, social posts, etc.)
SET LOCAL statement_timeout = 0;
SET LOCAL lock_timeout = '120s';

CREATE TABLE IF NOT EXISTS ioc_analyst_intelligence (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  ioc_id BIGINT NOT NULL,
  ioc_observable_type TEXT NOT NULL,
  title TEXT NOT NULL,
  url TEXT NULL,
  source_name TEXT NULL,
  reference_type TEXT NOT NULL DEFAULT 'other',
  tlp TEXT NOT NULL DEFAULT 'clear',
  confidence TEXT NOT NULL DEFAULT 'unknown',
  assessment_impact TEXT NOT NULL DEFAULT 'context_only',
  note TEXT NULL,
  created_by UUID NULL,
  created_by_username TEXT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_by UUID NULL,
  updated_by_username TEXT NULL,
  updated_at TIMESTAMPTZ NULL,
  deleted_by UUID NULL,
  deleted_by_username TEXT NULL,
  deleted_at TIMESTAMPTZ NULL,
  CONSTRAINT fk_ioc_analyst_intelligence_ioc
    FOREIGN KEY (ioc_observable_type, ioc_id)
    REFERENCES ioc_items(observable_type, id)
    ON DELETE CASCADE,
  CONSTRAINT ioc_analyst_intelligence_title_len_chk
    CHECK (char_length(title) >= 1 AND char_length(title) <= 200),
  CONSTRAINT ioc_analyst_intelligence_source_name_len_chk
    CHECK (source_name IS NULL OR char_length(source_name) <= 120),
  CONSTRAINT ioc_analyst_intelligence_note_len_chk
    CHECK (note IS NULL OR char_length(note) <= 4000),
  CONSTRAINT ioc_analyst_intelligence_reference_type_chk
    CHECK (reference_type IN ('social', 'free_ti', 'vendor_report', 'sandbox', 'blog', 'internal_note', 'other')),
  CONSTRAINT ioc_analyst_intelligence_tlp_chk
    CHECK (tlp IN ('clear', 'green', 'amber', 'red')),
  CONSTRAINT ioc_analyst_intelligence_confidence_chk
    CHECK (confidence IN ('unknown', 'low', 'medium', 'high')),
  CONSTRAINT ioc_analyst_intelligence_assessment_impact_chk
    CHECK (assessment_impact IN ('supports_malicious', 'supports_benign', 'context_only', 'needs_review'))
);

CREATE INDEX IF NOT EXISTS idx_ioc_analyst_intelligence_ioc_active
  ON ioc_analyst_intelligence (ioc_id, ioc_observable_type)
  WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_ioc_analyst_intelligence_impact_active
  ON ioc_analyst_intelligence (assessment_impact)
  WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_ioc_analyst_intelligence_created_at_active
  ON ioc_analyst_intelligence (created_at DESC)
  WHERE deleted_at IS NULL;
