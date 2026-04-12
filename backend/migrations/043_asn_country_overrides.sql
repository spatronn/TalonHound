CREATE TABLE IF NOT EXISTS asn_country_overrides (
  asn BIGINT PRIMARY KEY,
  country_code TEXT NOT NULL,
  note TEXT,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO asn_country_overrides (asn, country_code, note)
VALUES (9121, 'TR', 'Manual override for known ASN country gap in source feed')
ON CONFLICT (asn) DO UPDATE SET
  country_code = EXCLUDED.country_code,
  note = EXCLUDED.note,
  updated_at = NOW();
