CREATE TABLE IF NOT EXISTS risk_snapshots (
  id BIGSERIAL PRIMARY KEY,
  ts TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  institution_risk NUMERIC(6,2) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_risk_snapshots_ts_desc
  ON risk_snapshots (ts DESC);
