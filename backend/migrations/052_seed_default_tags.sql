INSERT INTO tags (name, type, enabled)
VALUES
  ('ransomware', 'threat', TRUE),
  ('c2', 'threat', TRUE),
  ('phishing', 'threat', TRUE),
  ('apt29', 'actor', TRUE),
  ('clickfix', 'technique', TRUE)
ON CONFLICT (name) DO UPDATE
SET enabled = TRUE;
