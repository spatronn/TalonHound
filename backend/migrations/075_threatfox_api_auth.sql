-- ThreatFox now uses Auth-Key API (get_iocs) instead of public full CSV export.
UPDATE integration_feeds
SET source_url = 'https://threatfox-api.abuse.ch/api/v1/',
    feed_update_mode = 'incremental',
    updated_at = NOW()
WHERE key = 'threatfox-abusech';
