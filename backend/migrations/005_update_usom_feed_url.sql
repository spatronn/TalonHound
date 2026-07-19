UPDATE integration_feeds
SET source_url = 'https://siberguvenlik.gov.tr/api/address/index',
    updated_at = NOW()
WHERE key = 'usom-trcert';
