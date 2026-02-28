UPDATE integration_feeds
SET source_url = 'https://www.usom.gov.tr/url-list.txt',
    updated_at = NOW()
WHERE key = 'usom-trcert';
