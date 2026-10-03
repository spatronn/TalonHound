-- 035_ioc_feed_evidence_classification_index.sql
--
-- Indexable feed classification proposals for the IOC Search DSL.
--
-- The canonical effective IOC classification (backend/lib/iocCanonicalClassifications.js)
-- includes classifications that source feeds propose through the controlled feed
-- vocabulary (backend/lib/feedTagNormalization.js: evidence category, note
-- `tags=` tokens, note `signature=`). They live in free-text columns of
-- ioc_feed_source_evidence, so the DSL `classification` filter could only find
-- them by evaluating the vocabulary over every evidence row (~6 s on production,
-- 925k rows). This function is that vocabulary as an IMMUTABLE expression, and
-- the partial GIN index makes `slugs && ARRAY[...]` an index lookup.
--
-- The VALUES lists are generated from feedClassificationVocabulary(); the
-- migrationFiles test fails when the JS vocabulary and the newest definition of
-- this function differ (a vocabulary change needs a new migration that
-- re-creates the function and rebuilds the index). Mirrors parseNoteFields /
-- normalizeFeedTags: LAST `key=` segment of the ' | '-delimited note wins; tag
-- tokens are trimmed, lowercased and space/hyphen/underscore runs folded to '_'.
--
-- Additive only: no table or data change.

CREATE OR REPLACE FUNCTION public.ioc_feed_evidence_classification_slugs(p_category text, p_note text)
RETURNS text[]
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
AS $fn$
  SELECT COALESCE(array_agg(DISTINCT z.slug ORDER BY z.slug), ARRAY[]::text[])
  FROM (
    SELECT v.slug
      FROM (VALUES
        ('malware', 'malware'), ('botnet_cc', 'command_and_control'), ('botnet_cc_url', 'command_and_control'), ('phishing', 'phishing'),
        ('ransomware', 'ransomware'), ('spam', 'spam_abuse')
      ) AS v(k, slug)
     WHERE v.k = lower(p_category)
    UNION ALL
    SELECT v.slug
      FROM (VALUES
        ('malware_download', 'dropper_downloader'), ('malware_delivery', 'dropper_downloader'), ('dropper_downloader', 'dropper_downloader'), ('phishing', 'phishing'),
        ('botnet', 'botnet'), ('c2', 'command_and_control'), ('cc', 'command_and_control'), ('cnc', 'command_and_control'),
        ('command_and_control', 'command_and_control'), ('spam', 'spam_abuse'), ('ransomware', 'ransomware'), ('exploit', 'exploit'),
        ('trojan', 'malware'), ('rat', 'malware'), ('remote_access_trojan', 'malware'), ('stealer', 'credential_theft'),
        ('infostealer', 'credential_theft'), ('dropper', 'dropper_downloader'), ('loader', 'dropper_downloader'), ('cryptominer', 'cryptomining'),
        ('miner', 'cryptomining')
      ) AS v(k, slug),
      unnest(string_to_array((SELECT btrim(substr(seg.v, strpos(seg.v, '=') + 1))
                 FROM unnest(string_to_array(p_note, ' | ')) WITH ORDINALITY AS seg(v, n)
                WHERE strpos(seg.v, '=') > 1 AND btrim(left(seg.v, strpos(seg.v, '=') - 1)) = 'tags'
                ORDER BY seg.n DESC LIMIT 1), ',')) AS tok(t)
     WHERE v.k = regexp_replace(lower(btrim(tok.t)), '[[:space:]_-]+', '_', 'g')
    UNION ALL
    SELECT v.slug
      FROM (VALUES
        ('mirai', 'botnet'), ('gafgyt', 'botnet'), ('bashlite', 'botnet'), ('mozi', 'botnet'),
        ('tsunami', 'botnet'), ('hajime', 'botnet'), ('iotreaper', 'botnet'), ('iot_reaper', 'botnet'),
        ('darknexus', 'botnet'), ('dark_nexus', 'botnet'), ('satori', 'botnet'), ('brickerbot', 'botnet'),
        ('torii', 'botnet'), ('kaiten', 'botnet'), ('demonbot', 'botnet'), ('wicked', 'botnet'),
        ('gcleaner', 'botnet'), ('ircbot', 'botnet'), ('botnet', 'botnet'), ('wannacry', 'ransomware'),
        ('wannacrypt', 'ransomware'), ('ryuk', 'ransomware'), ('revil', 'ransomware'), ('sodinokibi', 'ransomware'),
        ('darkside', 'ransomware'), ('lockbit', 'ransomware'), ('conti', 'ransomware'), ('blackcat', 'ransomware'),
        ('alphv', 'ransomware'), ('hive', 'ransomware'), ('clop', 'ransomware'), ('cl0p', 'ransomware'),
        ('maze', 'ransomware'), ('ragnarlocker', 'ransomware'), ('ragnar_locker', 'ransomware'), ('netwalker', 'ransomware'),
        ('dharma', 'ransomware'), ('phobos', 'ransomware'), ('makop', 'ransomware'), ('stop', 'ransomware'),
        ('djvu', 'ransomware')
      ) AS v(k, slug)
     WHERE v.k = lower(btrim((SELECT btrim(substr(seg.v, strpos(seg.v, '=') + 1))
                 FROM unnest(string_to_array(p_note, ' | ')) WITH ORDINALITY AS seg(v, n)
                WHERE strpos(seg.v, '=') > 1 AND btrim(left(seg.v, strpos(seg.v, '=') - 1)) = 'signature'
                ORDER BY seg.n DESC LIMIT 1)))
  ) AS z
$fn$;

CREATE INDEX IF NOT EXISTS idx_ioc_feed_source_evidence_classification_slugs
    ON public.ioc_feed_source_evidence
 USING gin (public.ioc_feed_evidence_classification_slugs(category, note))
 WHERE public.ioc_feed_evidence_classification_slugs(category, note) <> ARRAY[]::text[];

ANALYZE public.ioc_feed_source_evidence;
