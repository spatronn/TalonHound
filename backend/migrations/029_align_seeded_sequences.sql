-- 029_align_seeded_sequences.sql
--
-- Repair sequences left behind by the released public baseline.
--
-- The released 001_core.sql seeded explicit ids into ioc_sources, tags,
-- threat_feed_expiration_policies and threat_intel_provider_configs but did not
-- restore their sequences (scripts/baseline/build-001-core.sh stripped the
-- SELECT pg_catalog.setval(...) lines pg_dump emits). An installation built from
-- that baseline hands out already-used ids: 019 fails on a fresh database, and
-- installs that got past 019 by re-running migrations still fail their first
-- default-id inserts into the other seeded tables (e.g. tags_pkey).
--
-- For each sequence: advance it ONLY when the next value it would return
-- (last_value + 1 when is_called, otherwise last_value) is <= MAX(id). It is then
-- set so the next value is MAX(id) + 1. A sequence already ahead of its table is
-- left untouched, so this never moves a sequence backwards and is a no-op on
-- correctly maintained databases (including production). Safe to re-run.

SELECT pg_catalog.setval('public.ioc_sources_id_seq', m.max_id, true)
FROM (SELECT max(id) AS max_id FROM public.ioc_sources) m, public.ioc_sources_id_seq s
WHERE m.max_id IS NOT NULL
  AND m.max_id >= CASE WHEN s.is_called THEN s.last_value + 1 ELSE s.last_value END;

SELECT pg_catalog.setval('public.tags_id_seq', m.max_id, true)
FROM (SELECT max(id) AS max_id FROM public.tags) m, public.tags_id_seq s
WHERE m.max_id IS NOT NULL
  AND m.max_id >= CASE WHEN s.is_called THEN s.last_value + 1 ELSE s.last_value END;

SELECT pg_catalog.setval('public.threat_feed_expiration_policies_id_seq', m.max_id, true)
FROM (SELECT max(id) AS max_id FROM public.threat_feed_expiration_policies) m, public.threat_feed_expiration_policies_id_seq s
WHERE m.max_id IS NOT NULL
  AND m.max_id >= CASE WHEN s.is_called THEN s.last_value + 1 ELSE s.last_value END;

SELECT pg_catalog.setval('public.threat_intel_provider_configs_id_seq', m.max_id, true)
FROM (SELECT max(id) AS max_id FROM public.threat_intel_provider_configs) m, public.threat_intel_provider_configs_id_seq s
WHERE m.max_id IS NOT NULL
  AND m.max_id >= CASE WHEN s.is_called THEN s.last_value + 1 ELSE s.last_value END;
