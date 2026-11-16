-- 057_email_ioc_observable_type.sql
--
-- First-class `email` IOC observable type.
--
-- 1) ioc_observables.observable_type admits 'email' (constraint name from
--    001_core: chk_observable_type). Added NOT VALID then validated, so the
--    existing rows are checked without holding a write lock for the scan.
-- 2) published_feeds.ioc_type / ioc_types admit 'email' (a Published Feed may
--    publish email IOCs; at most five categories now).
--
-- ioc_items needs no change: it is LIST-partitioned by observable_type and an
-- `email` row lands in the DEFAULT partition ioc_items_other, which carries
-- every index of the partitioned parent. No existing row changes type.
--
-- Idempotent. Additive only.

-- ---------------------------------------------------------------------------
-- 1. ioc_observables admits email
-- ---------------------------------------------------------------------------
ALTER TABLE public.ioc_observables
  DROP CONSTRAINT IF EXISTS chk_observable_type;

ALTER TABLE public.ioc_observables
  ADD CONSTRAINT chk_observable_type CHECK (
    observable_type = ANY (ARRAY[
      'md5'::text, 'sha1'::text, 'sha256'::text, 'ssdeep'::text, 'imphash'::text, 'tlsh'::text,
      'ip'::text, 'ipv6'::text, 'domain'::text, 'url'::text, 'email'::text
    ])
  ) NOT VALID;

ALTER TABLE public.ioc_observables
  VALIDATE CONSTRAINT chk_observable_type;

-- ---------------------------------------------------------------------------
-- 2. Published Feeds admit email
-- ---------------------------------------------------------------------------
ALTER TABLE public.published_feeds
  DROP CONSTRAINT IF EXISTS chk_published_feeds_ioc_type;

ALTER TABLE public.published_feeds
  ADD CONSTRAINT chk_published_feeds_ioc_type CHECK (
    ioc_type = ANY (ARRAY['ip'::text, 'domain'::text, 'url'::text, 'hash'::text, 'email'::text])
  );

ALTER TABLE public.published_feeds
  DROP CONSTRAINT IF EXISTS chk_published_feeds_ioc_types;

ALTER TABLE public.published_feeds
  ADD CONSTRAINT chk_published_feeds_ioc_types CHECK (
    jsonb_typeof(ioc_types) = 'array'::text
    AND jsonb_array_length(ioc_types) >= 1
    AND jsonb_array_length(ioc_types) <= 5
    AND ioc_types <@ '["domain", "hash", "ip", "url", "email"]'::jsonb
  );
