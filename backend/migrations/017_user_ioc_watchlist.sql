-- Per-user IOC Watchlist (Favorites).
--
-- Membership is a relationship between a user and an IOC — never a global IOC
-- property. Isolation is enforced by always scoping reads/writes to user_id.
--
-- Design notes:
--   * ioc_items is LIST-partitioned by observable_type and its primary key is the
--     composite (observable_type, id); public_id is only indexed, not unique. The
--     only real foreign-key target is therefore the composite PK, so we store
--     (observable_type, ioc_id) and reference ioc_items(observable_type, id).
--   * The table starts empty (no historical backfill needed) so adding the
--     foreign key does not scan or rewrite the ~millions of ioc_items rows — it is
--     a metadata-only operation. migrate.js runs this file inside one transaction
--     with lock_timeout set, so if ingestion briefly holds a conflicting lock the
--     whole migration fails closed and rolls back cleanly (safe to retry).
--   * Idempotent: guarded with IF NOT EXISTS and tracked by filename in
--     schema_migrations.

CREATE TABLE IF NOT EXISTS public.user_ioc_watchlist (
  user_id bigint NOT NULL,
  observable_type text NOT NULL,
  ioc_id bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT user_ioc_watchlist_pkey PRIMARY KEY (user_id, observable_type, ioc_id),
  CONSTRAINT user_ioc_watchlist_user_fkey
    FOREIGN KEY (user_id) REFERENCES public.users (id) ON DELETE CASCADE,
  CONSTRAINT user_ioc_watchlist_ioc_fkey
    FOREIGN KEY (observable_type, ioc_id)
    REFERENCES public.ioc_items (observable_type, id) ON DELETE CASCADE
);

COMMENT ON TABLE public.user_ioc_watchlist IS
  'Per-user starred IOCs (Watchlist / Favorites). One row per (user, IOC). Strictly user-scoped; never expose another user''s rows.';

-- List a user''s watchlist newest-first without touching other users'' rows.
CREATE INDEX IF NOT EXISTS idx_user_ioc_watchlist_user_created
  ON public.user_ioc_watchlist (user_id, created_at DESC);

-- Membership annotation for a page of IOCs: WHERE user_id = $1 AND ioc_id = ANY($2).
-- ioc_id is globally unique (shared sequence across partitions), so this alone is
-- an exact per-user membership lookup.
CREATE INDEX IF NOT EXISTS idx_user_ioc_watchlist_user_ioc
  ON public.user_ioc_watchlist (user_id, ioc_id);

-- Supports the ioc_items ON DELETE CASCADE, which resolves referencing rows by the
-- referenced columns (observable_type, ioc_id).
CREATE INDEX IF NOT EXISTS idx_user_ioc_watchlist_ioc
  ON public.user_ioc_watchlist (observable_type, ioc_id);
