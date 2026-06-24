-- Allow deleting an IOC source after all ioc_items are moved; preserve move history rows.

ALTER TABLE ioc_manual_source_memberships
  DROP CONSTRAINT IF EXISTS ioc_manual_source_memberships_ioc_source_id_fkey;

ALTER TABLE ioc_manual_source_memberships
  ADD CONSTRAINT ioc_manual_source_memberships_ioc_source_id_fkey
    FOREIGN KEY (ioc_source_id) REFERENCES ioc_sources(id) ON DELETE SET NULL;
