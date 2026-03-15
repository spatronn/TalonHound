-- Drops legacy import_dedup table after dedup logic moved to ioc_items WHERE NOT EXISTS
DROP TABLE IF EXISTS import_dedup;
