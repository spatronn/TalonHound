-- GUI restore prepare/confirm flow removed; restore is host CLI only.
-- system_restores was only used by the Admin UI prepare/confirm API.

DROP TABLE IF EXISTS system_restores;
