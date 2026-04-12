ALTER TABLE ioc_ip_geo_cache
  ALTER COLUMN country_code DROP DEFAULT,
  ALTER COLUMN country_code DROP NOT NULL;
