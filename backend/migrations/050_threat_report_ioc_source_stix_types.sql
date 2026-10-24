-- 050_threat_report_ioc_source_stix_types.sql
-- Allow STIX / Markdown source_type values written by the STIX-aware IOC Source parser.

ALTER TABLE public.threat_report_ioc_sources
  DROP CONSTRAINT IF EXISTS threat_report_ioc_sources_source_type_check;

ALTER TABLE public.threat_report_ioc_sources
  ADD CONSTRAINT threat_report_ioc_sources_source_type_check
  CHECK (source_type = ANY (ARRAY[
    'html'::text,
    'txt'::text,
    'csv'::text,
    'json'::text,
    'stix_json'::text,
    'stix_xml'::text,
    'xml'::text,
    'markdown'::text,
    'pdf'::text,
    'github_dir'::text,
    'github_file'::text,
    'unknown'::text
  ]));
