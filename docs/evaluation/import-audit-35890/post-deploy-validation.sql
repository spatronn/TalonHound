-- Read-only validation of reports 35890-35901 (persisted Indicators = is_member rows of each report's latest real extraction run).
\echo === per report: latest run, contract, Indicators, candidates, status
with latest as (
  select distinct on (report_id) report_id, id run_id, run_type, contract_fingerprint, completed_at
  from threat_report_extraction_runs where report_id between 35890 and 35901 and run_type <> 'legacy_baseline'
  order by report_id, id desc)
select l.report_id, l.run_type, left(l.contract_fingerprint, 8) fp,
       (select count(*) from threat_report_extraction_run_candidates rc where rc.run_id = l.run_id and rc.is_member) indicators,
       (select count(*) from threat_report_candidates c where c.report_id = l.report_id) candidates,
       t.analysis_status, t.canonical_document->'meta'->>'extractor' extractor, left(t.title, 50) title, t.published_at::date
from latest l join threat_reports t on t.id = l.report_id order by 1;

\echo === totals: stored / valid / malformed / false positive / missing
with latest as (
  select distinct on (report_id) report_id, id run_id from threat_report_extraction_runs
  where report_id between 35890 and 35901 and run_type <> 'legacy_baseline' order by report_id, id desc),
m as (select l.report_id, rc.candidate_type, rc.normalized_value v from latest l
      join threat_report_extraction_run_candidates rc on rc.run_id = l.run_id and rc.is_member),
malformed as (select * from m where (report_id = 35900 and v like '%\%3Clinkid:8\%3E%') or (report_id = 35892 and v like '%/ob/cronhit?h=jup_start_')),
fp as (select * from m where report_id = 35899 and v = 'malware-traffic-analysis.net'),
missing(report_id, t, v) as (values (35895,'domain','green-horse-42739.zap.cloud'), (35895,'domain','blue-eagle-26751.zap.cloud'), (35899,'url','http://171.22.131.24:8133/api/t'))
select (select count(*) from m) stored,
       (select count(*) from m) - (select count(*) from malformed) - (select count(*) from fp) valid,
       (select count(*) from malformed) malformed, (select count(*) from fp) false_positive,
       (select count(*) from missing x where not exists (select 1 from m where m.report_id = x.report_id and m.v = x.v)) still_missing_of_3;

\echo === 35894 / 35901: expected Indicator sets (rows = missing expected values; empty = complete)
with latest as (
  select distinct on (report_id) report_id, id run_id from threat_report_extraction_runs
  where report_id in (35894, 35901) and run_type <> 'legacy_baseline' order by report_id, id desc),
m as (select l.report_id, rc.candidate_type || ':' || rc.normalized_value id from latest l
      join threat_report_extraction_run_candidates rc on rc.run_id = l.run_id and rc.is_member),
exp(report_id, id) as (
  select 35894, 'ip:' || x from unnest(string_to_array('38.244.50.120 144.172.64.60 144.172.64.99 144.172.64.128 187.15.88.186 187.15.90.217 187.15.89.186 101.53.80.20 205.214.59.31 124.155.252.63 154.201.79.246 23.248.249.90 23.158.220.98 103.248.148.84 203.160.133.172 209.209.85.38 199.19.95.66 199.19.95.67 199.19.95.68 91.92.240.238 85.11.168.45 178.16.54.129 31.77.229.35 85.11.167.52', ' ')) x
  union all select 35894, 'domain:xcai.pro'
  union all select 35901, 'sha256:' || x from unnest(string_to_array('f41ad6382381aa01b232007a62e845dfb062dc7050f23e987f341fe04b5628e8 79bc2ef7e362394cb209de491ff8c2402c944b835d923ece0a63531922c2f4b1 a94e2c99cd8aaed4124fb4301b71dc97d480bf47135d4d7f45057f2c05487b0e 86ca13d899fb4c9eb9a7a783347b8901945fac8039d1dfbb148f57dbd14991d9 d08f5be17e0faae9e2284d89995ee0e9d86f2f7e700a0cc01e268c651f892cc1 fc1e396f086f78b1c1a722187d5576ca1a110139f6ea92051c056fae2bcaee15 407dd6fc3839977aef22ab7083f53f2544140ed47b05177ca2910521a3731740 44b5f61672bd2243250d068053c2e2fd4be2277b1833ebedf97c43d2723d9d23 6a98f728dd24e272965a9dae64ccbf9c4a34b1136c2fda3ebf3fc2f1f4813941 99fce013248f101bd8a3d51142e0c2fd8cd480443a99519cf8a5426a69e06f45 f72d737bba6785cb1c94c773a1bf1f283e6395ec5d0daf051734a2f2147fe28d ba916aa1dfb0f562556e514b9fe92637e97282813047955c9744467154da3df3 4eddd4af1fd3a3e40e61e9cc2961b540504e86713c27fda166f7b870b3a0f36e c5c4c9b794e5f1f2be986b7dbb74bba949218be947ca0f381585f551bec0a846 059c0dcdd98d19e31d310427a422d48c47c5e8615ad3c0d31fcaa26c4eacac1c c65bfd22870a3a7e561a8009a9b69f58c0a9017343095d849f64a428cf136431 e5f52fa07c411141904d2f41aa5ba774083272f787d5871a5bc9bba9d2d07902 6298d7791cd6f556d4e8b60350a5fe6a4361cba7234d416031186ee249a81cc8 72a9a2bbefdfc08b7153f7808c7b27254bdb4b5d9e3a3c0249b5889efbc0becf 2d93804826f8a7a28ce6f60162f1d73b84c6ece3daa823ece170fafc558a796d b42910aae8a63d7550b5e8277ac47aebb842441e2110a75ff6bd4dfa5f927dd7 598abde0f738440fa7a368b9f5c324a7f54847dab55fd88ed817f5c17f56d882', ' ')) x
  union all select 35901, 'ip:' || x from unnest(string_to_array('38.255.32.104 46.250.238.87 85.239.144.51 108.186.112.105 198.46.243.24', ' ')) x
  union all select 35901, 'domain:' || x from unnest(string_to_array('unmoralreformeddehydrate.cfd stinkyshockblazer.cfd', ' ')) x
  union all select 35901, 'url:http://85.239.144.51/agent.exe' union all select 35901, 'url:http://46.250.238.87/agent.exe'
  union all select 35901, 'url:http://' || x || '/stream/ws' from unnest(string_to_array('85.239.144.51:5173/api/clients/9e4dfd51fb1788a91403039724dffc0457aae05dbf9719bb9d1454cac33b9352 85.239.144.51:5173/api/clients/f14ee4054ed8f6b15042cc7a1ca56052d4d8e6558d942e32105772a54e9bfe69 85.239.144.51:5173/api/clients/53298f5e0823781d027e751bbac0b68339f7e40fc23b9c4b0f56663e80d06612 85.239.144.51:5173/api/clients/8b097777ffe1ae102fc7ac9af97119e4287315a5c385d7d6c4a2a860ec2e44b7 46.250.238.87:5173/api/clients/caf7038b9d615f75243b31632268602017d3665ec80b064205c869413bc8c038 46.250.238.87:5173/api/clients/7ca843cebc422ba7c437018500c3933b5d972cefc0af4b460116830e996f3ba3 46.250.238.87:5173/api/clients/19d38ac5455dbd8392b07036f11bdef3596c41b67f81d1bf1aaee7a8d074ac0b 46.250.238.87:5173/api/clients/58a6172bcf0ed2c48f4f33d9976796375c9763a2be53922c8089afeccdb2c097 38.255.32.104:5173/api/clients/f146eac864ccd709d022e4b14a98441eb19d6b92aa921a0c1279a449b1ec57f0 198.46.243.24:5173/api/clients/ae8ff1c3b5e620b2233389661842c765cd04dfecd73a880de3cbf7115c1ebb50 108.186.112.105:5173/api/clients/342b4805758e2ea62fe3b91c7614a4d719caf819dc5b4afc8d5e4694666cf21a', ' ')) x)
select e.report_id, count(*) filter (where m.id is null) missing, count(*) expected,
       (select count(*) from m m2 where m2.report_id = e.report_id and not exists (select 1 from exp e2 where e2.report_id = m2.report_id and e2.id = m2.id)) unexpected
from exp e left join m on m.report_id = e.report_id and m.id = e.id group by e.report_id order by 1;

\echo === benign values that must not be Indicators (expect 0 rows)
with latest as (
  select distinct on (report_id) report_id, id run_id from threat_report_extraction_runs
  where report_id in (35894, 35901) and run_type <> 'legacy_baseline' order by report_id, id desc)
select l.report_id, rc.normalized_value from latest l join threat_report_extraction_run_candidates rc on rc.run_id = l.run_id and rc.is_member
where rc.normalized_value in ('api.anthropic.com','api.deepseek.com','open.bigmodel.cn','api.x.ai','api.ipify.org','127.0.0.1','bi.zone','webhook.site','api.db-ip.com');

\echo === analyst decisions + IOC links on the 12 reports (snapshot before, compare after)
select report_id, review_status, count(*), count(matched_ioc_id) linked, md5(string_agg(candidate_type || ':' || normalized_value || ':' || review_status, ',' order by candidate_type, normalized_value)) digest
from threat_report_candidates where report_id between 35890 and 35901 group by 1, 2 order by 1, 2;

\echo === duplicates / active jobs (expect 0 rows)
select report_id, candidate_type, lower(normalized_value), count(*) from threat_report_candidates where report_id between 35890 and 35901 group by 1,2,3 having count(*) > 1;
select report_id, id, job_type, status from threat_library_jobs where report_id between 35890 and 35901 and status in ('queued','running');
