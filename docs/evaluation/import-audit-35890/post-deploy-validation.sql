-- Read-only validation of the 12 reports of import audit 35890-35901.
--
-- Stored Indicators = is_member rows of each report's latest non-legacy extraction run.
--
-- Inventories (auditable history):
--   original_audit_ioc (192) = the source-derived inventory before the P1 template
--     policy, including 5 publisher-template URLs marked malformed=true.
--   excluded_template_ioc (5) = those template URLs; never Indicators after P1.
--   expected_ioc (187) = the revised concrete-IOC inventory used for scoring.
--
-- Scoring against expected_ioc:
--   matched = expected AND stored; missing = expected, not stored;
--   false positive = stored, not expected.
-- Pre-deploy (prod c694d6d, 2026-11-14): stored 134, matched 133, valid 128,
--   malformed 5, FP 1, missing 59 (against the original 192).
-- After P0 refresh of 35894 and 35901 (f47edde): stored 190, matched 189,
--   valid 184, malformed 5, FP 1, missing 3 (against the original 192).
-- After a future P1 refresh (against expected_ioc 187): stored 187, matched 187,
--   missing 0, FP 0, and 0 rows in excluded_template_ioc as Indicators.
-- This is not proof of perfect extraction outside the curated inventory.

\echo === per report: latest run, contract, extractor, title, published date
with latest as (
  select distinct on (report_id) report_id, id run_id, run_type, contract_fingerprint
  from threat_report_extraction_runs where report_id between 35890 and 35901 and run_type <> 'legacy_baseline'
  order by report_id, id desc)
select l.report_id, l.run_type, left(l.contract_fingerprint, 8) fp, t.analysis_status,
       t.canonical_document->'meta'->>'extractor' extractor, left(t.title, 60) title, t.published_at::date
from latest l join threat_reports t on t.id = l.report_id order by 1;

create temp table original_audit_ioc (report_id bigint, identity text, malformed boolean) on commit preserve rows;
create temp table excluded_template_ioc (report_id bigint, identity text) on commit preserve rows;
create temp table expected_ioc (report_id bigint, identity text, malformed boolean) on commit preserve rows;

insert into excluded_template_ioc values
  (35892, 'url:http://157.20.241.16:8080/ob/cronhit?h=jup_start_'),
  (35900, 'url:https://securedoc.mesuttgulerr573.workers.dev/?id=%3Clinkid:8%3E'),
  (35900, 'url:https://securedoc.mesuttgulerr573.workers.dev/h?id=%3Clinkid:8%3E'),
  (35900, 'url:https://securedoc.mesuttgulerr573.workers.dev/m?id=%3Clinkid:8%3E'),
  (35900, 'url:https://securedoc.mesuttgulerr573.workers.dev/s?id=%3Clinkid:8%3E');

insert into original_audit_ioc values
  (35890, 'ip:197.47.160.252', false),
  (35890, 'ip:74.208.158.106', false),
  (35890, 'ip:87.106.111.220', false),
  (35890, 'sha256:008839ef2a2d54e9efa47013bb23c773d3a152f351e9dfd3b2f4dd27086121df', false),
  (35890, 'sha256:45136a9ab47015c4334b881df9daf824a72347daae0b5730ce3bd7d42b204bf2', false),
  (35890, 'sha256:b55ce5130cd2623017cca29318341f6b4656e3a1dc5ab82ce704e912d0d17535', false),
  (35890, 'sha256:bea82efc82672225cf29eb869972670754f15941bc61b9e5801ffd41c5c39e5f', false),
  (35890, 'sha256:c15b008b0296b1bc9e0f979e6f25b780e3e89edabb344c7ee8c284a1a140f0d7', false),
  (35890, 'sha256:e73020645e7a11a90865d93bd7f3d797585f49ef72b1ac7354392a2da7fbd91f', false),
  (35890, 'sha256:f6d37291c4948b974caf2e9e7e8ca9c2173d2779d1ec0a391488706bbd1a995c', false),
  (35891, 'domain:gpimmlgration.com', false),
  (35891, 'url:share.google/?q=UltJkMsVWI5V9GJM1', false),
  (35891, 'url:www.google.com/share.google?q=UltJkMsVWI5V9GJM1', false),
  (35892, 'ip:139.99.69.109', false),
  (35892, 'ip:157.20.241.16', false),
  (35892, 'ip:79.76.51.56', false),
  (35892, 'url:http://157.20.241.16:8080/jup.sh', false),
  (35892, 'url:http://157.20.241.16:8080/ob/cronhit?h=jup_start_', true),
  (35892, 'url:http://157.20.241.16:8080/ob/fcheck', false),
  (35892, 'url:http://157.20.241.16:8080/xmrig.tgz', false),
  (35892, 'url:http://157.20.241.16:8080/xvgz', false),
  (35893, 'domain:analytics.insightjs.com', false),
  (35893, 'domain:insightjs.com', false),
  (35893, 'ip:89.127.233.127', false),
  (35893, 'sha256:cc0ad05bfe85940a6067b3a72c182d3953339129206634141926d5d0b35973ec', false),
  (35894, 'domain:xcai.pro', false),
  (35894, 'ip:101.53.80.20', false),
  (35894, 'ip:103.248.148.84', false),
  (35894, 'ip:124.155.252.63', false),
  (35894, 'ip:144.172.64.128', false),
  (35894, 'ip:144.172.64.60', false),
  (35894, 'ip:144.172.64.99', false),
  (35894, 'ip:154.201.79.246', false),
  (35894, 'ip:178.16.54.129', false),
  (35894, 'ip:187.15.88.186', false),
  (35894, 'ip:187.15.89.186', false),
  (35894, 'ip:187.15.90.217', false),
  (35894, 'ip:199.19.95.66', false),
  (35894, 'ip:199.19.95.67', false),
  (35894, 'ip:199.19.95.68', false),
  (35894, 'ip:203.160.133.172', false),
  (35894, 'ip:205.214.59.31', false),
  (35894, 'ip:209.209.85.38', false),
  (35894, 'ip:23.158.220.98', false),
  (35894, 'ip:23.248.249.90', false),
  (35894, 'ip:31.77.229.35', false),
  (35894, 'ip:38.244.50.120', false),
  (35894, 'ip:85.11.167.52', false),
  (35894, 'ip:85.11.168.45', false),
  (35894, 'ip:91.92.240.238', false),
  (35895, 'domain:blue-eagle-26751.zap.cloud', false),
  (35895, 'domain:chainmanamgentagency.info', false),
  (35895, 'domain:db-connectors.vercel.app', false),
  (35895, 'domain:green-horse-42739.zap.cloud', false),
  (35895, 'ip:138.226.247.154', false),
  (35895, 'ip:147.189.169.26', false),
  (35895, 'ip:185.248.161.18', false),
  (35895, 'ip:94.249.185.106', false),
  (35895, 'sha256:39abfd47b02d66ed2084775b4ade23c3f057969490d60a1e50309b72544a8a9d', false),
  (35895, 'sha256:47a76888121a06bf9d56313b21be269a3b5acb32a7c25c0ef8c4739e219c27ce', false),
  (35895, 'sha256:5dff1771d10845cc06c6e501d9f3e4359ebe60bcf6a0d3699d8ed41abab24857', false),
  (35895, 'sha256:6562585009f15155eea9a489e474cebc4dd2a01a26d846fdd1b93fdc24b0c269', false),
  (35895, 'sha256:ebeb2ecce5c173cbec156a4d66413dba0bd60a5bf7ee90ba8100a7866bbbd9e2', false),
  (35896, 'ip:43.240.29.11', false),
  (35896, 'ip:43.240.29.28', false),
  (35896, 'ip:43.240.29.33', false),
  (35897, 'domain:ip-223-6.dataclub.info', false),
  (35897, 'domain:lo1yaizaeghaevarood1ahtaichootae.nofrillsdns.com', false),
  (35897, 'domain:lo1yaizaeghaevarood1ahtaichootaz.nofrillsdns.com', false),
  (35897, 'domain:vmware-timecheck-api.nofrillsdns.com', false),
  (35897, 'ip:193.3.23.236', false),
  (35897, 'ip:80.76.42.139', false),
  (35897, 'ip:95.81.115.77', false),
  (35897, 'md5:346b04985ec6c5d107ba0ddf32fe7691', false),
  (35897, 'md5:5aa8c19c897176502cf8d8fc543fafc7', false),
  (35897, 'md5:5e04b2891635cbaa83ad619fe248e85b', false),
  (35897, 'md5:68957de915e2a58339fa477f8078bdf4', false),
  (35897, 'md5:6d12efa1db15121f88d58b9952e301ef', false),
  (35897, 'md5:719e813e527920e83349e061b5b1590f', false),
  (35897, 'md5:86ff08749e77d5d078e929e5f9748504', false),
  (35897, 'md5:b86690213f0155f7b3b65832301ed932', false),
  (35897, 'md5:cb2908ef4cc042bfe856c84e9b61a2f9', false),
  (35898, 'md5:5bd3c5f273ba5ae4c4ae745c6943a4f7', false),
  (35898, 'md5:8b3542531d98a47524c0f468d0158996', false),
  (35898, 'md5:e0d7a34bc9f4590bc073d08b50c854d1', false),
  (35898, 'url:http://www.dumbsplash.com/ilto/', false),
  (35899, 'domain:quill-kraee-um2gf.pro', false),
  (35899, 'sha256:58e503cc2e6aacc6bdba54f40a7edebf7a5362bef0a9039769baaba8c472c4db', false),
  (35899, 'sha256:8b5026d841aa93758ec3cb55c276f84d3ec1cf459810e0d9aa5624e2776f2fcd', false),
  (35899, 'sha256:c34cc30cb1cff5c47d77e62a3ba63e9a183989ec1ccdf7929beb1bcae0d41f23', false),
  (35899, 'url:http://171.22.131.24:8133/api/t', false),
  (35899, 'url:http://45.150.32.130/37339606cba4522a?force=1', false),
  (35899, 'url:http://45.150.32.130/4be1066a49e75?force=1', false),
  (35900, 'domain:544504d7fe1e.xyz', false),
  (35900, 'domain:a8f2aac37385.xyz', false),
  (35900, 'domain:bestutyresdomaonupder.com', false),
  (35900, 'domain:bestutyresdomaonupder.top', false),
  (35900, 'domain:bestutyresdomaonupder2324.com', false),
  (35900, 'domain:cdn-analytics-3f4033.rosamariaeadeshtvfud.workers.dev', false),
  (35900, 'domain:cdn-analytics-p53.makeneg458.workers.dev', false),
  (35900, 'domain:cdn-assets-api.busykifukek2-8psk.workers.dev', false),
  (35900, 'domain:cdn-assets-api.cfchk902834.workers.dev', false),
  (35900, 'domain:cdn-assets-api.kessler-m88.workers.dev', false),
  (35900, 'domain:cdn-assets-api.makeneg458.workers.dev', false),
  (35900, 'domain:dns.cdn-syncnode-server.com', false),
  (35900, 'domain:dns.timesyncserver-312453.com', false),
  (35900, 'domain:kfkwrfdd.xyz', false),
  (35900, 'domain:linkrot.fypahedupal2-0maz.workers.dev', false),
  (35900, 'domain:securedoc.makeneg458.workers.dev', false),
  (35900, 'domain:securedoc.mesuttgulerr573.workers.dev', false),
  (35900, 'domain:sync-node-serv.com', false),
  (35900, 'ip:145.63.138.67', false),
  (35900, 'ip:162.252.198.204', false),
  (35900, 'ip:162.252.199.92', false),
  (35900, 'ip:176.9.154.69', false),
  (35900, 'ip:185.224.132.148', false),
  (35900, 'ip:91.132.93.251', false),
  (35900, 'ip:94.156.152.7', false),
  (35900, 'sha256:009099ba10365b44bdb3ecc28dfcbed6a594ec0a0df86931620cdaac9843e611', false),
  (35900, 'sha256:0aff424f9a02eb9f429119c4caa05e85fc952603549d69849e745293d20235d6', false),
  (35900, 'sha256:0dcfe51d2521e52a469f5cec6b42bc8e7e37b41df993cce7d739ff3fd248d8b1', false),
  (35900, 'sha256:0e1c94a8f94158f64558325ddbfd1e1277884fba6fb1f8c381dbd5c742e59fbb', false),
  (35900, 'sha256:47e853092511d9663196e9b36d563a0c3e92ee734f88675c4f375ffcfa5f3db8', false),
  (35900, 'sha256:4efe003a54db8ffbaef6065270eacb0a59479ccc86941517ac7a33344e97bc1d', false),
  (35900, 'sha256:4f656834e545c0b44922ce6d8952989c8c0859d8ae8b1f117c06ab07b047e2b4', false),
  (35900, 'sha256:56582934901cce0b618d6a50e54c9db29bf2d444636bcd40b5975a765ecde538', false),
  (35900, 'sha256:7055483a77f679ad569c3a9bfe76cdb8e5b96efc44d2bf2a6f08e930add598b0', false),
  (35900, 'sha256:79a4cb73983a1facb5db09f1a20cec6e58d91a93044a78aa3ba32ab2190284ed', false),
  (35900, 'sha256:8ebb2bf61b48ae7abdcd674413bebd79b30ddd945854e175ba60d56c0a3adf54', false),
  (35900, 'sha256:9a2af4b6d9780e08c86ff35030ee1747ea11460cb1dffc868c48e7af6d626546', false),
  (35900, 'sha256:a4ad001c6900176eba43a747ae5d212db6fc78f7ef4e777f276cbbdf8099dbe8', false),
  (35900, 'sha256:a972797cc1a4161f6e2841142b8cace9b781585f9a71b03aa79a9c051b817491', false),
  (35900, 'sha256:bceeb2d54b6a756c73a3e06617e9e95ad4d8e53da47639bcd6ef3cae98c6da6d', false),
  (35900, 'sha256:bd1c005f35e4fd8c61dfa6f20d4c03e082c692e286a3b22dd642369c8d5e3564', false),
  (35900, 'sha256:d2d41b249905deae3bd6bcaa547872d747256a7dfa459b509d9db9de8f0ca29b', false),
  (35900, 'sha256:dbd252becd490ac47e16bff4391ab9e6237c4f7e81ab6784c57fa2eed751f477', false),
  (35900, 'sha256:dc57638cb90798835848a9dafec228bef7738def50f4f2db612862e07c5b6f8a', false),
  (35900, 'sha256:e9e57a57ee45b8faae2e47affd8cf3a6d0cc1283802108f7298ae1d2ef3b43f0', false),
  (35900, 'sha256:ee5fa33b58d0f2772e091e23de9db24908d970000a88e39fd7d908f30f5e591a', false),
  (35900, 'sha256:efc4b8c1968c06e598a6f6f98398d44b488198b497291fe30fb792d696b6cb81', false),
  (35900, 'url:http://145.63.138.67:8125/up/', false),
  (35900, 'url:https://gist.githubusercontent.com/yegeqebige46-creator/b393f36b20ad8aeadcb8a80af70ccc09/raw/da03fd7f1ffacda970a1f3d345bdaeae8c6a7b43/gistfile1.txt', false),
  (35900, 'url:https://github.com/JohnDow22', false),
  (35900, 'url:https://github.com/yegeqebige46-creator/qq', false),
  (35900, 'url:https://github.com/yegeqebige46-creator/qq/raw/main/update.zip', false),
  (35900, 'url:https://linkrot.fypahedupal2-0maz.workers.dev/link?token=7157717581ca4e3dda83e418af25fa448fe98ed2', false),
  (35900, 'url:https://securedoc.mesuttgulerr573.workers.dev/?id=%3Clinkid:8%3E', true),
  (35900, 'url:https://securedoc.mesuttgulerr573.workers.dev/h?id=%3Clinkid:8%3E', true),
  (35900, 'url:https://securedoc.mesuttgulerr573.workers.dev/m?id=%3Clinkid:8%3E', true),
  (35900, 'url:https://securedoc.mesuttgulerr573.workers.dev/s?id=%3Clinkid:8%3E', true),
  (35901, 'domain:stinkyshockblazer.cfd', false),
  (35901, 'domain:unmoralreformeddehydrate.cfd', false),
  (35901, 'ip:108.186.112.105', false),
  (35901, 'ip:198.46.243.24', false),
  (35901, 'ip:38.255.32.104', false),
  (35901, 'ip:46.250.238.87', false),
  (35901, 'ip:85.239.144.51', false),
  (35901, 'sha256:059c0dcdd98d19e31d310427a422d48c47c5e8615ad3c0d31fcaa26c4eacac1c', false),
  (35901, 'sha256:2d93804826f8a7a28ce6f60162f1d73b84c6ece3daa823ece170fafc558a796d', false),
  (35901, 'sha256:407dd6fc3839977aef22ab7083f53f2544140ed47b05177ca2910521a3731740', false),
  (35901, 'sha256:44b5f61672bd2243250d068053c2e2fd4be2277b1833ebedf97c43d2723d9d23', false),
  (35901, 'sha256:4eddd4af1fd3a3e40e61e9cc2961b540504e86713c27fda166f7b870b3a0f36e', false),
  (35901, 'sha256:598abde0f738440fa7a368b9f5c324a7f54847dab55fd88ed817f5c17f56d882', false),
  (35901, 'sha256:6298d7791cd6f556d4e8b60350a5fe6a4361cba7234d416031186ee249a81cc8', false),
  (35901, 'sha256:6a98f728dd24e272965a9dae64ccbf9c4a34b1136c2fda3ebf3fc2f1f4813941', false),
  (35901, 'sha256:72a9a2bbefdfc08b7153f7808c7b27254bdb4b5d9e3a3c0249b5889efbc0becf', false),
  (35901, 'sha256:79bc2ef7e362394cb209de491ff8c2402c944b835d923ece0a63531922c2f4b1', false),
  (35901, 'sha256:86ca13d899fb4c9eb9a7a783347b8901945fac8039d1dfbb148f57dbd14991d9', false),
  (35901, 'sha256:99fce013248f101bd8a3d51142e0c2fd8cd480443a99519cf8a5426a69e06f45', false),
  (35901, 'sha256:a94e2c99cd8aaed4124fb4301b71dc97d480bf47135d4d7f45057f2c05487b0e', false),
  (35901, 'sha256:b42910aae8a63d7550b5e8277ac47aebb842441e2110a75ff6bd4dfa5f927dd7', false),
  (35901, 'sha256:ba916aa1dfb0f562556e514b9fe92637e97282813047955c9744467154da3df3', false),
  (35901, 'sha256:c5c4c9b794e5f1f2be986b7dbb74bba949218be947ca0f381585f551bec0a846', false),
  (35901, 'sha256:c65bfd22870a3a7e561a8009a9b69f58c0a9017343095d849f64a428cf136431', false),
  (35901, 'sha256:d08f5be17e0faae9e2284d89995ee0e9d86f2f7e700a0cc01e268c651f892cc1', false),
  (35901, 'sha256:e5f52fa07c411141904d2f41aa5ba774083272f787d5871a5bc9bba9d2d07902', false),
  (35901, 'sha256:f41ad6382381aa01b232007a62e845dfb062dc7050f23e987f341fe04b5628e8', false),
  (35901, 'sha256:f72d737bba6785cb1c94c773a1bf1f283e6395ec5d0daf051734a2f2147fe28d', false),
  (35901, 'sha256:fc1e396f086f78b1c1a722187d5576ca1a110139f6ea92051c056fae2bcaee15', false),
  (35901, 'url:http://108.186.112.105:5173/api/clients/342b4805758e2ea62fe3b91c7614a4d719caf819dc5b4afc8d5e4694666cf21a/stream/ws', false),
  (35901, 'url:http://198.46.243.24:5173/api/clients/ae8ff1c3b5e620b2233389661842c765cd04dfecd73a880de3cbf7115c1ebb50/stream/ws', false),
  (35901, 'url:http://38.255.32.104:5173/api/clients/f146eac864ccd709d022e4b14a98441eb19d6b92aa921a0c1279a449b1ec57f0/stream/ws', false),
  (35901, 'url:http://46.250.238.87/agent.exe', false),
  (35901, 'url:http://46.250.238.87:5173/api/clients/19d38ac5455dbd8392b07036f11bdef3596c41b67f81d1bf1aaee7a8d074ac0b/stream/ws', false),
  (35901, 'url:http://46.250.238.87:5173/api/clients/58a6172bcf0ed2c48f4f33d9976796375c9763a2be53922c8089afeccdb2c097/stream/ws', false),
  (35901, 'url:http://46.250.238.87:5173/api/clients/7ca843cebc422ba7c437018500c3933b5d972cefc0af4b460116830e996f3ba3/stream/ws', false),
  (35901, 'url:http://46.250.238.87:5173/api/clients/caf7038b9d615f75243b31632268602017d3665ec80b064205c869413bc8c038/stream/ws', false),
  (35901, 'url:http://85.239.144.51/agent.exe', false),
  (35901, 'url:http://85.239.144.51:5173/api/clients/53298f5e0823781d027e751bbac0b68339f7e40fc23b9c4b0f56663e80d06612/stream/ws', false),
  (35901, 'url:http://85.239.144.51:5173/api/clients/8b097777ffe1ae102fc7ac9af97119e4287315a5c385d7d6c4a2a860ec2e44b7/stream/ws', false),
  (35901, 'url:http://85.239.144.51:5173/api/clients/9e4dfd51fb1788a91403039724dffc0457aae05dbf9719bb9d1454cac33b9352/stream/ws', false),
  (35901, 'url:http://85.239.144.51:5173/api/clients/f14ee4054ed8f6b15042cc7a1ca56052d4d8e6558d942e32105772a54e9bfe69/stream/ws', false);

insert into expected_ioc
select report_id, identity, false
from original_audit_ioc o
where not exists (
  select 1 from excluded_template_ioc t
  where t.report_id = o.report_id and t.identity = o.identity
);

\echo === inventory sizes (expect original 192, excluded templates 5, concrete expected 187)
select (select count(*) from original_audit_ioc) original_audit_192,
       (select count(*) from excluded_template_ioc) excluded_templates_5,
       (select count(*) from expected_ioc) concrete_expected_187;

create temp table stored_ioc on commit preserve rows as
with latest as (
  select distinct on (report_id) report_id, id run_id from threat_report_extraction_runs
  where report_id between 35890 and 35901 and run_type <> 'legacy_baseline' order by report_id, id desc)
select l.report_id, rc.candidate_type || ':' || rc.normalized_value identity
from latest l join threat_report_extraction_run_candidates rc on rc.run_id = l.run_id and rc.is_member;

\echo === per report: expected | stored | matched | valid | malformed | missing | false_positive
select e.report_id,
       count(*) expected,
       (select count(*) from stored_ioc s where s.report_id = e.report_id) stored,
       count(s.identity) matched,
       count(s.identity) filter (where not e.malformed) valid,
       count(s.identity) filter (where e.malformed) malformed,
       count(*) filter (where s.identity is null) missing,
       (select count(*) from stored_ioc s2 where s2.report_id = e.report_id
          and not exists (select 1 from expected_ioc e2 where e2.report_id = s2.report_id and e2.identity = s2.identity)) false_positive
from expected_ioc e left join stored_ioc s on s.report_id = e.report_id and s.identity = e.identity
group by e.report_id order by 1;

\echo === totals: expected | stored | matched | valid | malformed | missing | false_positive
select (select count(*) from expected_ioc) expected,
       (select count(*) from stored_ioc) stored,
       count(s.identity) matched,
       count(s.identity) filter (where not e.malformed) valid,
       count(s.identity) filter (where e.malformed) malformed,
       count(*) filter (where s.identity is null) missing,
       (select count(*) from stored_ioc s2 where not exists (select 1 from expected_ioc e2 where e2.report_id = s2.report_id and e2.identity = s2.identity)) false_positive
from expected_ioc e left join stored_ioc s on s.report_id = e.report_id and s.identity = e.identity;

\echo === missing expected IOCs (after a P1 refresh expect 0 rows)
select e.report_id, e.identity from expected_ioc e
where not exists (select 1 from stored_ioc s where s.report_id = e.report_id and s.identity = e.identity) order by 1, 2;

\echo === stored but not expected (after a P1 refresh expect 0 rows; f47edde still has malware-traffic-analysis.net)
select s.report_id, s.identity from stored_ioc s
where not exists (select 1 from expected_ioc e where e.report_id = s.report_id and e.identity = s.identity) order by 1, 2;

\echo === excluded publisher-template URLs must not be Indicators (expect 0 rows after a P1 refresh)
select t.report_id, t.identity from excluded_template_ioc t
where exists (select 1 from stored_ioc s where s.report_id = t.report_id and s.identity = t.identity)
order by 1, 2;

\echo === template-shaped stored Indicators outside the excluded list (expect 0 rows)
select report_id, identity from stored_ioc
where identity like '%jup_start_%' or identity like '%linkid%' or identity ilike '%3Crig%' or identity ilike '%3Cmethod%';

\echo === benign values that must not be Indicators (expect 0 rows)
select report_id, identity from stored_ioc
where split_part(identity, ':', 2) in ('api.anthropic.com','api.deepseek.com','open.bigmodel.cn','api.x.ai','api.ipify.org','127.0.0.1','bi.zone','webhook.site','api.db-ip.com');

\echo === analyst decisions + IOC matches (snapshot before, compare after; 10 unrefreshed reports must be identical)
select report_id, review_status, count(*), count(matched_ioc_id) matched_ioc,
       md5(string_agg(candidate_type || ':' || normalized_value || ':' || review_status, ',' order by candidate_type, normalized_value)) digest
from threat_report_candidates where report_id between 35890 and 35901 group by 1, 2 order by 1, 2;

\echo === duplicates / active jobs (expect 0 rows)
select report_id, candidate_type, lower(normalized_value), count(*) from threat_report_candidates
where report_id between 35890 and 35901 group by 1, 2, 3 having count(*) > 1;
select report_id, id, job_type, status from threat_library_jobs where report_id between 35890 and 35901 and status in ('queued','running');
