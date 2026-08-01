# IOC Search Endpoint Analizi

Bu doküman `GET /api/ioc/list` endpoint'ini, gecikme kaynaklarını ve performans önerilerini özetler.

---

## 1. Endpoint

- **Route:** `GET /api/ioc/list`
- **Query params:** `q`, `source_name`, `confidence`, `asn`, `country`, `page`, `page_size`
- **Kullanım:** IOC List sayfasındaki arama kutusu (`sha256:...`, `md5:...`, serbest metin vb.)

---

## 2. Timing Logları

**Açma:**  
- **docker-compose:** Backend servisinde `IOC_LIST_TIMING=1` env var tanımlı (varsayılan test ortamı). Container yeniden başlatıldığında `docker compose logs backend` ile startup’ta `[ioc/list] IOC_LIST_TIMING=1: timing logs enabled` satırı görünür.
- **Manuel:** `IOC_LIST_TIMING=1` (env) veya istekte **`?timing=1`** (tek istek, env olmadan).

Aşağıdaki aşamalar loglanır (ms):

| Aşama | Açıklama |
|--------|----------|
| **searchStringParse** | İstek alındı → `q` parse (prefixed hash / generic) |
| **dbConnectionAcquired** | Pool'dan client alınması (timing açıkken `pool.connect()`) |
| **dbQuery** | Ana list sorgusu (tek SELECT minimal path'te, CTE path'te 1 büyük sorgu) |
| **countQuery** | Boş sayfa durumunda ek COUNT (sadece CTE path) |
| **paginationLogic** | Slice + sayfa item'ları (minimal path) |
| **resultMapping** | Satırlar → API şekli (map / gruplama) |
| **jsonStringify** | `JSON.stringify(payload)` süresi (gerçek CPU maliyeti) |
| **responseSent** | Yanıt yazılıp kapanana kadar (ağ/proxy dahil) |
| **total** | İstek başından yanıt bitene kadar toplam |
| **queries** | Çalışan DB sorgu sayısı (1 veya 2) |
| **responseBytes** | JSON yanıt boyutu (byte); büyükse serialize/ağ yavaşlar |

Örnek log (minimal path):
```
[ioc/list timing] searchStringParse=0ms dbConnectionAcquired=1ms dbQuery=3ms paginationLogic=0ms resultMapping=1ms jsonStringify=0ms responseSent=2ms total=7ms queries=1 rows=12 responseBytes=2048 path=minimalHash q=sha256:68274...
```

**Gecikme nerede?**
- **dbConnectionAcquired** yüksek → Pool veya ilk bağlantı.
- **dbQuery** yüksek → Sorgu/plan; EXPLAIN ANALYZE ile kontrol et.
- **resultMapping** / **jsonSerialization** yüksek → Çok satır veya büyük payload.
- **responseSent** yüksek → Ağ veya proxy.

---

## 3. Kaç Sorgu Çalışıyor?

| Durum | Sorgu sayısı | Açıklama |
|--------|---------------|----------|
| Normal (sonuç var) | **1** | Tek sorgu: CTE (combined → filtered → grouped) + geo join + LIMIT/OFFSET, `COUNT(*) OVER()` ile total |
| Boş sayfa | **2** | Aynı CTE ile list sorgusu (0 satır) + ayrı COUNT sorgusu |
| Hash-only (sha256:/md5:/sha1:, asn/country yok) — **varsayılan** | **1** | Tek `SELECT ... WHERE observable_type AND observable OR note_expr` + Node'da gruplama (minimal path). CTE kullanılmaz. |
| Hash-only + `IOC_LIST_USE_CTE_FOR_HASH=1` | 1 veya 2 | Eski CTE path (gruplama DB'de) |

- **JOIN:** Sadece asn/country filtresi varken `ioc_ip_geo_cache` ile LEFT JOIN.
- **Enrichment / source:** Aynı endpoint içinde ek sorgu yok; tüm veri tek (veya iki) sorgudan geliyor.

---

## 4. Search Logic: Exact Match (sha256:/md5:/sha1:) ve plan davranışı

- **Exact hash path (varsayılan):** Prefixed hash için `ioc_file_hash` tablosu, `WHERE observable = $1`, LIMIT 1; LOWER/OR/note yok. dbQuery ms seviyesi.
- **observable_type literal (CTE path):** Sorguda `observable_type = $1` yerine `observable_type = 'sha256'` (whitelist’ten literal) kullanılır; böylece PostgreSQL parametreye göre generic plan yerine sabit değere göre concrete plan ve index kullanır. pg driver ile parametreli `observable_type = $1` kullanıldığında plan 2–6 sn sürebilir; literal ile ~2 ms seviyesine iner.

- Arama `sha256:xxxx`, `md5:xxxx`, `sha1:xxxx` formatındaysa **parse edilip** exact match kullanılıyor:
  - `observable_type = 'sha256'` (literal, whitelist) ve `LOWER(observable) = $1` (tek parametre)
  - Veya note içinden hash çıkaran expression = `$1`
- **Generic ILIKE** sadece prefiks/hash formatı yokken kullanılıyor (`observable ILIKE $n`, `source_name ILIKE $n` vb.); bu durumda full scan riski var (filtre varken `IOC_LIST_MAX_AGE_DAYS` ile sınırlı).

Basit “tek satır var mı?” sorgusu API’de yok; endpoint her zaman sayfalı liste döner. Minimal path tek bir index-friendly `SELECT` atar, gruplamayı Node’da yapar.

---

## 5. Generic Arama ve Yavaş Sorgular

- **ILIKE '%...%'** sadece prefiks/hash olmayan serbest metin aramasında kullanılıyor; index kullanımı sınırlı.
- **Full table scan** filtre varken `created_at > now() - interval '1 day' * N` ile sınırlandı (`IOC_LIST_MAX_AGE_DAYS`, varsayılan 365).
- **Wildcard / full text:** Sadece ILIKE ve note regex; özel full-text index yok.

---

## 6. Connection Pool ve Bağlantı

- **pg.Pool** kullanılıyor; her istekte **yeni `Client` açılmıyor**, bağlantı pool’dan alınıyor.
- `IOC_LIST_TIMING=1` iken **connection süresi** ayrı ölçülür: `pool.connect()` ile bir client alınıp tüm istek boyunca kullanılır, süre loglanır, `finally` ile release edilir.
- İlk istek 9 sn, ikinci 3.5 sn ise olasılıklar:
  - İlk istek: **cold start** (Node/container), **ilk TCP/TLS** veya **DNS**.
  - İkinci istek: Hâlâ yavaşsa **sorgu** veya **proxy/network**; timing loglarındaki **connection** ve **query** değerleriyle netleştirilir.

---

## 7. JSON ve Veri Boyutu

- Yanıt: `{ items: [...], pagination: { page, page_size, total, total_pages } }`.
- Sayfa boyutu varsayılan 5, en fazla 100; **serialize** süresi normalde düşük olmalı.
- Çok büyük **items** (çok satır veya çok büyük `source_names`/`category_set`) **serialize** ve **send** süresini artırır; timing’de görülür.

---

## 8. Performans Önerileri (Hedef &lt;200 ms)

1. **Timing’i aç:** `IOC_LIST_TIMING=1` ile **connection / query / map / serialize / send** değerlerine bak; gecikmenin hangi aşamada olduğunu tespit et.
2. **Minimal hash path:** Hash-only aramada (sha256:/md5:/sha1:, asn/country yok) `IOC_LIST_MINIMAL_HASH_PATH=1` kullan: tek `SELECT` + Node’da gruplama, CTE ve geo join yok.
3. **Pool ayarı:** Connection süresi yüksekse pool size ve DB bağlantı limitini kontrol et; ilk bağlantıyı uygulama açılışında ısıtmak (dummy query) faydalı olabilir.
4. **Sorgu planı:** `query` süresi yüksekse aynı SQL’i psql’de `EXPLAIN (ANALYZE, BUFFERS)` ile çalıştır; index (örn. 024 migration) ve istatistik (ANALYZE) kontrol et.
5. **Proxy / network:** **send** yüksekse reverse proxy, TLS veya ağ gecikmesi araştırılmalı.

---

## 9. Özet Tablo

| Konu | Durum |
|------|--------|
| Endpoint | `GET /api/ioc/list` |
| Pool | `pg.Pool`, yeni Client/request yok |
| Sorgu sayısı | 1 (veya boş sayfada 2) |
| sha256:/md5:/sha1: | Parse + exact match (observable + note expr) |
| Generic ILIKE | Sadece prefiks yokken; max age ile sınırlı |
| Timing | `IOC_LIST_TIMING=1` veya `?timing=1` → searchStringParse, dbConnectionAcquired, dbQuery, countQuery, resultMapping, jsonSerialization, responseSent |
| Hash-only path | Varsayılan: tek SELECT + JS gruplama (queries=1). CTE için `IOC_LIST_USE_CTE_FOR_HASH=1` |

---

## 10. Gecikme kaynağı ve 200 ms hedefi

- **Hash-only (sha256:/md5:/sha1:):** Exact match kullanılır; varsayılan path tek `SELECT` + Node gruplama. **COUNT(*) ayrı çalışmaz.** JOIN yok (geo atlanır). DB ~2 ms ise toplam birkaç 10 ms mertebesinde olmalı.
- **Pool:** `pg.Pool` kullanılıyor; her istekte yeni connection açılmıyor.
- **ILIKE / full scan:** Sadece prefiks olmayan aramada; hash prefiksi varken kullanılmaz.
- **3 sn görülüyorsa:** `?timing=1` ile bir arama yapıp log’taki **dbQuery**, **dbConnectionAcquired**, **responseSent** değerlerine bakın. **path=minimalHash** ve **queries=1** görünmüyorsa eski deploy veya farklı path; **dbQuery** düşük ama **total** yüksekse gecikme Node dışında (proxy, ağ, DNS).

---

## 11. Bottleneck analizi ve 200–500 ms hedefi

### Timing ile bottleneck’i bulma

`?timing=1` ile bir istek atın; log’taki değerlere göre:

| Log’ta görünen | Olası bottleneck | Yapılacak |
|-----------------|------------------|-----------|
| **path=cte** veya **queries=2** | Hash aramada hâlâ CTE/COUNT kullanılıyor | Son deploy’u kontrol et; hash-only için minimal path varsayılan olmalı |
| **dbConnectionAcquired** &gt; 500 ms | Pool veya ilk DB bağlantısı | Pool size, DB limit; uygulama açılışında `SELECT 1` ile ısıtma |
| **dbQuery** &gt; 100 ms | Sorgu veya plan | Aynı SQL’i DB’de EXPLAIN (ANALYZE); index/ANALYZE |
| **resultMapping** veya **jsonStringify** yüksek | Çok satır veya büyük nesne | **responseBytes**’a bakın; sayfa boyutunu 5–25 ile sınırlayın |
| **responseBytes** &gt; 100 KB | Büyük JSON | Gereksiz alanları kaldırın; sayfa boyutu küçültün |
| **responseSent** &gt; 1 s, **total** ~ 3 s, diğerleri düşük | Gecikme Node sonrası | Reverse proxy, TLS, ağ, tarayıcı; Node tarafında yapılacak az |

### Endpoint’teki sorgu sayısı ve tipleri

- **Hash-only (varsayılan):** 1 SELECT (exact match). COUNT yok, JOIN yok, enrichment/source için ek sorgu yok.
- **CTE path:** 1 list sorgusu; boş sayfada +1 COUNT. JOIN sadece asn/country varken (geo).

### ILIKE / wildcard / full scan

- **sha256:/md5:/sha1:** Parse edilip exact match; ILIKE/wildcard kullanılmıyor.
- **Serbest metin:** `observable ILIKE '%...%'`, `source_name ILIKE '%...%'` vb.; full scan riski, `IOC_LIST_MAX_AGE_DAYS` ile sınırlı.

### JSON boyutu

- Log’ta **responseBytes** yazılıyor. 50–200 KB normal; &gt; 500 KB ise sayfa boyutunu veya dönen alanları azaltın.
- **jsonStringify** süresi log’ta; yüksekse büyük payload veya çok sayıda öğe.

### Node tarafında CPU yoğun noktalar

- **resultMapping:** Gruplama (byKey loop) + slice + map; satır sayısı çok değilse (&lt; 500) genelde &lt; 10 ms.
- **jsonStringify:** Tek seferde stringify (timing açıkken); **responseBytes** büyükse burada zaman artar.
- Gereksiz veri: Sadece listelenen kolonlar çekiliyor; ek enrichment sorgusu yok.

### Özet: Gecikmenin en büyük kaynağı

1. **Log’ta total ~ 3 s, dbQuery ~ 2–10 ms ise** → Gecikme büyük ölçüde **Node dışında**: reverse proxy, TLS, ağ gecikmesi, tarayıcı. Node’da ek optimizasyonla 200–500 ms’e inmek zor; proxy/network tarafını iyileştirin veya doğrudan backend’e (proxy atlamadan) test edin.
2. **dbConnectionAcquired yüksek** → Pool/ilk bağlantı; startup’ta bağlantı ısıtma, pool ayarı.
3. **dbQuery yüksek** → Sorgu/plan/index; DB tarafında iyileştirme.
4. **responseSent yüksek, diğerleri düşük** → Yanıt yazma/ağ; payload küçültme, proxy/network incelemesi.

**Hedef 200–500 ms:** Minimal path + index’li sorgu + küçük payload ile Node tarafı birkaç 10 ms olabilir. Tarayıcıda 2–3 sn görülüyorsa fark proxy/ağ/tarayıcıdadır; backend log’undaki **total** ile tarayıcı süresini karşılaştırın.

Bu doküman `docs/ioc-performance-improvements.md` ve `docs/sql-scale-20m.md` ile birlikte kullanılabilir.
