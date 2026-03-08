# IOC Search Endpoint Analizi

Bu doküman `GET /api/ioc/list` endpoint'ini, gecikme kaynaklarını ve performans önerilerini özetler.

---

## 1. Endpoint

- **Route:** `GET /api/ioc/list`
- **Query params:** `q`, `source_name`, `confidence`, `asn`, `country`, `page`, `page_size`
- **Kullanım:** IOC List sayfasındaki arama kutusu (`sha256:...`, `md5:...`, serbest metin vb.)

---

## 2. Timing Logları

`IOC_LIST_TIMING=1` ile aşağıdaki aşamalar loglanır (ms):

| Aşama | Açıklama |
|--------|----------|
| **parse** | İstek alındı → search string parse edildi (prefixed hash / generic) |
| **connection** | Pool'dan connection alınması (sadece timing açıkken `pool.connect()` kullanılır) |
| **query** | Ana list sorgusu (CTE veya minimal path) |
| **countQuery** | Boş sayfa durumunda ek COUNT sorgusu |
| **map** | `listRes.rows.map(...)` ile satırların işlenmesi |
| **serialize** | Payload hazırlama |
| **send** | `res.json()` ile yanıt gönderilmesi |
| **total** | İstek başından yanıt bitene kadar toplam süre |

Örnek log:
```
[ioc/list timing] parse=0ms connection=2ms query=5ms map=0ms serialize=1ms send=3ms total=11ms fastPath q=sha256:68274...
```

**Gecikme nerede?**
- **connection** yüksek → Pool dolu veya DB bağlantı gecikmesi (ilk istek 9 sn ise cold start / DNS / TCP).
- **query** yüksek → Sorgu veya plan ağır; EXPLAIN ANALYZE ile kontrol et.
- **map** / **serialize** yüksek → Çok satır veya büyük JSON.
- **send** yüksek → Ağ veya proxy.

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

## 4. Search Logic: Exact Match (sha256:/md5:/sha1:)

- Arama `sha256:xxxx`, `md5:xxxx`, `sha1:xxxx` formatındaysa **parse edilip** exact match kullanılıyor:
  - `observable_type = $1 AND LOWER(observable) = $2`
  - Veya note içinden hash çıkaran expression (örn. `sha256=` ile) = `$2`
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
| Timing | `IOC_LIST_TIMING=1` → parse / connection / query / map / serialize / send |
| Hash-only path | Varsayılan: tek SELECT + JS gruplama. CTE için `IOC_LIST_USE_CTE_FOR_HASH=1` |

Bu doküman `docs/ioc-performance-improvements.md` ve `docs/sql-scale-20m.md` ile birlikte kullanılabilir.
