# IOC Performans İyileştirme Noktaları

Bu doküman, özellikle **yeni IOC eklendiğinde** ve **local / kısıtlı ortamda** yaşanan performans sorunları için iyileştirme alanlarını özetler.

---

## 1. Yeni IOC eklerken (POST /api/ioc/ip)

**Sorun:** Her eklemede `refreshGeoCache(1000)` tetikleniyor. Bu sorgu:
- `ioc_items` ile `ioc_ip_geo_cache` arasında LEFT JOIN
- Eksik IP’ler için `asn_ipv4_ranges` ile LATERAL join
- Limit 1000 olsa bile local’de hissedilir gecikme yapabiliyor

**Öneriler:**
- **Uygulandı:** Geo refresh **debounce** edildi; tek eklemede hemen büyük refresh yerine kısa gecikmeyle tek seferde çalışıyor, limit ortam değişkeni ile düşürülebilir.
- İsteğe bağlı: Sadece eklenen tek IP için hafif bir “single IP geo lookup” ile cache’i anında doldurmak (opsiyonel, daha fazla kod).

---

## 2. IOC listesi (GET /api/ioc/list)

**Sorun:**
- Filtre yokken bile **2000 satır** `ioc_items`’dan alınıp CTE içinde gruplanıyor.
- **Count** ve **list** için aynı büyük CTE iki kez çalışıyordu (Promise.all ile paralel ama her ikisi de ağır).

**Uygulandı:** Tek sorguda hem sayfa hem toplam: `COUNT(*) OVER()` ile window count; sonuç satırlarında `total` dönüyor. Sadece **boş sayfa** (0 satır) döndüğünde total için ayrı count sorgusu çalışıyor. Böylece normal kullanımda ağır CTE bir kez çalışıyor.

---

## 3. Integration bulk import (ET / USOM / URLhaus vb.)

**Sorun:** Integration worker’da her IP/observable için 2 round-trip (dedup + insert); binlerce IOC’de çok yavaştı.

**Uygulandı (ET feed):** `batchInsertIocs(client, entries, 'ip')` eklendi. EmergingThreats feed’i artık IP’leri **chunk’lar halinde** (varsayılan 150, `IOC_BATCH_INSERT_CHUNK` ile 50–500) tek sorguda ekliyor: `INSERT INTO ioc_items ... SELECT FROM (VALUES ...) WHERE NOT EXISTS (...)` ile idempotent. ET için `import_dedup` kullanılmıyor (aynı feed tekrar çalışırsa duplicate’lar INSERT’te eleniyor). USOM/URLhaus/ThreatFox vb. hâlâ tek tek `insertObservable` kullanıyor; ileride aynı batch pattern uygulanabilir.

---

## 4. Geo cache refresh (startup + periyodik)

**Sorun:**
- Startup’ta `refreshGeoCache(100000)`.
- Her 60 saniyede `refreshGeoCache(20000)`.
- Local’de bellek ve CPU kısıtlıysa bu sorgular sistemi zorlayabilir.

**Öneriler:**
- **Uygulandı:** Backend aşağıdaki ortam değişkenlerini kullanıyor (local’de daha düşük limit, daha seyrek aralık):
  - `GEO_CACHE_REFRESH_LIMIT` — periyodik ve startup’taki refresh limiti (varsayılan 20000)
  - `GEO_CACHE_REFRESH_INTERVAL_MS` — periyodik refresh aralığı ms (varsayılan 60000)
  - `GEO_CACHE_ON_ADD_LIMIT` — yeni IOC ekledikten sonra debounce ile çalışan refresh limiti (varsayılan 500)
  - `GEO_CACHE_DEBOUNCE_MS` — yeni IOC sonrası refresh’i ne kadar geciktireceği ms (varsayılan 2000)
- Örnek local `.env` (hafif yük):
  - `GEO_CACHE_REFRESH_LIMIT=500`
  - `GEO_CACHE_REFRESH_INTERVAL_MS=300000`
  - `GEO_CACHE_ON_ADD_LIMIT=200`
  (5 dakikada bir 500 IP; IOC ekleyince 2 sn sonra en fazla 200 IP)

---

## 5. Dashboard map worker

**Mevcut:** Chunk’larla (varsayılan 1000) işliyor; `DASHBOARD_MAP_CHUNK_SIZE` ve `DASHBOARD_MAP_INTERVAL_MS` zaten var.

**Öneri:** Local’de chunk size’ı 200–500, interval’i 10–15 saniye yaparak hem bellek hem CPU’yu yumuşatmak. Yoğun IOC eklemesi sonrası tam rebuild süresi uzayabilir ama tek seferde yük azalır.

---

## 6. Veritabanı indeksleri

**Mevcut:**  
- `uq_ioc_items_dedup` (observable, observable_type, source_name, confidence, category, source_url)  
- `idx_ioc_items_created_at_desc`, `idx_ioc_items_observable`, `idx_ioc_items_observable_type_observable`  
- `idx_ioc_items_observable_trgm`, `idx_ioc_items_source_trgm` (pg_trgm)
- `idx_ioc_items_sha256_from_note` vb. (022) — note içinden hash
- `idx_ioc_items_sha256_lower_observable` vb. (024) — sha256/sha1/md5 prefiksli aramada `LOWER(observable)` path

**Öneri:** Yeni composite index’e gerek yok; mevcut indeksler duplicate check ve sıralama için yeterli. İleride sadece ASN/country filtreli list sorguları çok artarsa `ioc_ip_geo_cache(asn)`, `(country_code)` üzerinde index düşünülebilir.

---

## Özet (öncelik sırasıyla)

| Öncelik | Alan              | Yapılacak / Yapılan |
|--------|--------------------|----------------------|
| 1      | IOC ekleme         | Geo refresh debounce + düşük limit (env) ✅ |
| 2      | Geo refresh        | Startup/interval limit ve süre env ile ayarlanabilir ✅ |
| 3      | IOC list           | Tek sorguda count + sayfa (COUNT(*) OVER()); boş sayfada ayrı count ✅ |
| 4      | Bulk import        | ET feed için batch INSERT (IOC_BATCH_INSERT_CHUNK) ✅ |
| 5      | Map worker         | Local’de CHUNK_SIZE ve INTERVAL env ile oynanabilir |

Bu doküman, `docs/container-operations-and-tuning.md` ile birlikte kullanılabilir; container ayarları orada, IOC tarafı burada toplanmıştır.
