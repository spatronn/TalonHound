# SQL Tarafında 20M IOC Ölçek Notları

~1.5M’den ~20M satıra çıkarken kullanılan index’ler, uygulama davranışı ve bakım önerileri.

---

## 1. Migration 021 (indexler ve istatistik)

**Dosya:** `backend/migrations/021_ioc_scale_20m.sql`

| Index | Amaç |
|-------|------|
| `idx_ioc_ip_geo_cache_asn` | List filtre (asn/country) join’inde ASN üzerinden hızlı erişim |
| `idx_ioc_items_observable_where_ip` | Sadece IP satırları; geo refresh ve IP lookup’ta daha küçük index |
| `idx_ioc_items_created_at_desc_covering` | List default path: Index Only Scan, heap’e gitmeden sayfa |
| `idx_ioc_items_source_created_at_desc` | Filtre: source_name + son eklenenler |
| `idx_ioc_items_confidence_created_at_desc` | Filtre: confidence + son eklenenler |

Ayrıca `ioc_items` için `observable`, `source_name`, `created_at` kolonlarında `STATISTICS` artırıldı; 20M’da planlayıcı tahminleri iyileşir. Migration sonunda `ANALYZE ioc_items` ve `ANALYZE ioc_ip_geo_cache` çalıştırılır.

---

## 2. List API: Filtre varken “son N gün” sınırı

Filtre (source_name, confidence, q, asn, country) varken eskiden tüm tablo taranıyordu; 20M’da bu çok ağır.

**Yapılan:** Filtre varken artık sadece **son 365 gün** (varsayılan) kullanılıyor:  
`WHERE created_at > now() - interval '1 day' * N`

- **Ortam değişkeni:** `IOC_LIST_MAX_AGE_DAYS` (varsayılan 365; min 30, max 3650).
- Filtre yokken davranış değişmez: hâlâ “son 2000 kayıt” (created_at DESC LIMIT 2000).

Böylece filtreli listeler 20M üzerinde full scan yapmaz, created_at index’i ile sınırlı satır taranır.

---

## 3. Geo cache refresh

`refreshGeoCache` ioc_items’dan “cache’te olmayan IP’leri” buluyor. 20M’da:

- `idx_ioc_items_observable_where_ip` sadece IP satırlarına bakmayı hızlandırır.
- Limit zaten var (`GEO_CACHE_REFRESH_LIMIT`); local’de düşük tutulabilir.
- Gerekirse refresh’i daha seyrek veya sadece “son eklenen” IP’lere odaklayacak şekilde (örn. `created_at > last_run`) daraltabilirsin.

---

## 4. Bakım ve ayarlar

- **ANALYZE:** Büyük toplu insert’lerden sonra `ANALYZE ioc_items;` çalıştır. Migration 021 zaten ekliyor; periyodik (cron) de eklenebilir.
- **Autovacuum:** 20M satırda `autovacuum_vacuum_scale_factor` / `autovacuum_analyze_scale_factor` düşürülebilir; böylece vacuum/analyze daha sık ama kısa sürede biter.
- **Index boyutu:** `idx_ioc_items_observable_trgm` ve `idx_ioc_items_source_trgm` (GIN pg_trgm) büyük olur. Sadece “arama” gerçekten kullanılıyorsa tut; değilse veya “son N gün” ile sınırlı arama yeterliyse kaldırıp yerine (created_at, observable) gibi daha dar index düşünülebilir.

---

## 5. İsteğe bağlı: Partitioning

20M’dan sonra büyüme devam edecekse, uzun vadede **created_at ile partition** (aylık/yıllık) düşünülebilir:

- Eski partition’lar ayrı tutulup arşivlenebilir veya silinebilir.
- Sorgular `created_at` ile sınırlı olduğu için partition pruning kullanılır.
- Migration ve uygulama değişikliği gerektirir; ihtiyaç halinde ayrı tasarlanmalı.

---

## Özet

| Konu | Yapılan / Öneri |
|------|------------------|
| Index’ler | Migration 021: geo asn, IP-only partial, list covering, source/confidence+created_at |
| İstatistik | ioc_items için statistics artırıldı, ANALYZE eklendi |
| List filtre | Filtre varken son N gün (IOC_LIST_MAX_AGE_DAYS, varsayılan 365) |
| Geo refresh | IP partial index ile hızlanır; limit/env ile kontrol |
| Bakım | ANALYZE periyodik; autovacuum ayarı; GIN index’leri gözden geçir |
| Partitioning | İleride ihtiyaç halinde created_at ile partition |

Bu doküman `docs/ioc-performance-improvements.md` ve `docs/container-operations-and-tuning.md` ile birlikte kullanılabilir.
