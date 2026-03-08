# import_dedup tablosu – kullanım analizi

## 1. Tabloya referans veren tüm yerler

| Dosya | Satır | Kullanım türü |
|-------|-------|----------------|
| `backend/migrations/001_core.sql` | 46–51 | **CREATE TABLE** – şema tanımı |
| `db/init/003_integration.sql` | 22–27 | **CREATE TABLE** – init şema (tekrar) |
| `integration/importer.js` | 235–239 | **INSERT** – `insertIoc()` içinde |
| `integration/importer.js` | 268 | Yorum – “import_dedup kullanılmaz” (batchInsertIocs için) |
| `integration/importer.js` | 321–325 | **INSERT** – `insertObservable()` içinde |
| `docs/ioc-performance-improvements.md` | 36 | Dokümantasyon – ET feed’in import_dedup kullanmadığı |

---

## 2. SQL kullanımları

### 2.1 INSERT (aktif)

**Yer:** `integration/importer.js`

- **insertIoc:**  
  `INSERT INTO import_dedup (source_name, external_id) VALUES ($1, $2) ON CONFLICT (source_name, external_id) DO NOTHING RETURNING source_name`  
  → **insertIoc hiçbir yerde çağrılmıyor** (ölü kod).

- **insertObservable:**  
  Aynı SQL, `insertObservable()` içinde.  
  → **Aktif:** USOM, URLhaus, ThreatFox, MalwareBazaar feed’leri bu fonksiyonu kullanıyor.

### 2.2 SELECT

- Repo genelinde **import_dedup** üzerinde **SELECT yok**.  
  Dedup mantığı: önce `import_dedup`’a INSERT; conflict olursa `RETURNING` boş döner, `rowCount === 0` ile “zaten işlendi” anlaşılır ve `ioc_items` INSERT’i atlanır.

### 2.3 DELETE / cleanup

- **import_dedup** için **DELETE**, **TRUNCATE** veya cleanup job **yok**.  
  Tablo sürekli büyür (unbounded growth).

---

## 3. Hangi dosyalar bu tabloyu kullanıyor?

- **Backend migration:** `backend/migrations/001_core.sql` – tabloyu oluşturur.
- **DB init:** `db/init/003_integration.sql` – aynı tabloyu init senaryosunda oluşturur.
- **Aktif uygulama kodu:** sadece **`integration/importer.js`** (INSERT, iki fonksiyonda; biri ölü).

---

## 4. Hangi akışta kullanılıyor?

| Akış | Kullanım | Açıklama |
|------|----------|----------|
| **Feed ingestion (IOC import pipeline)** | Evet, aktif | USOM, URLhaus, ThreatFox, MalwareBazaar tek tek `insertObservable()` ile ekleme yapıyor; her kayıt öncesi `import_dedup`’a INSERT (ON CONFLICT DO NOTHING) ile “bu external_id bu source için daha önce işlendi mi?” kontrolü. |
| **Deduplication logic** | Evet | Aynı (source_name, external_id) ikinci kez gelirse `import_dedup` INSERT conflict olur, `ioc_items` INSERT’i yapılmaz. |
| **EmergingThreats (ET) feed** | Hayır | ET, `batchInsertIocs()` kullanıyor; dokümana göre “import_dedup kullanılmaz”, dedup `WHERE NOT EXISTS` ile yapılıyor. |
| **Migration** | Sadece CREATE | `001_core.sql` ve `003_integration.sql` – tablo tanımı. |
| **Test kodu** | Hayır | Repoda test içinde `import_dedup` kullanımı yok. |
| **insertIoc** | Ölü kod | `insertIoc()` tanımlı ama hiçbir yerden çağrılmıyor; dolayısıyla buradaki `import_dedup` INSERT’i fiilen çalışmıyor. |

---

## 5. Özet: Amaç, aktif mi, silmek güvenli mi?

### Amaç

- **Import deduplication:** Aynı feed’den aynı “external_id” (ör. `observableType|observable|sourceName|confidence|...` composite key) ikinci kez geldiğinde tekrar `ioc_items`’a yazmamak.  
- İlk işlemede: `import_dedup`’a satır eklenir, sonra `ioc_items` (ve gerekirse `ioc_observables`) güncellenir.  
- Aynı key tekrar gelince: `import_dedup` INSERT conflict olur, `rowCount === 0` ile `ioc_items` atlanır.

### Aktif mi, legacy mi?

- **Aktif.**  
  USOM, URLhaus, ThreatFox, MalwareBazaar feed’leri `insertObservable()` üzerinden **import_dedup**’ı kullanıyor.  
- **insertIoc** ve onun **import_dedup** kullanımı **legacy/ölü**: fonksiyon hiç çağrılmıyor.

### Silinmesi güvenli mi?

- **Hayır.**  
  Tabloyu veya ilgili INSERT’i kaldırırsanız:
  - `insertObservable()` içindeki `INSERT INTO import_dedup` başarısız olur veya tablo yoksa hata alırsınız.
  - USOM, URLhaus, ThreatFox, MalwareBazaar import’ları bozulur.

**Güvenli silmek için:** Bu dört feed’i de ET gibi `batchInsertIocs` (veya benzeri idempotent batch) pattern’ine geçirip, `insertObservable()` ve dolayısıyla **import_dedup** bağımlılığını kaldırmanız gerekir. O zamana kadar tablo **dead table değil**, **aktif kullanımda**.

---

## 6. Ek notlar

- **Cleanup:** `import_dedup` için hiçbir DELETE/TRUNCATE/retention job yok; tablo süresiz büyür. İleride retention/cleanup eklenebilir.
- **insertIoc:** İsterseniz refactor’ta kaldırılabilir; şu an hiçbir akışı etkilemez, sadece **import_dedup** ile birlikte ölü kod.
