# Risk Engine Analytics

Bu doküman, backend tarafındaki merkezi risk engine’in **incident risk** ve **institution risk** hesaplama mantığını açıklar.

- Kod kaynağı: `backend/lib/riskEngine.js`
- Incident endpointleri: `GET /api/incidents`, `GET /api/incidents/:id`
- Institution endpointi: `GET /api/risk/overview`

---

## 1) Tasarım hedefleri

1. Tek hesaplama kaynağı (merkezi modül)
2. Deterministic ve explainable skorlar
3. Tüm skorlar 0–100 aralığında bounded
4. Incident ve institution katmanlarının birbirinden ayrık ama tutarlı olması

---

## 2) Incident Risk (`calculateIncidentRisk`)

Fonksiyon girişte incident benzeri bir obje bekler (ör. `total_hits`, `event_count`, `asset_count`, `last_seen`, `verdict`, `confidence`).

### 2.1 Özel durum kuralları

- **False Positive (FP)** → skor doğrudan `0`
- **Security Test** tespit edilirse → düşük sabit skor (`8`)
  - Tespit, verdict veya metin alanlarında anahtar kelime eşleşmesine göre yapılır (örn. `eicar`, `security test`, `red team`, `simulation`)

### 2.2 Bileşenler

Normal akışta skor şu sinyallerden oluşur:

- **Activity signal** (0–45)
  - Kaynak: `total_hits`
  - Log-scale normalize edilir
- **Spread signal** (0–25)
  - Kaynak: `max(event_count, asset_count)`
  - Log-scale normalize edilir
- **Recency signal** (0–20)
  - Kaynak: `last_seen`
  - Üssel decay ile yeni olaylar daha yüksek etki verir
- **Confidence signal** (0–10)
  - Kaynak: `confidence` (`high`, `medium`, `low`, unknown)
- **Verdict boost** (0–8)
  - TP / Suspicious / In Progress için ek katkı

### 2.3 Final

- Ham skor = bileşenlerin toplamı
- Final skor = `clamp(raw, 0, 100)`
- Response’a:
  - `risk_score`
  - `risk_breakdown`

`risk_breakdown` içinde bileşen katkıları, normalize değerler ve ham input alanları döndürülür.

---

## 3) Institution Risk (`calculateInstitutionRisk`)

Amaç: Tüm aktif incident’ları dahil ederek kurum seviyesinde tek skor üretmek.

### 3.1 Girdi

Fonksiyon incident listesi alır ve listedeki mevcut `risk_score` değerlerini kullanır.

> Not: `GET /api/risk/overview` akışında incident’lar önce `calculateIncidentRisk` ile skorlanır, sonra institution hesaplamaya verilir.

### 3.2 Katkı modeli (non-linear)

Her incident için:

1. `risk_score` → `[0,100]` clamp
2. normalize: `r = risk_score / 100`
3. non-linear katkı: `c = r^2`

Toplam ham katkı:

- `total_raw_contribution = Σ c`

Damping (çok sayıda düşük riskin lineer şişirmesini engellemek için):

- `normalized_input = total_raw_contribution / sqrt(active_incident_count)`

### 3.3 0–100 normalizasyon

Exponential normalization:

- `institution_risk_score = 100 * (1 - exp(-lambda * normalized_input))`
- Varsayılan: `lambda = 2.4`
- Final değer 0–100 clamp edilir

### 3.4 Breakdown

Response breakdown alanı en az şunları içerir:

- `active_incident_count`
- `total_raw_contribution`
- `normalized_contribution_input`
- `institution_risk_score` (üst seviyede)
- `top_contributing_incidents`

---

## 4) Endpoint davranışı

### `GET /api/incidents`

Her item için:

- `risk_score`
- `risk_breakdown`

alanları backend tarafında eklenir.

### `GET /api/incidents/:id`

Tek incident için:

- `risk_score`
- `risk_breakdown`

alanları eklenir.

### `GET /api/risk/overview`

Kurum çıktısı:

- `institution_risk_score`
- `active_incident_count`
- `top_contributing_incidents`
- `breakdown`

---

## 5) Tuning notları

Risk motoru parametreleri (ör. sinyal ağırlıkları, decay süresi, `lambda`) kod içinde açık ve merkezi tanımlıdır.

Gelecekte tuning yapılırken:

1. Önce staging veri üzerinde dağılım gözlemlenmeli
2. Sonra küçük adımlarla ağırlıklar güncellenmeli
3. Dashboard trendlerinde ani sıçrama/çöküş kontrol edilmeli

---

## 6) Değişiklik ilkesi

- DB schema değiştirilmeden çalışır
- API formatı korunur (ek alanlarla genişler)
- Eski SQL içi risk formülleri kullanılmaz
- Tek kaynak: `backend/lib/riskEngine.js`
