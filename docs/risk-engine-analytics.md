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
4. Workflow status ile risk state’in ayrılması (institution risk için)

---

## 2) Incident Risk (`calculateIncidentRisk`)

Fonksiyon girişte incident benzeri bir obje bekler (örn. `total_hits`, `event_count`, `asset_count`, `last_seen`, `verdict`, `confidence`).

### 2.1 Özel durum kuralları

- **False Positive (FP)** → skor doğrudan `0`
- **Security Test** tespit edilirse → düşük sabit skor (`8`)
  - Tespit, verdict veya metin alanlarında anahtar kelime eşleşmesine göre yapılır (örn. `eicar`, `security test`, `red team`, `simulation`)

### 2.2 Bileşenler

Normal akışta skor şu sinyallerden oluşur:

- **Activity signal** (0–45) — `total_hits` log-scale
- **Spread signal** (0–25) — `max(event_count, asset_count)` log-scale
- **Recency signal** (0–20) — `last_seen` ile üssel decay
- **Confidence signal** (0–10) — `high/medium/low/unknown`
- **Verdict boost** (0–8) — TP / Suspicious / In Progress

### 2.3 Final

- Ham skor = bileşenlerin toplamı
- Final skor = `clamp(raw, 0, 100)`
- Response’a eklenen alanlar:
  - `risk_score`
  - `risk_breakdown`

---

## 3) Institution Risk (`calculateInstitutionRisk`)

Amaç: kurum riskini sadece workflow `open` durumuna bağlamadan hesaplamak.

### 3.1 Dataset ve status ayrımı

`GET /api/risk/overview` dataset’i, match’i olan incident’ları içerir (open + closed). Institution katkısı statüye göre ayrıştırılır:

- **FP** → contribution `0` (exclude)
- **Security Test** → `0` veya çok düşük katkı
- **Open** → normal contribution
- **Closed + TP/Suspicious** → zaman bazlı decay ile contribution
- **Closed + düşük risk state** → exclude

Bu sayede analyst workflow kapanışı ile gerçek risk etkisi tamamen eşitlenmez.

### 3.2 Katkı modeli (non-linear)

Temel katkı:

1. `risk_score` clamp `[0,100]`
2. normalize: `r = risk_score / 100`
3. base contribution: `c = r^2`

Closed-risk kayıtlar için:

- `c_closed = c * decay(t)`
- `decay(t)` deterministic exponential decay (kapanışa referans zamanından itibaren)

### 3.3 Agregasyon ve normalizasyon

- `total_raw_contribution = open_contribution + closed_decaying_contribution`
- Damping: `normalized_input = total_raw_contribution / sqrt(contributing_count)`
- Final: `institution_risk_score = 100 * (1 - exp(-lambda * normalized_input))`
- Sonuç 0–100 clamp

### 3.4 Breakdown

Institution breakdown alanları:

- `active_incident_count`
- `total_raw_contribution`
- `open_incident_contribution`
- `closed_decaying_contribution`
- `excluded_incident_count`
- `normalized_contribution_input`
- `top_contributing_incidents`

---

## 4) Truncation Guard (`/api/risk/overview`)

Risk overview dataset’i performans için limitlidir (`LIMIT 1000`). Sessiz eksik hesaplama riskini önlemek için response şeffaflık alanları içerir:

- `active_incident_count` (hesaplamaya giren satır)
- `total_active_incidents` (COUNT query sonucu)
- `data_truncated` (partial dataset flag)

`data_truncated = true` ise frontend uyarı gösterir:

> "Risk score is calculated on a partial dataset"

---

## 5) Endpoint davranışı

### `GET /api/incidents`

Her item için:

- `risk_score`
- `risk_breakdown`

### `GET /api/incidents/:id`

Tek incident için:

- `risk_score`
- `risk_breakdown`

### `GET /api/risk/overview`

Kurum çıktısı:

- `institution_risk_score`
- `active_incident_count`
- `total_active_incidents`
- `data_truncated`
- `top_contributing_incidents`
- `breakdown`

---

## 6) Değişiklik ilkesi

- DB schema değiştirilmeden çalışır
- Eski SQL içi risk formülleri kullanılmaz
- Tek kaynak: `backend/lib/riskEngine.js`
- Hesaplama explainable ve modüler tutulur
