# IOC Exposure & Impact Scoring

Bu doküman, backend’deki merkezi skorlama motorunun **güncel** davranışını açıklar. Kod kaynağı: `backend/lib/riskEngine.js`.

API alan adları tarihsel olarak `risk_score` / `institution_risk_score` kullanır; ürün dili olarak bunlar **Exposure Score** / **IOC Impact Score** olarak düşünülmelidir — kesin “kurum riski” veya “hacklendi” iddiası değildir.

**İlgili kod ve veri:**

| Bileşen | Dosya |
|---------|--------|
| Merkezi skor motoru | `backend/lib/riskEngine.js` |
| Event aggregate SQL | `backend/lib/incidentEventAggSql.js` |
| AI advisory delta | `backend/risk/llmRiskAdvisor.js` |
| HTTP endpoint’ler | `backend/server.js` |
| Regresyon testleri | `backend/lib/riskEngine.test.js` (`npm run test:risk`) |

**Endpoint’ler**

| Endpoint | Skor kaynağı |
|----------|----------------|
| `GET /api/incidents` | `calculateIncidentRisk` (base exposure; LLM yok) |
| `GET /api/incidents/:id` | Base + opsiyonel LLM → `risk_score = final_risk_score` |
| `GET /api/risk/overview` | `calculateInstitutionRisk` (incident katkıları; LLM cache varsa final incident skoru kullanılır) |
| `GET /api/risk/trend` | `risk_snapshots` + canlı overview |

Skorlar SQL içinde hesaplanmaz; SQL yalnızca aggregate alanları sağlar.

---

## 1. Ürün konumu

Bu ürün bir **SIEM değildir** ve **threat feed sağlayıcısı değildir**.

- Kurum kendi IOC/threat feed kaynaklarını bağlar.
- Ürün, bu IOC’lerin kurum loglarında **gerçekten iz bırakıp bırakmadığını**, hangi kanıtlarla görüldüğünü ve analist açısından **ne kadar öncelikli** olduğunu gösterir.
- Skor, feed’in dünya çapında “kötülüğünü” ölçmez; feed’in **kurum içi exposure/impact** etkisini ölçmeye çalışır.
- **Yüksek skor ≠ kurum kesinlikle compromise oldu.** Düşük skor ≠ risk yok.
- Skor, bilimsel kesinlik iddiası taşımaz; **açıklanabilir, sınırlı ve analist önceliklendirme** içindir.

---

## 2. Incident-level exposure score (`calculateIncidentRisk`)

### 2.1 Girdi alanları

Fonksiyon, incident benzeri bir obje bekler. Önemli alanlar:

| Alan | Kaynak (tipik) | Rol |
|------|----------------|-----|
| `total_hits` | `ioc_activity.total_hits` | Hacim sinyali (log-scale, tier cap’li) |
| `asset_count` | SQL aggregate (distinct observed hosts) | Yayılım sinyali |
| `accepted_connections` | `match_context.action` ∈ allow kabul | Allowed outcome |
| `blocked_connections` | `match_context.action` ∈ deny/block | Blocked outcome |
| `verdict` | `ioc_activity.verdict` | FP / TP / Suspicious / … |
| `confidence` | Event’lerden BOOL_OR | high / medium / low |
| `ioc_type` | `ioc_activity.ioc_type` | Tier ipucu + bonus |
| `detection_type` | Event aggregate: realtime / retro | +3 / +1 |
| `dominant_source_type`, `dominant_parser_source` | En sık görülen source/parser | Evidence sınıflandırma |
| `has_*_evidence` | SQL BOOL_OR (endpoint/proxy/dns/firewall) | Evidence sınıflandırma |
| `event_summary.source_types` | Detail/AI context (opsiyonel) | Evidence sınıflandırma |

Liste, detail ve institution overview aynı aggregate mantığını kullanır: `IOC_MATCH_EVENT_STATS_SELECT` (`backend/lib/incidentEventAggSql.js`).

### 2.2 Özel durumlar

**False positive (FP)** — `normalizeVerdict` şunların hepsini `FP` yapar: `fp`, `FP`, `false_positive`, `false positive`, `False Positive`.

- `risk_score = 0`
- `risk_breakdown.reason = false_positive`
- Kurum katkısı ve AI delta da 0

**Security test** — verdict veya metin alanlarında `eicar`, `security test`, `red team`, vb.

- Sabit skor: **8**
- `evidence_tier: security_test`

### 2.3 Normal akış formülü

```
evidence_tier = inferEvidenceTier(incident)
evidence_strength = evidenceStrengthLabel(tier)

score = base_score (8)
      + hits_signal      = min(log1p(total_hits) * 3.2, tier_hit_cap)
      + observed_hosts_signal = min(log1p(asset_count) * 8, cap 10 veya 14 endpoint)
      + action_signal    = allowed ? 10 : blocked ? 3 : 0
      + detection_type   = realtime ? 3 : retro ? 1 : 0
      + confidence       = high ? 8 : medium ? 4 : low ? 1 : 0
      + verdict_signal   = TP ? 18 : Suspicious ? 8 : In Progress ? 2 : 0
      + ioc_type_bonus   = sha256 ? 20 : domain|url ? 6 : 2

score = min(score, getLowEvidenceCap(evidence_tier, verdict))  // tier tavanı
score = min(score, 90)
score = clamp(score, 0, 90)
```

**Tier hit cap’leri** (`getHitContribution`): dns_only 10, blocked_only 8, generic/unknown 6, proxy_only 15, proxy_allowed 22, firewall_allowed 20, multi_source 25, endpoint 30.

**Tier skor tavanları** (`getLowEvidenceCap`, TP değilse): dns_only/blocked_only **25**, proxy_only 35, proxy_allowed/firewall_allowed **45**, multi_source 60, endpoint 85. TP için tavan +10 (max 90).

Yanıt: `risk_score`, `risk_breakdown` (aşağıda).

---

## 3. Evidence tier mantığı

`inferEvidenceTier` önce `collectEvidenceSignals` ile kanıt ailesi çıkarır:

- SQL flag’ler: `has_endpoint_evidence`, `has_proxy_evidence`, `has_dns_evidence`, `has_firewall_evidence`
- `dominant_source_type` / `dominant_parser_source`
- Opsiyonel `event_summary.source_types`
- `ioc_type` (ör. hash → endpoint; url → proxy ipucu)

**Önemli:** `ioc_type = domain` tek başına **DNS-only kanıtı anlamına gelmez**. `hasDns` domain IOC için true olabilir; fakat tier `dns_only` yalnızca proxy/firewall kanıtı yokken ve outcome unknown iken seçilir.

### 3.1 Precedence (yüksekten düşüğe)

1. `endpoint_or_file` — endpoint/EDR/hash IOC
2. `proxy_allowed` — `accepted_connections > 0` ve proxy kanıtı
3. `firewall_allowed` — `accepted_connections > 0` ve firewall kanıtı (veya accepted var, diğer aileler zayıf)
4. `multi_source_network` — accepted + (dns veya ≥2 source ailesi veya ≥2 host)
5. `proxy_only` — proxy kanıtı, accepted=0, blocked=0
6. `dns_only` — dns kanıtı, proxy/firewall yok, accepted=0, blocked=0
7. `blocked_only` — blocked>0, accepted=0
8. `generic_only` — unknown metadata + hits + confidence ≠ high
9. `unknown` — unknown metadata

### 3.2 `evidence_strength` etiketleri

| Tier | evidence_strength |
|------|-------------------|
| false_positive | none |
| generic_only, unknown | very_low |
| dns_only, blocked_only | low |
| proxy_only | medium |
| proxy_allowed | medium_high |
| firewall_allowed, multi_source_network | high |
| endpoint_or_file | very_high |

---

## 4. Action outcome

`deriveActionOutcome(accepted, blocked)`:

| Durum | action_outcome | action_signal |
|-------|----------------|---------------|
| `accepted_connections > 0` | `allowed` | +10 |
| sadece `blocked_connections > 0` | `blocked` | +3 |
| ikisi de 0 | `unknown` | 0 |

**Neden allowed daha güçlü?** Allowed proxy/firewall oturumu, IOC ile **kontrol noktasından geçmiş trafik** anlamına gelir; compromise kanıtı sayılmaz ama DNS sorgusundan güçlüdür.

**Blocked-only** — Deneme/visibility değerlidir; kontrol çalışmıştır. Tier `blocked_only`, düşük hit cap ve institution katkı tavanı (~1.0) ile şişirilmez.

**DNS-only** — Çözümleme veya sorgu kanıtıdır; oturum/erişim veya endpoint execution kanıtı değildir. Tier `dns_only`, incident tavanı **25**.

---

## 5. Institution-level exposure score (`calculateInstitutionRisk`)

Kurum skoru, incident’lerin **kalite ağırlıklı katkılarının** kümeleme + doygunluk ile birleşimidir. Incident `risk_score` değeri katkı formülünde doğrudan kare/normalize edilmez; katkı `getInstitutionContribution` ile ayrı hesaplanır.

### 5.1 Incident katkısı (`getInstitutionContribution`)

```
raw = (confidenceWeight + activityWeight + hitFactor + hostSpread + persistence)
      * verdictMultiplier
      + mapAiAdjustmentDelta(llm_risk_adjustment)   // kurumda ±0.25..0.5, incident AI’dan ayrı

// Çeşitli senaryo cap’leri (dns_only, blocked_only, url, ip, …)
raw = min(raw, tier_cap[evidence_tier])

final_contribution = raw * recency_multiplier(last_seen) * decay_factor
```

- **Open** incident: `decay_factor = 1`
- **Closed** incident: `decay_factor = getClosedDecayFactor` — üstel decay, yarı ömür **14 gün** (`updated_at` veya `last_seen`)
- **FP**: katkı 0, bucket `excluded`

`recency_multiplier(last_seen)`: ≤1 gün 1.0; ≤7 gün 0.7; ≤30 gün 0.4; daha eski 0.2.

### 5.2 Kümeleme ve rank

- `cluster_key`: IP IOC → `ip:value`; domain/url → kök domain; diğer → `type:value`
- Küme skoru: `max(contribution) + 0.25 * sum(diğerleri)`
- Kümeler sıralanır; **rank weight**: 1.0, 0.6, 0.35, 0.12 (4–10), 0.03 (11+)
- `weighted_cluster_total` = ağırlıklı küme toplamı
- `density_bonus` = `min(6, log1p(non-FP incident sayısı) * 1.5)` — düşük kalite oranı ≥0.75 ise **yarıya** indirilir

### 5.3 Dampening

```
low_incident_dampening = contributing_count < 5 ? 0.6 : 1

quality_dampening:
  low_quality_ratio ≥ 0.85 → 0.5
  ≥ 0.65 → 0.65
  ≥ 0.50 → 0.8
  else → 1

combined_dampening = low_incident_dampening * quality_dampening
cluster_total = (weighted_cluster_total + density_bonus) * combined_dampening
```

`low_quality` tier’lar: `dns_only`, `blocked_only`, `generic_only`, `unknown`.

### 5.4 Doygunluk (saturation)

```
institution_risk_score = 100 * (1 - exp(-cluster_total / RISK_SCORE_SCALE))
```

`RISK_SCORE_SCALE` env (varsayılan **50**). Sonuç 0–100 clamp.

### 5.5 Güvenlik tavanları

| Koşul | Etki |
|-------|------|
| `strongEvidenceCount === 0` | Skor **≤ 55**; label HIGH/CRITICAL → MEDIUM |
| `low_quality_ratio ≥ 0.85` | Skor **≤ 65** |

`strongEvidenceCount`: verdict TP, veya `accepted_connections > 0`, veya high confidence + ≥2 host, veya tier ∈ {endpoint_or_file, proxy_allowed, firewall_allowed}.

**Neden çok DNS-only/blocked-only kurum skorunu şişirmemeli?** Her biri düşük `tier_cap` (≈0.6–1.0) ile sınırlı; küme diminishing returns ve `quality_dampening` ile toplam katkı sınırlanır; doygunluk eğrisi tek başına 100’e fırlatmaz.

---

## 6. AI adjustment (advisory delta)

AI **ana skor kaynağı değildir**. Akış:

1. `calculateIncidentRisk` → base (`risk_before_llm`)
2. LLM opsiyonel → `llm_risk_adjustment` + `llm_risk_confidence`
3. `final_risk_score = base + effective_delta` (clamp 0–100)

`computeEffectiveAiDelta` (`llmRiskAdvisor.js`):

| Kural | Değer |
|-------|--------|
| `LLM_RISK_ADVISOR_AI_WEIGHT` | Kod varsayılanı **1** (`.env.example` ile uyumlu) |
| `confidence < 0.4` | effective delta **0** |
| Genel clamp | **±10** (`adjustment * confidence * weight`) |
| Düşük tier pozitif delta | `dns_only`, `blocked_only`, `generic_only`, `unknown` → pozitif max **+5** |
| FP verdict | `final_risk_score = 0` (adjustment uygulanmaz) |

Model adjustment seti: `{-20,-10,-5,0,5,10,15,20}`.

**Liste vs detail:** `GET /api/incidents` yalnızca base skor döner. Detail/overview’da cache varsa `risk_score` LLM final olabilir.

**Deploy notu:** `docker-compose.yml` içinde `LLM_RISK_ADVISOR_AI_WEIGHT` varsayılanı hâlâ **3** olabilir; kod varsayılanı 1’dir. Production’da bilinçli override kullanılmalıdır.

LLM worker eşiği: `total_events >= 50` ve `unique_hosts >= 2` (`llmRiskWorker.js`).

---

## 7. Risk breakdown alanları

Incident `risk_breakdown` (additive; UI henüz tüm alanları göstermeyebilir):

| Alan | Anlam |
|------|--------|
| `evidence_tier` | Sınıflandırma kodu (örn. `dns_only`, `proxy_allowed`) |
| `evidence_strength` | İnsan okunur güç etiketi (`low`, `high`, …) |
| `action_outcome` | `allowed` / `blocked` / `unknown` |
| `accepted_connections` | Allow action sayısı |
| `blocked_connections` | Deny/block action sayısı |
| `affected_hosts` | `asset_count` (distinct observed hosts) |
| `total_hits` | Toplam hit |
| `dns_only_dampening` | Tier dns_only ise true (düşük exposure sınıfı) |
| `blocked_only_dampening` | Tier blocked_only ise true |
| `ai_delta_effective` | Incident base hesapta **0**; LLM sonrası `ai_delta_effective` ayrı alanda (detail response) |
| `final_score` | Bu hesaptaki nihai incident skoru (= `risk_score` base path’te) |
| `reason` | Kısa açıklama metni |
| `components.*` | Sayısal bileşenler (hits_signal, verdict_signal, …) |
| `raw.*` | Ham girdiler + `low_evidence_cap`, dominant source |

Institution `breakdown`: `clusters`, `combined_dampening`, `quality_dampening`, `low_quality_ratio`, `strong_evidence_count`, `saturation_formula`, vb.

---

## 8. Örnek senaryolar

### DNS-only domain match

- **Girdi:** `has_dns_evidence`, `dominant_source_type=dns`, accepted=0, blocked=0, yüksek `total_hits`
- **Tier:** `dns_only`
- **Skor:** ≤ **25** (tier cap); hit signal cap 10
- **Neden:** Sadece sorgu/visibility; erişim kanıtı yok

### Blocked-only firewall hit burst

- **Girdi:** `blocked_connections` çok yüksek, accepted=0, `has_firewall_evidence`
- **Tier:** `blocked_only`
- **Skor:** ≤ **25** incident; kurum katkısı tier cap ~**1.0**
- **Neden:** Kontrol çalıştı; compromise değil, attempt görünürlüğü

### Allowed proxy URL access

- **Girdi:** `has_proxy_evidence`, `accepted_connections > 0`, `ioc_type=url`
- **Tier:** `proxy_allowed`
- **Skor:** DNS-only aynı hit’te **daha yüksek** (ör. cap 45 vs 25)
- **Neden:** Ağ kontrol noktasından geçmiş oturum/istek kanıtı

### Multiple internal hosts, same IOC

- **Girdi:** `asset_count` yüksek, proxy_allowed, orta `total_hits`
- **Etki:** `observed_hosts_signal` ve institution `hostSpread` artar
- **Not:** Incident tier cap (45) nedeniyle final skorlar yakınsayabilir; spread bileşeni breakdown’da görülür

### Endpoint / hash evidence

- **Girdi:** `ioc_type=sha256` veya endpoint parser/source
- **Tier:** `endpoint_or_file`
- **Skor:** En yüksek incident tavanları (85, TP ile 90’a kadar)
- **Neden:** Dosya/endpoint kanıtı ağ DNS’inden güçlü kabul edilir

### False positive verdict

- **Girdi:** verdict `false positive` / `FP` / …
- **Skor:** **0**; AI delta **0**
- **Neden:** Analist kararı ile exposure suppress

---

## 9. Limitasyonlar

- Skor **kesin risk ölçümü değildir**; önceliklendirme ve kanıt gücü özetidir.
- Parser/source metadata eksik veya yanlışsa tier yanlış seçilebilir (`generic_only` / `unknown`).
- Feed kalitesi ve kapsamı tamamen kuruma bağlıdır; ürün feed doğrulamaz.
- **Asset criticality** skora dahil değildir; aynı skor farklı iş kritikliğinde farklı anlam taşır.
- `dominant_source_type` en sık görülen event’e göre seçilir; az sayıda yanlış event baskın tipi çarpıtabilir.
- Canlı/production loglarıyla kalibrasyon süregelir; `RISK_SCORE_SCALE` env ile ayarlanabilir.
- `calculateThreatMetricsV2` (`server.js`) tanımlıdır ama **çağrılmaz** (ölü kod); overview bu metriği kullanmaz.
- Sentetik unit testler regresyonu yakalar; gerçek kurum validasyonunun yerini tutmaz.

---

## 10. Testler

```bash
cd backend && npm run test:risk
```

`backend/lib/riskEngine.test.js` şunları doğrular:

| Test | Kanıtladığı |
|------|-------------|
| FP verdict varyantları | Skor 0 |
| DNS-only 10k hits | Skor ≤ 25 |
| Blocked-only 50k hits | Skor ≤ 25 |
| Allowed proxy vs DNS-only | Proxy skoru daha yüksek |
| Multi-host vs single-host | `observed_hosts_signal` artışı |
| Düşük tier AI +20 | Effective delta ≤ +5 |
| FP + AI | Final 0 |
| 40× dns-only institution | Skor < 80 |
| Liste/detail aggregate alanları | Aynı base skor |
| Low AI confidence | Delta 0 |

**Testlerin kanıtlamadığı:** Gerçek log parser doğruluğu, feed kalitesi, UI/LLM metin kalitesi, production latency, çok kiracılı ölçek davranışı.

---

## 11. Ortam değişkenleri

| Değişken | Varsayılan (kod) | Açıklama |
|----------|------------------|----------|
| `RISK_SCORE_SCALE` | 50 | Institution doygunluk ölçeği |
| `LLM_RISK_ADVISOR_AI_WEIGHT` | 1 | AI delta çarpanı (`.env.example`) |
| `LLM_RISK_ADVISOR_ENABLED` | false (advisor factory) | LLM açık/kapalı |

---

## 12. Değişiklik ilkesi

- Tek hesaplama kaynağı: `backend/lib/riskEngine.js`
- SQL yalnızca aggregate; skor formülü SQL’e gömülmez
- API alan adları geriye uyumlu; breakdown alanları genişletilebilir
- Bu doküman Phase 1 kalibrasyonu (`incident-risk-central-2026-05-calibrated`, `institution-risk-central-2026-04-workflow-decoupled`) ile uyumludur
