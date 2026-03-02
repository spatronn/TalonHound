# Demo-Run Feature Backlog (Research-Driven)

Bu backlog, `reports/threat-intel-ops-research.md` içinde tekrar eden 15 dk araştırma çıktılarından türetildi.

## Skorlama
- **Impact (1-5):** Ürün değerine etkisi
- **Effort (1-5):** Geliştirme zorluğu (5 = zor)
- **Priority Score:** `Impact / Effort` (yüksek daha iyi)

## Backlog

### 1) Identity Threat Radar (Kimlik Odaklı Risk Görünümü)
- **Tekrarlayan sinyal:** Kimlik merkezli ihlal/saldırı paterni sürekli tekrar ediyor.
- **Feature:** Dashboard’da ayrı bir “Identity Risk” kartı + risk trendi + top identity indicators.
- **MVP kapsamı:**
  - Identity-related event sınıfı
  - Son 24s/7g trend sparkline
  - “Top 5 identity risk reason” listesi
- **Impact:** 5
- **Effort:** 2
- **Priority Score:** 2.5

### 2) Alert Fatigue Guardrail (Alarm Yorgunluğu Koruması)
- **Tekrarlayan sinyal:** Alarm yükü / analist yorgunluğu teması stabil şekilde geliyor.
- **Feature:** Benzer alarmları otomatik gruplama + “noise score” + tekil olay akışına indirme.
- **MVP kapsamı:**
  - Rule-based dedup (kaynak+tip+zaman penceresi)
  - Grup başına tek incident görünümü
  - “Suppressed count” göstergesi
- **Impact:** 5
- **Effort:** 3
- **Priority Score:** 1.67

### 3) 3rd-Party Exposure Lens (Üçüncü Taraf Maruziyet Lensi)
- **Tekrarlayan sinyal:** Üçüncü taraf bağımlılık/zafiyet baskısı sürekli doğrulanıyor.
- **Feature:** Event ve IOC’ları “first-party / third-party” diye etiketleyip ayrı raporlama.
- **MVP kapsamı:**
  - Basit provider/vendor eşleme tablosu
  - Filtre: third-party only
  - Haftalık third-party risk özeti
- **Impact:** 4
- **Effort:** 3
- **Priority Score:** 1.33

### 4) AI Governance Watch (Shadow AI / AI Risk İzleme)
- **Tekrarlayan sinyal:** AI yönetişim açığı ve shadow AI riski düzenli geçiyor.
- **Feature:** Demo-run içinde AI-risk checklist ve AI-related event tagging.
- **MVP kapsamı:**
  - “AI-related” etiket alanı
  - AI risk policy checklist widget
  - Basit AI risk heatmap
- **Impact:** 4
- **Effort:** 2
- **Priority Score:** 2.0

### 5) Speed-to-Respond KPI Panel (Hız Baskısı için KPI)
- **Tekrarlayan sinyal:** Saldırı/operasyon hızı baskısı sürekli tema.
- **Feature:** MTTD/MTTR/triage-time paneli + hedefe göre renkli durum.
- **MVP kapsamı:**
  - 3 KPI kartı (MTTD, MTTR, Triage)
  - Hedef değer tanımı
  - Son 7 gün trendi
- **Impact:** 5
- **Effort:** 2
- **Priority Score:** 2.5

### 6) Research-to-Roadmap Auto-Summarizer
- **Tekrarlayan sinyal:** 15 dk koşular “anlamlı yeni bulgu yok” gibi tekrar eden pattern üretiyor.
- **Feature:** Koşu çıktılarından otomatik “what changed?” özeti + feature önerisi.
- **MVP kapsamı:**
  - Son N run diff özeti
  - “New signal / No-change streak” metriği
  - Backlog öneri satırı üretimi
- **Impact:** 4
- **Effort:** 4
- **Priority Score:** 1.0

## Önerilen Sprint Sırası
1. **Identity Threat Radar**
2. **Speed-to-Respond KPI Panel**
3. **AI Governance Watch**
4. **Alert Fatigue Guardrail**
5. **3rd-Party Exposure Lens**
6. **Research-to-Roadmap Auto-Summarizer**

## Hızlı Uygulama Planı (2 Sprint)
- **Sprint 1:** Identity Threat Radar + KPI Panel + temel AI tagging
- **Sprint 2:** Alert Fatigue Guardrail + 3rd-party lens + auto-summarizer iskeleti

## Not
Bu dosya yaşayan backlog’dur; 15 dk research çıktılarıyla periyodik güncellenmelidir.
