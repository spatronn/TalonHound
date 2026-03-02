# Demo-Run Feature Ideas (Research-Driven)

Bu dosya, `reports/threat-intel-ops-research.md` içindeki 15 dakikalık araştırma çıktılarından türetilen **öneri havuzudur**.

> Not: Bu bir sprint/backlog taahhüdü değildir. Sadece fikirleri toplar, sıralar ve gerektiğinde karar desteği sağlar.

## Hafif Skorlama (Karar Desteği)
- **Impact (1-5):** Ürün değerine potansiyel etki
- **Effort (1-5):** Tahmini geliştirme zorluğu (5 = zor)
- **Idea Score:** `Impact / Effort` (yüksek = daha cazip fikir)

## Öneri Havuzu

### 1) Identity Threat Radar (Kimlik Odaklı Risk Görünümü)
- **Tekrarlayan sinyal:** Kimlik merkezli ihlal/saldırı paterni sürekli tekrar ediyor.
- **Öneri:** Dashboard’da “Identity Risk” kartı + trend + temel göstergeler.
- **Minimum kapsam (istersek):**
  - identity-related event sınıfı
  - son 24s/7g trend
  - top 5 identity risk reason
- **Impact:** 5
- **Effort:** 2
- **Idea Score:** 2.5

### 2) Speed-to-Respond KPI Panel (Hız Baskısı KPI)
- **Tekrarlayan sinyal:** Operasyonel hız baskısı sürekli tema.
- **Öneri:** MTTD/MTTR/triage-time kartları + hedefe göre durum.
- **Minimum kapsam (istersek):**
  - 3 KPI kartı
  - hedef değer tanımı
  - 7 günlük trend
- **Impact:** 5
- **Effort:** 2
- **Idea Score:** 2.5

### 3) AI Governance Watch (Shadow AI / AI Risk İzleme)
- **Tekrarlayan sinyal:** AI yönetişim açığı ve shadow AI riski düzenli geçiyor.
- **Öneri:** AI-related etiketleme + basit risk görünümü.
- **Minimum kapsam (istersek):**
  - AI-related etiket alanı
  - AI risk checklist widget
  - basic heatmap
- **Impact:** 4
- **Effort:** 2
- **Idea Score:** 2.0

### 4) Alert Fatigue Guardrail (Alarm Yorgunluğu Koruması)
- **Tekrarlayan sinyal:** Alarm yükü / analist yorgunluğu stabil.
- **Öneri:** Benzer alarmları gruplama + noise score + suppressed count.
- **Minimum kapsam (istersek):**
  - rule-based dedup (kaynak+tip+zaman)
  - grup başına tek incident görünümü
  - suppressed count metriği
- **Impact:** 5
- **Effort:** 3
- **Idea Score:** 1.67

### 5) 3rd-Party Exposure Lens (Üçüncü Taraf Maruziyet Lensi)
- **Tekrarlayan sinyal:** Üçüncü taraf bağımlılık/zafiyet baskısı sürekli.
- **Öneri:** event/IOC için first-party vs third-party etiketleme + filtre.
- **Minimum kapsam (istersek):**
  - provider/vendor eşleme tablosu
  - third-party only filtre
  - haftalık özet
- **Impact:** 4
- **Effort:** 3
- **Idea Score:** 1.33

### 6) Research-to-Idea Auto-Summarizer
- **Tekrarlayan sinyal:** Koşularda “anlamlı yeni bulgu yok” tekrar deseni var.
- **Öneri:** Son N koşu farkını çıkarıp yeni sinyal olduğunda fikir önerisi üretmek.
- **Minimum kapsam (istersek):**
  - son N run diff özeti
  - no-change streak metriği
  - öneri satırı üretimi
- **Impact:** 4
- **Effort:** 4
- **Idea Score:** 1.0

## Compose İçinde Olası Yerleşim (Karar verilirse)
- **frontend:** dashboard kartları, filtreler, trend görselleştirmeleri
- **backend:** skor/aggregasyon endpoint’leri, etiketleme kuralları
- **db:** etiket/metric alanları, özet tablolar
- **integration-worker/scheduler:** araştırma sinyallerinden etiket/özet üretimi

## Not
Bu dosya yaşayan bir fikir havuzudur; 15 dk research çıktıları geldikçe güncellenir.
