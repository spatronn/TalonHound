# Frontend İyileştirme Önerileri

Bu doküman, `frontend/src/main.jsx` ve genel UX için önerilen iyileştirmeleri listeler.

---

## 1. IOC List – API çağrılarını azaltmak

**Mevcut:** Her sayfa değişiminde hem `/ioc/list` hem `/ioc/summary/today` birlikte çağrılıyor (Promise.all). Summary verisi sayfa ile değişmediği için gereksiz yere tekrarlanıyor.

**Öneri:** Summary’i sadece sayfa ilk açıldığında (mount) bir kez çek; list isteğini sadece `page`, `pageSize`, `search` değişince at. Böylece "Next" / "Previous" ile sayfa değiştirirken sadece list endpoint’i çağrılır.

**Durum:** Uygulandı ✅

---

## 2. IOC List – Arama debounce

**Mevcut:** Arama, kullanıcı "Search" butonuna bastığında veya Enter’a basınca tetikleniyordu.

**Uygulandı:** Yazarken 400 ms debounce ile otomatik arama eklendi: kullanıcı yazmayı bıraktıktan 400 ms sonra tek istek atılıyor. Enter ve "Search" butonu anında arama yapıyor; "Clear" bekleyen debounce’u iptal ediyor.

---

## 3. Add IOC – alert yerine inline mesaj

**Mevcut:** Başarı veya hata için `alert()` kullanılıyor.

**Öneri:** Form üstünde kısa süre görünen inline mesaj (yeşil: "IOC saved", kırmızı: hata, sarı: "Already in list (duplicate)"). Backend duplicate için `{ skipped: true, reason: 'duplicate_tuple' }` döndüğünde bunu ayrı mesajla göstermek.

**Durum:** Uygulandı ✅

---

## 4. useEffect / useCallback bağımlılıkları

**Mevcut:** `loadData` dependency list’te yoktu; ESLint uyarı verebiliyordu.

**Uygulandı:** `loadSummary` ve `loadData` `useCallback` ile sarmalandı; effect’ler `[loadSummary]`, `[page, pageSize, loadData]` kullanıyor. `loadData` bağımlılığı `[search]`.

---

## 5. Hata durumlarında tutarlı geri bildirim

**Mevcut:** Birçok yerde `catch` içinde sadece state sıfırlanıyor veya `alert()` kullanılıyor.

**Öneri:** Kritik sayfalarda (IOC list, Add IOC, Analytics) hata mesajını sayfa içinde göstermek (örn. banner veya form üstünde); gerekirse 5–10 saniye sonra otomatik gizlemek.

---

## 6. Loading state

**Mevcut:** Çoğu yerde "Loading..." metni kullanılıyor.

**Öneri:** Ortak bir küçük spinner veya skeleton bileşeni; tablolar için satır sayısı kadar placeholder. Öncelik düşük; mevcut metin de yeterli.

---

## 7. Erişilebilirlik (a11y)

**Öneri:** Form alanlarında `label` + `htmlFor`, butonlarda anlamlı `aria-label`, hata mesajlarında `role="alert"`. Klavye ile gezinme ve ekran okuyucu deneyimini iyileştirir.

---

## 8. Kod organizasyonu

**Mevcut:** Tüm sayfalar tek `main.jsx` dosyasında (~1900+ satır).

**Öneri:** Uzun vadede sayfa bileşenlerini ayrı dosyalara bölmek (örn. `pages/IOCListPage.jsx`, `pages/AddIOCPage.jsx`); hooks ve yardımcıları da ayrı modüllere taşımak. Bakım ve test için faydalı; acil değil.

---

## Özet

| Öncelik | Konu              | Durum / Öneri |
|--------|--------------------|----------------|
| 1      | List’te summary’i ayrı, sadece mount’ta | ✅ Uygulandı |
| 2      | Add IOC inline mesaj (duplicate dahil) | ✅ Uygulandı |
| 3      | Arama debounce (IOC list, 400 ms)     | ✅ Uygulandı |
| 4      | useCallback / effect deps             | ✅ Uygulandı |
| 5      | Hata mesajı banner’ları                | Önerilir |
| 6      | Loading skeleton/spinner              | İsteğe bağlı |
| 7      | a11y (label, aria)                    | İsteğe bağlı |
| 8      | Dosya bölme (pages/)                  | Uzun vadeli |

Bu doküman, `docs/ioc-performance-improvements.md` ile birlikte kullanılabilir; biri backend/IOC performansı, biri frontend/UX odaklıdır.
