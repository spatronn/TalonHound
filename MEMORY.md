# MEMORY.md - Long-Term Memory

## User Preferences

- Kullanıcıya hitap: **kirvem**.
- Tekrarlayan onboarding istemiyor; session başında mevcut kalıcı notlardan ilerlenmeli.
- Erişim/doğrulama istenirse önce sistemde kontrol edip net sonuç verilmeli.

## Project Context

- **Aktif proje:** TalonHound — threat intel & enrichment odaklı.
- **Arşiv:** demo-runbook (2026-07 geçişi).

## Infrastructure Facts (Persistent)

- TalonHound hedef host: `192.168.1.190` (hostname: `talonhound`)
  - OS: Ubuntu 24.04.4 LTS
  - SSH: `spatronn@192.168.1.190` — Windows host'ta `~/.ssh/id_ed25519` ile erişim doğrulandı (2026-07-11)
  - `root` SSH: mevcut key ile erişim yok (publickey denied)
  - Web: HTTP 80 → HTTPS redirect, HTTPS 443 → 200
  - Stack: demo-runbook tabanlı docker compose (container isimleri hâlâ `demo-*`)
- Eski demo host (arşiv): `192.168.1.251`
- GitHub repo: `https://github.com/spatronn/TalonHound` (private; web 404, local remote OK)
- Local path: `C:\Proje\TalonHound`
