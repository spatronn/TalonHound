# MEMORY.md - Long-Term Memory

## User Preferences

- Kullanıcıya hitap: **kirvem**.
- Tekrarlayan onboarding istemiyor; session başında mevcut kalıcı notlardan ilerlenmeli.
- Erişim/doğrulama istenirse önce sistemde kontrol edip net sonuç verilmeli.

## Project Context

- **Aktif proje:** TalonHound — threat intel & enrichment odaklı.
- **Arşiv:** demo-runbook (2026-07 geçişi).
- **File Artifacts:** Additive md5/sha1/sha256 identity layer (migration `131`). Flags `FILE_ARTIFACTS_DUAL_WRITE_ENABLED` / `FILE_ARTIFACTS_READ_ENABLED`. Docs: `docs/file-artifacts.md`.
- **IOC Details:** Legacy Source Evidence UI section removed (Intelligence tab); memberships / feed evidence / hash canonicalization kept.
- **API Keys / REST (2026-08-08):** General-purpose API keys with scope profiles.
  - Profiles: `published_feed` → `published_feeds:read`; `ioc_management` → `ioc:create` + `ioc:update`.
  - Management API: `POST/PATCH /api/v1/iocs` (Bearer only). Docs: `/api/docs`, `/api/openapi.json`.
  - System IOC source name `API` (not selectable in Add IOC). Shared service: `backend/lib/apiIocService.js`.
  - Migration: `145_api_key_scopes_and_ioc_management.sql` (not yet deployed until explicitly asked).
- **Entegrasyon (devam):** TalonHound ↔ DNSMania DNS enrichment.
  - DNSMania local path: `C:\Proje\DNSMania`
  - API readiness raporu: `C:\Proje\DNSMania\docs\api-reference.html`
  - DNSMania test API: `http://192.168.1.191:3000` (BIND + DNSTAP; auth yok, LAN)
  - **Phase 1 (manuel):** IOC Detail > Intelligence DNSMania kartı eklendi
    - Env: `DNSMANIA_BASE_URL`, `DNSMANIA_TIMEOUT_MS`, `DNSMANIA_ENABLED`
    - Routes: `GET/POST /api/enrichment/dnsmania` (+ `/refresh`)
    - Table: `ioc_dnsmania_enrichment` (migration `112_...`)
    - Otomatik/cron/batch YOK — yalnızca Enrich/Refresh butonu

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
