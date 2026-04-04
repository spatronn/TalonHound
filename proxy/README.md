# TLS reverse proxy

- **443 / 443:** TLS burada sonlanır; trafik içeride `frontend:80` (nginx + statik) üzerinden gider.
- **80:** Varsayılan olarak **HTTPS’e yönlendirir**. Let’s Encrypt HTTP-01 için `/.well-known/acme-challenge/` klasörü ayrıldı; üretimde certbot ile doldurup gerçek sertifika dosyalarını `certs/` altına koyabilirsin.

İlk çalıştırmada `certs/` boşsa entrypoint **self-signed** üretir (tarayıcı uyarısı normal).

Üretim: `cert.pem` / `key.pem` dosyalarını bu dizine mount edin (veya volume).

`nginx.conf` içinde özetle: **TLS 1.2+**, AEAD cipher seti, **HTTP/2**, oturum önbelleği, **HSTS** (`includeSubDomains`), **OCSP stapling** (stapling doğrulaması self-signed ile uyum için `off`; Let’s Encrypt kullanırken `fullchain.pem`’i `cert.pem` olarak verip istersen `ssl_stapling_verify on` + `ssl_trusted_certificate` ile sıkılaştırabilirsin), birkaç güvenlik başlığı (`nosniff`, `Referrer-Policy`, `X-Frame-Options`).
