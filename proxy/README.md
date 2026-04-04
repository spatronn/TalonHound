# TLS reverse proxy

- **443 / 443:** TLS burada sonlanır; trafik içeride `frontend:80` (nginx + statik) üzerinden gider.
- **80:** Varsayılan olarak **HTTPS’e yönlendirir**. Let’s Encrypt HTTP-01 için `/.well-known/acme-challenge/` klasörü ayrıldı; üretimde certbot ile doldurup gerçek sertifika dosyalarını `certs/` altına koyabilirsin.

İlk çalıştırmada `certs/` boşsa entrypoint **self-signed** üretir (tarayıcı uyarısı normal).

Üretim: `cert.pem` / `key.pem` dosyalarını bu dizine mount edin (veya volume); güçlü cipher ve HSTS ihtiyacına göre `nginx.conf` genişletin.
