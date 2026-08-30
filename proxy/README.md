# TLS reverse proxy

- **443:** TLS terminates here; traffic is forwarded internally to `frontend:80` (nginx + static UI) and the backend API paths.
- **80:** Redirects to HTTPS by default. The `/.well-known/acme-challenge/` location is reserved for Let's Encrypt HTTP-01.

On first run, if `certs/` is empty, the entrypoint generates a **self-signed** certificate.

Mount `cert.pem` / `key.pem` into this directory (or a volume) for issued certificates. Generated keys are gitignored; see `proxy/certs/.gitignore`.

`nginx.conf` enables TLS 1.2+, an AEAD cipher suite, HTTP/2, session cache, HSTS (`includeSubDomains`), and common security headers. OCSP stapling verification is off for self-signed certs; when using Let's Encrypt (`fullchain.pem` as `cert.pem`), stapling can use `ssl_stapling_verify on` and `ssl_trusted_certificate`.
