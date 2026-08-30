#!/bin/sh
set -e
if [ ! -f /etc/nginx/certs/cert.pem ] || [ ! -f /etc/nginx/certs/key.pem ]; then
  echo "[proxy] No TLS certs in /etc/nginx/certs; generating self-signed (dev/demo only)."
  apk add --no-cache openssl >/dev/null
  openssl req -x509 -nodes -days 825 -newkey rsa:2048 \
    -keyout /etc/nginx/certs/key.pem \
    -out /etc/nginx/certs/cert.pem \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null \
    || openssl req -x509 -nodes -days 825 -newkey rsa:2048 \
      -keyout /etc/nginx/certs/key.pem \
      -out /etc/nginx/certs/cert.pem \
      -subj "/CN=localhost"
  chmod 644 /etc/nginx/certs/cert.pem
  chmod 600 /etc/nginx/certs/key.pem
fi
exec nginx -g "daemon off;"
