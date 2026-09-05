#!/bin/sh
set -e

CERT_DIR=/etc/nginx/certs
CERT_FILE="$CERT_DIR/cert.pem"
KEY_FILE="$CERT_DIR/key.pem"
SOURCE_FILE="$CERT_DIR/.cert_source"
RELOAD_REQUEST="$CERT_DIR/.reload_request"
RELOAD_RESULT="$CERT_DIR/.reload_result"

mkdir -p "$CERT_DIR"

if [ ! -f "$CERT_FILE" ] || [ ! -f "$KEY_FILE" ]; then
  echo "[proxy] No TLS certs in $CERT_DIR; generating self-signed (dev/demo only)."
  apk add --no-cache openssl >/dev/null
  openssl req -x509 -nodes -days 825 -newkey rsa:2048 \
    -keyout "$KEY_FILE" \
    -out "$CERT_FILE" \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null \
    || openssl req -x509 -nodes -days 825 -newkey rsa:2048 \
      -keyout "$KEY_FILE" \
      -out "$CERT_FILE" \
      -subj "/CN=localhost"
  chmod 644 "$CERT_FILE"
  chmod 600 "$KEY_FILE"
  printf 'generated\n' > "$SOURCE_FILE"
  chmod 644 "$SOURCE_FILE"
elif [ ! -f "$SOURCE_FILE" ]; then
  # Existing installs without a marker remain "generated" unless replaced via UI.
  printf 'generated\n' > "$SOURCE_FILE"
  chmod 644 "$SOURCE_FILE"
fi

# Watch for TLS replace requests from the backend (shared certs volume).
# Backend writes .reload_request after updating cert.pem/key.pem; we nginx -t && reload.
(
  while true; do
    if [ -f "$RELOAD_REQUEST" ]; then
      rm -f "$RELOAD_RESULT"
      if nginx -t >/tmp/nginx-t.out 2>&1; then
        if nginx -s reload >/tmp/nginx-reload.out 2>&1; then
          printf 'ok\n' > "$RELOAD_RESULT"
        else
          printf 'fail: nginx reload failed\n' > "$RELOAD_RESULT"
        fi
      else
        printf 'fail: nginx configuration test failed\n' > "$RELOAD_RESULT"
      fi
      rm -f "$RELOAD_REQUEST"
      chmod 644 "$RELOAD_RESULT" 2>/dev/null || true
    fi
    sleep 1
  done
) &

exec nginx -g "daemon off;"
