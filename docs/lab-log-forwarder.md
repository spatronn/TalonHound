# Lab Log Forwarder (BIND + Squid -> Syslog Receiver)

Purpose: forward BIND recursive DNS and Squid proxy logs from files into existing UDP syslog receiver without changing parsers/correlation.

## Receiver target in this repo
- Syslog receiver service: `syslog-receiver`
- Receiver UDP port: `514`
- Source: `backend/syslog-receiver.js` and `docker-compose.yml`

## Docker profile (`lab`)
Service added: `lab-log-forwarder` (profile: `lab`).

Run:
```bash
docker compose --profile lab up -d lab-log-forwarder
```

### Env vars
- `SYSLOG_FORWARD_TARGET_HOST` (default `syslog-receiver`)
- `SYSLOG_FORWARD_TARGET_PORT` (default `514`)
- `BIND_LOG_PATH` (default `/logs/bind-query.log`)
- `SQUID_LOG_PATH` (default `/logs/squid-access.log`)
- `LOG_FORWARDER_START_FROM_BEGINNING` (default `false`)
- `LOG_FORWARDER_BIND_TAG` (default `bind_dns`)
- `LOG_FORWARDER_SQUID_TAG` (default `squid_proxy`)
- `LOG_FORWARDER_HOSTNAME` (default `lab-forwarder`)
- `LOG_FORWARDER_POLL_MS` (default `1000`)

Host paths for mounts:
- `LAB_BIND_LOG_HOST_PATH` (default `/var/cache/bind/query.log`)
- `LAB_SQUID_LOG_HOST_PATH` (default `/var/log/squid/access.log`)

## Behavior
- tail-like polling (new lines only)
- default starts from file end (`LOG_FORWARDER_START_FROM_BEGINNING=false`)
- handles rotation/truncate via inode/size checks
- if file missing, logs warning and keeps retrying
- sends one syslog datagram per line (UDP)
- tags: `bind_dns` and `squid_proxy`
- periodic metrics on stdout:
  - `forwarded_lines_total`
  - `bind_forwarded_lines`
  - `squid_forwarded_lines`
  - `read_errors`
  - `last_forward_time`

## Systemd alternative (run on BIND/Squid host)
`/etc/lab-log-forwarder.env`:
```bash
SYSLOG_FORWARD_TARGET_HOST=192.168.1.X
SYSLOG_FORWARD_TARGET_PORT=514
BIND_LOG_PATH=/var/cache/bind/query.log
SQUID_LOG_PATH=/var/log/squid/access.log
LOG_FORWARDER_START_FROM_BEGINNING=false
LOG_FORWARDER_HOSTNAME=lab-forwarder
LOG_FORWARDER_BIND_TAG=bind_dns
LOG_FORWARDER_SQUID_TAG=squid_proxy
```

`/etc/systemd/system/lab-log-forwarder.service`:
```ini
[Unit]
Description=Lab Log Forwarder (BIND/Squid -> Syslog UDP)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/lab-log-forwarder
EnvironmentFile=/etc/lab-log-forwarder.env
ExecStart=/usr/bin/node /opt/lab-log-forwarder/forwarder.js
Restart=always
RestartSec=3
User=labforwarder
Group=labforwarder

[Install]
WantedBy=multi-user.target
```

Enable:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now lab-log-forwarder
sudo systemctl status lab-log-forwarder
```

## Validation
1. On BIND/Squid host:
```bash
tail -f /var/cache/bind/query.log
tail -f /var/log/squid/access.log
```

2. Generate traffic:
```bash
dig @192.168.1.140 malicious-domain.com A
curl -x http://192.168.1.140:3128 https://www.google.com -I
curl -x http://192.168.1.140:3128 "http://example.com/test/payload.exe" -I
```

3. Forwarder logs:
```bash
docker compose --profile lab logs -f lab-log-forwarder
```

4. Receiver logs:
```bash
docker compose logs -f syslog-receiver
```
Look for lines tagged with `bind_dns` and `squid_proxy`.

5. ClickHouse check:
```bash
docker compose exec clickhouse clickhouse-client -u demo --password "$CLICKHOUSE_PASSWORD" -q "SELECT ts, source, raw FROM syslog_logs ORDER BY ts DESC LIMIT 20"
```
