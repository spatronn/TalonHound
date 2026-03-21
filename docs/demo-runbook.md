# Demo Runbook (Single-VM)

## 1) Scope
- Goal: Run full demo stack on a single VM in same subnet.
- Target OS: Ubuntu 22.04.x LTS
- Initial resources: 2 vCPU / 4 GB RAM

## 2) Environment
- VM IP: `192.168.1.251`
- SSH User: `spatronn`
- SSH Port: `22`
- Auth: password-based login (secret not stored here)

## 3) Preflight Checklist
- [x] OS reachable via SSH
- [x] `sudo` access confirmed
- [x] Disk free space checked
- [x] Time sync OK (`timedatectl`)
- [x] Docker installed
- [x] Docker Compose plugin installed
- [x] Required ports free (80/443/3000/8080 as needed)
- [x] Swap configured (recommended for low-memory setups)

## 4) Install & Setup
### 4.1 Base packages
- Command(s):
  ```bash
  sudo apt update
  sudo apt install -y ca-certificates curl gnupg lsb-release
  ```
- Expected output: package install completed without errors
- Verification: `apt update` and package install return code `0`

### 4.2 Docker/Compose
- Command(s):
  ```bash
  sudo install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  sudo chmod a+r /etc/apt/keyrings/docker.gpg

  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

  sudo apt update
  sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  sudo systemctl enable --now docker
  ```
- Expected output: docker service active, compose installed
- Verification:
  ```bash
  docker --version
  docker compose version
  docker run --rm hello-world
  ```

### 4.3 Project bootstrap
- Command(s):
  ```bash
  cd /opt
  git clone https://github.com/spatronn/demo-runbook.git
  cd /opt/demo-runbook
  ```
- Expected output: repo cloned successfully
- Verification: `ls -la /opt/demo-runbook`

### 4.4 Environment variables
- Command(s): runtime env passed via `docker-compose.yml` (DEMO_EMAIL/DEMO_PASSWORD)
- Expected output: backend starts and listens on `:3000`
- Verification: `docker compose logs --tail=100`

## 5) App Deployment (Compose)
- [x] Pull/build images
- [x] Start services
- [x] Check container health
- [x] Check logs for fatal errors

Commands:
```bash
cd /opt/demo-runbook
git pull
docker compose up -d --build
docker compose ps
docker compose logs --tail=100
```

## 6) Test Plan (Smoke)
### 6.1 Infra
- [x] VM reachable
- [x] Docker daemon healthy
- [x] All required containers running

### 6.2 Backend
- [x] `/health` returns 200
- [x] Auth endpoint reachable

### 6.3 Frontend
- [x] Login page loads
- [x] Login success path works
- [x] Protected route redirects correctly

### 6.4 End-to-end
- [x] Login -> dashboard flow works
- [x] API calls through reverse proxy (`/api`) work

## 7) Troubleshooting Notes
### Issue 1: `dpkg was interrupted`
- Symptom: `E: dpkg was interrupted, you must manually run 'sudo dpkg --configure -a'`
- Likely cause: previous apt operation unfinished
- Fix:
  ```bash
  sudo dpkg --configure -a
  sudo apt --fix-broken install -y
  sudo apt update
  ```

### Issue 2: `file:/cdrom jammy Release` error
- Symptom: `The repository 'file:/cdrom jammy Release' no longer has a Release file`
- Likely cause: installer CD-ROM repo still enabled
- Fix:
  ```bash
  sudo sed -i 's/^deb cdrom/# deb cdrom/g' /etc/apt/sources.list
  sudo apt update
  ```

### Issue 3: GitHub clone via SSH fails
- Symptom: `git@github.com: Permission denied (publickey)`
- Likely cause: VM SSH key not registered in GitHub
- Fix options:
  1) Clone with HTTPS + Fine-grained PAT (used in this demo)
  2) Register VM public key to GitHub and use SSH clone

### Issue 4: Docker service inactive after install
- Symptom: `docker.service ... Active: inactive (dead)`
- Fix:
  ```bash
  sudo systemctl enable --now docker
  sudo systemctl start docker
  docker run --rm hello-world
  ```

## 8) Rollback & Operational Commands
### 8.1 Restart stack
```bash
cd /opt/demo-runbook
docker compose down
docker compose up -d --build
docker compose ps
```

### 8.2 Stop stack
```bash
cd /opt/demo-runbook
docker compose down
```

### 8.3 Check logs
```bash
cd /opt/demo-runbook
docker compose logs --tail=200
```

## 9) Demo Script (Presentation Flow)
1. Open `http://<VM_IP>`
2. Show login screen
3. Try wrong password and show validation
4. Login with demo user (`demo@demo.local / Password1!`)
5. Show dashboard access
6. Logout and verify redirect back to login

## 10) Test Evidence (Summary)
- VM reachable over subnet (`192.168.1.251`)
- Docker installed and validated (`hello-world` successful)
- Compose stack running:
  - `demo-backend` up
  - `demo-frontend` up (`0.0.0.0:80->80`)
- Backend log confirms: `Backend listening on :3000`
- Frontend reachable and login flow validated end-to-end

## 11) Export / Import Procedure
### 11.1 Before export
- [ ] Create snapshot: `clean-base`
- [ ] Create snapshot: `demo-ready`
- [ ] Stop app services if needed

### 11.2 Export
- [ ] Export as OVA
- [ ] Record VM settings (CPU/RAM/Disk/Network)

### 11.3 After import
- [ ] Re-check NIC/network
- [ ] Re-check Docker and volumes
- [ ] Re-run smoke tests

## 12) Technologies & Integrations

### Core stack
- Frontend: React 18 + Vite 5 + React Router 6
- Backend: Node.js (ESM) + Express
- Database: PostgreSQL 16
- Runtime/Orchestration: Docker + Docker Compose
- Reverse proxy/static serving: Nginx (frontend container)
- Map rendering: `react-simple-maps` + local lightweight GeoJSON (`frontend/public/world-lite.geojson`)

### Data sources / integrations
- ASN + Country enrichment source: https://iptoasn.com/
  - Import format: TSV/TSV.GZ
  - Imported into PostgreSQL (`asn_networks_raw` + optimized `asn_ipv4_ranges`)
- Threat intel rules feed (blocklists): **Emerging Threats**
  - Source index: `http://rules.emergingthreats.net/blockrules/`
  - Example feed: `threatview_CS_c2.rules`
  - Parser/import scripts:
    - `scripts/prepare-et-blockrules-import.mjs`
    - `scripts/import-ioc-csv-via-api.mjs`

### Internal API modules implemented
- Auth: `/api/auth/login`
- User preferences (timezone):
  - `GET /api/users/me/preferences`
  - `PUT /api/users/me/preferences`
- IOC create/list/delete/bulk-delete: `/api/ioc/*`
- IOC source detail view: `/api/ioc/ip/sources`
- Raw recent IOC feed (Add IOC table): `/api/ioc/ip/recent-raw`
- Daily/period summary: `/api/ioc/summary/today?day=today|24h|7d|all`
- Threat map country aggregation: `/api/ioc/map/countries?day=today|24h|7d|all`
- IOC filters: query/source/confidence/asn/country + subnet search

## 13) Supported Syslog Parse Formats (IOC Extraction)

### 13.1 Microsoft DNS Debug (existing)
- Detection: lines containing Microsoft DNS debug pattern (`Snd`/`Rcv` + encoded query labels)
- Extracted fields:
  - `parsed_ip`: source IP from debug line
  - `parsed_query`: decoded DNS query (domain)
- IOC derivation:
  - `ioc_query`: decoded domain
  - `ioc_ip`: source IP only when public IP

### 13.2 FortiGate Traffic Key=Value (new)
- Detection: syslog payload containing `type="traffic"`
- Expected format: key=value pairs (quoted/unquoted), e.g. `srcip=... dstip=... service="HTTP"`
- Extracted fields (current schema, no new columns):
  - `parsed_ip`: `dstip`
  - `parsed_ip_private`: private/public check for `dstip`
- IOC derivation:
  - `ioc_ip`: `dstip` when public IP
- Tested sample variants:
  - `subtype="multicast"` with `dstip=49.212.188.245`
  - `subtype="forward"` with `dstip=23.59.154.35`

## 14) Change Log
- 2026-02-26: Initial runbook created.
- 2026-02-26: Added minimal demo stack (React login frontend + Express auth backend + Docker Compose).
- 2026-02-26: Completed preflight, deployment, and smoke tests on demo VM (192.168.1.251).
- 2026-02-26: Expanded runbook with troubleshooting, rollback commands, demo presentation flow, and test evidence summary.
- 2026-02-26: Switched persistence to PostgreSQL and added IOC IP/source data flow.
- 2026-02-28: Updated technology stack section (map layer, timezone preferences, map APIs) and documented Emerging Threats blockrules integration.
- 2026-03-21: Documented currently supported syslog parse formats used for IOC extraction (Microsoft DNS debug + FortiGate traffic key=value).
