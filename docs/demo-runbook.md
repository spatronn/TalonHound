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

## 4) Install & Setup (to fill during execution)
### 4.1 Base packages
- Command(s):
- Expected output:
- Verification:

### 4.2 Docker/Compose
- Command(s):
- Expected output:
- Verification:

### 4.3 Project bootstrap
- Command(s):
- Expected output:
- Verification:

### 4.4 Environment variables
- Command(s):
- Expected output:
- Verification:

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
- Symptom:
- Likely cause:
- Fix:

## 8) Export / Import Procedure
### 8.1 Before export
- [ ] Create snapshot: `clean-base`
- [ ] Create snapshot: `demo-ready`
- [ ] Stop app services if needed

### 8.2 Export
- [ ] Export as OVA
- [ ] Record VM settings (CPU/RAM/Disk/Network)

### 8.3 After import
- [ ] Re-check NIC/network
- [ ] Re-check Docker and volumes
- [ ] Re-run smoke tests

## 9) Change Log
- 2026-02-26: Initial runbook created.
- 2026-02-26: Added minimal demo stack (React login frontend + Express auth backend + Docker Compose).
- 2026-02-26: Completed preflight, deployment, and smoke tests on demo VM (192.168.1.251).
