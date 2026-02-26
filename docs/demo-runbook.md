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
- [ ] OS reachable via SSH
- [ ] `sudo` access confirmed
- [ ] Disk free space checked
- [ ] Time sync OK (`timedatectl`)
- [ ] Docker installed
- [ ] Docker Compose plugin installed
- [ ] Required ports free (80/443/3000/8080 as needed)
- [ ] Swap configured (recommended for low-memory setups)

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
- [ ] Pull/build images
- [ ] Start services
- [ ] Check container health
- [ ] Check logs for fatal errors

Commands:
```bash
# to be filled
```

## 6) Test Plan (Smoke)
### 6.1 Infra
- [ ] VM reachable
- [ ] Docker daemon healthy
- [ ] All required containers running

### 6.2 Backend
- [ ] `/health` returns 200
- [ ] Auth endpoint reachable

### 6.3 Frontend
- [ ] Login page loads
- [ ] Login success path works
- [ ] Protected route redirects correctly

### 6.4 End-to-end
- [ ] Login -> dashboard flow works
- [ ] API calls through reverse proxy (`/api`) work

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
- YYYY-MM-DD: Initial runbook created.
