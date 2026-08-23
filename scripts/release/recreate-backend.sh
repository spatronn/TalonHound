#!/usr/bin/env bash
set -euo pipefail
cd /opt/TalonHound
export TALONHOUND_VERSION="$(tr -d '\r\n' < VERSION)"
export TALONHOUND_COMMIT="$(git rev-parse HEAD)"
export TALONHOUND_BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
docker compose build backend
docker compose up -d --no-deps backend
sleep 15
docker compose exec -T backend node --input-type=module <<'NODE'
import { getProductVersionInfo } from './lib/productVersion.js';
console.log(JSON.stringify(getProductVersionInfo(), null, 2));
NODE
