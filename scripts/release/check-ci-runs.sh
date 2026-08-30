#!/usr/bin/env bash
set -euo pipefail
: "${GH_TOKEN:?GH_TOKEN required}"
curl -sS \
  -H "Authorization: Bearer ${GH_TOKEN}" \
  -H "Accept: application/vnd.github+json" \
  "https://api.github.com/repos/spatronn/TalonHound/actions/runs?per_page=8" \
  -o /tmp/talonhound-runs.json
python3 <<'PY'
import json
with open('/tmp/talonhound-runs.json') as f:
    data = json.load(f)
if 'message' in data:
    print('ERROR:', data['message'])
    raise SystemExit(1)
for run in data.get('workflow_runs', []):
    print(
        run['id'],
        run['status'],
        run.get('conclusion'),
        run['head_sha'][:12],
        run['name'],
        run['html_url'],
        sep='\t'
    )
PY
