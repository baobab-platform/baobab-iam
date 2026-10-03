#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
mkdir -p ory-foundation-evidence
# Require lock/Compose agreement before contacting registries or starting services.
python3 - <<'PY'
import yaml
from pathlib import Path
lock = yaml.safe_load(Path('provider.lock.yaml').read_text())
compose = yaml.safe_load(Path('docker-compose.ory.yml').read_text())
for provider in ('kratos', 'hydra'):
    pin = lock[provider]
    image = f"{pin['image']}:{pin['version']}@{pin['digest']}"
    for service in (provider, provider + '-migrate'):
        if compose['services'][service]['image'] != image:
            raise SystemExit(f'{service}: Compose differs from provider.lock.yaml')
print('Kratos and Hydra Compose images match the exact provider lock')
PY
timeout 240 docker compose -p ory-foundation-ci -f docker-compose.ory.yml up -d
for port in 4434 4445; do
  ready=0
  for attempt in $(seq 1 30); do
    if curl --connect-timeout 2 --max-time 3 -fsS -o /dev/null "http://127.0.0.1:$port/admin/health/ready" 2>/dev/null ||
       curl --connect-timeout 2 --max-time 3 -fsS -o /dev/null "http://127.0.0.1:$port/health/ready" 2>/dev/null; then
      ready=1
      break
    fi
    sleep 2
  done
  if [ "$ready" != 1 ]; then
    echo "Ory admin listener $port did not become ready" >&2
    exit 1
  fi
  echo "Admin listener $port ready" | tee -a ory-foundation-evidence/readiness.txt
done
export ORY_SMOKE=1 ORY_FOUNDATION=1
# Test output contains only statuses, never fixture credential or response bodies.
go test -json ./internal/provider/ory -run '^(TestSmoke_ProviderInfoAgainstLocalStack|TestLiveFoundation)$' -count=1 | tee ory-foundation-evidence/tests.jsonl
python3 - <<'PY'
import json
from pathlib import Path
events = [json.loads(line) for line in Path('ory-foundation-evidence/tests.jsonl').read_text().splitlines()]
for name in ('TestSmoke_ProviderInfoAgainstLocalStack', 'TestLiveFoundation',
             'TestLiveFoundation/authorized-human-migration-and-lifecycle',
             'TestLiveFoundation/real-session-revocation'):
    if not any(event.get('Test') == name and event.get('Action') == 'pass' for event in events):
        raise SystemExit(f'{name}: missing live PASS evidence (skips are not success)')
print('All required live tests passed without skips')
PY
