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
python3 tests/ory-foundation/workload_profiles.py
# Always address this disposable Compose stack, never inherited remote endpoints.
export ORY_KRATOS_ADMIN_URL=http://127.0.0.1:4434
export ORY_KRATOS_PUBLIC_URL=http://127.0.0.1:4433
export ORY_HYDRA_ADMIN_URL=http://127.0.0.1:4445
export ORY_PUBLIC_ISSUER=http://127.0.0.1:4444
export ORY_SMOKE=1 ORY_FOUNDATION=1 ORY_WORKLOAD=1
export ORY_M4_PROFILES_FILE="$PWD/ory-foundation-evidence/workload-profiles.json"
export ORY_M4_EVIDENCE_DIR="$PWD/ory-foundation-evidence"
# Test output contains only statuses, never fixture credential or response bodies.
go test -json ./internal/provider/ory -run '^(TestSmoke_ProviderInfoAgainstLocalStack|TestLiveFoundation|TestLiveWorkloadClientCredentials|TestLiveWorkloadFederated)$' -count=1 | tee ory-foundation-evidence/tests.jsonl
python3 - <<'PY'
import json
from pathlib import Path
events = [json.loads(line) for line in Path('ory-foundation-evidence/tests.jsonl').read_text().splitlines()]
for name in ('TestSmoke_ProviderInfoAgainstLocalStack', 'TestLiveFoundation',
             'TestLiveFoundation/authorized-human-migration-and-lifecycle',
             'TestLiveFoundation/real-session-revocation',
             'TestLiveWorkloadClientCredentials', 'TestLiveWorkloadFederated',
             'TestLiveWorkloadClientCredentials/signed-token-and-shared-scopes',
             'TestLiveWorkloadClientCredentials/invalid-credential-and-scope',
             'TestLiveWorkloadClientCredentials/rotation-invalidates-old-credential',
             'TestLiveWorkloadClientCredentials/suspend-denies-future-issuance'):
    if not any(event.get('Test') == name and event.get('Action') == 'pass' for event in events):
        raise SystemExit(f'{name}: missing live PASS evidence (skips are not success)')
print('All required live tests passed without skips')
PY

python3 - <<'PYPROOF'
import json
from pathlib import Path
root = Path('ory-foundation-evidence')
events = [json.loads(line) for line in (root / 'tests.jsonl').read_text().splitlines()]
checks = ('signed-exchange-and-replay-rejected', 'reject-issuer', 'reject-subject',
          'reject-audience', 'reject-expired', 'reject-not-yet-valid',
          'reject-signature', 'reject-scope', 'no-static-secret-downgrade',
          'revoke-denies-future-exchange')
for workload in ('baobab-cp-workload', 'baobab-subscriptions-workload'):
    for check in checks:
        name = f'TestLiveWorkloadFederated/{workload}/{check}'
        if not any(event.get('Test') == name and event.get('Action') == 'pass' for event in events):
            raise SystemExit(f'{name}: missing live PASS evidence')
for workload in ('baobab-trade-workload', 'baobab-cp-workload', 'baobab-subscriptions-workload'):
    evidence = json.loads((root / (workload + '.json')).read_text())
    if not evidence['signature_verified'] or not evidence['requested_shared_scopes_verified']:
        raise SystemExit(f'{workload}: missing signed token profile proof')
    if evidence['canonical_activation_proven'] or evidence['actual_consumer_tested']:
        raise SystemExit('Isolated fixtures must not claim canonical activation')
print('M4 provider mechanics evidenced; actual-consumer activation remains outside this fixture')
PYPROOF
