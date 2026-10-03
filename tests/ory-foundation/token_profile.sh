#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
task_dir=$(mktemp -d)
cleanup() {
  if [ -n "${hook_pid:-}" ]; then kill "$hook_pid" 2>/dev/null || true; wait "$hook_pid" 2>/dev/null || true; fi
  docker compose -p ory-foundation-ci -f docker-compose.ory.yml stop hydra >/dev/null 2>&1 || true
  rm -rf "$task_dir"
}
trap cleanup EXIT
mkdir -p ory-foundation-evidence/token-profile
python3 - "$task_dir" <<'PY'
import json, secrets, sys
from pathlib import Path
import yaml
root = Path(sys.argv[1])
key = secrets.token_hex(32)
(root / 'key').write_text(key)
(root / 'key').chmod(0o600)
profiles = json.loads(Path('ory-foundation-evidence/workload-profiles.json').read_text())
profiles['bindings'] = {name: {'issuer': 'https://projected.m4-ci.invalid/' + name,
                              'subject': 'system:serviceaccount:m4-ci:' + name}
                        for name, profile in profiles['workloads'].items()
                        if profile['credential_type'] == 'federated_workload_token'}
(root / 'profiles.json').write_text(json.dumps(profiles))
config = yaml.safe_load(Path('config/ory/hydra/hydra.yml').read_text())
config['ttl'] = {'access_token': '15m'}
config['strategies']['jwt'] = {'scope_claim': 'string'}
config['oauth2'].update({'allowed_top_level_claims': ['actor_type', 'azp', 'scope'],
                       'mirror_top_level_claims': False,
                       'token_hook': {'url': 'http://host.docker.internal:4466/internal/ory/token-profile',
                                      'auth': {'type': 'api_key', 'config': {'in': 'header',
                                               'name': 'X-Baobab-Token-Hook-Key', 'value': key}}}})
# Configuration with credentials is private temporary input, never an artifact.
(root / 'hydra.yml').write_text(yaml.safe_dump(config))
# Hydra's non-root UID needs to read this bind mount in the isolated CI host.
# The parent directory remains mode 0700 outside the container.
(root / 'hydra.yml').chmod(0o644)
overlay = {'services': {'hydra': {'extra_hosts': ['host.docker.internal:host-gateway'],
                                'volumes': [str(root / 'hydra.yml') + ':/etc/config/hydra/hydra.yml:ro']}}}
(root / 'compose.yml').write_text(yaml.safe_dump(overlay))
PY
go build -o "$task_dir/token-profile-hook" ./cmd/ory-token-profile-hook
"$task_dir/token-profile-hook" -listen 0.0.0.0:4466 -profiles "$task_dir/profiles.json" -key-file "$task_dir/key" > "$task_dir/hook.log" 2>&1 &
hook_pid=$!
for attempt in $(seq 1 20); do
  # An unauthenticated health probe must be rejected, never treated as evidence.
  if [ "$(curl --max-time 2 -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:4466/internal/ory/token-profile || true)" = 401 ]; then break; fi
  sleep 1
done
kill -0 "$hook_pid"
timeout 120 docker compose -p ory-foundation-ci -f docker-compose.ory.yml -f "$task_dir/compose.yml" up -d hydra
ready=0
for attempt in $(seq 1 30); do
  if curl --max-time 3 -fsS -o /dev/null http://127.0.0.1:4445/health/ready; then ready=1; break; fi
  sleep 2
done
[ "$ready" = 1 ]
export ORY_WORKLOAD=1 ORY_TOKEN_PROFILE=1
export ORY_KRATOS_ADMIN_URL=http://127.0.0.1:4434 ORY_HYDRA_ADMIN_URL=http://127.0.0.1:4445 ORY_PUBLIC_ISSUER=http://127.0.0.1:4444
export ORY_M4_PROFILES_FILE="$PWD/ory-foundation-evidence/workload-profiles.json"
export ORY_M4_EVIDENCE_DIR="$PWD/ory-foundation-evidence/token-profile"
go test -json ./internal/provider/ory -run '^(TestLiveWorkloadClientCredentials|TestLiveTokenProfileFederatedAudienceBlocked)$' -count=1 | tee ory-foundation-evidence/token-profile/tests.jsonl
python3 - <<'PY'
import json
from pathlib import Path
root = Path('ory-foundation-evidence/token-profile')
events = [json.loads(line) for line in (root / 'tests.jsonl').read_text().splitlines()]
required = ('TestLiveWorkloadClientCredentials',
            'TestLiveWorkloadClientCredentials/signed-token-and-shared-scopes',
            'TestLiveWorkloadClientCredentials/wrong-and-missing-resource-audience',
            'TestLiveWorkloadClientCredentials/rotation-invalidates-old-credential',
            'TestLiveWorkloadClientCredentials/suspend-denies-future-issuance',
            'TestLiveTokenProfileFederatedAudienceBlocked')
for name in required:
    if not any(e.get('Test') == name and e.get('Action') == 'pass' for e in events):
        raise SystemExit(f'{name}: missing live PASS evidence')
proof = json.loads((root / 'baobab-trade-workload.json').read_text())
if not proof['logical_audience_matches'] or not proof['actor_type_is_workload']:
    raise SystemExit('Governed signed workload profile not proven')
if proof['canonical_activation_proven'] or proof['actual_consumer_tested']:
    raise SystemExit('Provider token profile cannot establish canonical activation')
print('M4-C governed token profile verified; pinned M4-F audience mismatch fails closed')
PY
