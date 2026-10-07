#!/usr/bin/env python3
"""Select fixtures from the exact Shared pin; never write canonical lifecycle."""
import json
from pathlib import Path
import sys
import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from iam_capability_matrix import shared_file

lock = yaml.safe_load((ROOT / 'contracts.lock.yaml').read_text())
registry = shared_file(lock, 'contracts/identity/v1/workload-registry.yaml')
selected = {
    'baobab-trade-workload': 'client_credentials',
    'baobab-cp-workload': 'federated_workload_token',
    'baobab-subscriptions-workload': 'federated_workload_token',
}
profiles = {}
for name, credential_type in selected.items():
    entry = registry['workloads'][name]
    if entry['credential_type'] != credential_type:
        raise ValueError(f'{name}: unexpected credential profile at Shared pin')
    if not entry['allowed_scopes'] or not entry['allowed_audiences']:
        raise ValueError(f'{name}: empty Shared scope/audience profile')
    profiles[name] = {key: entry[key] for key in
                      ('environment', 'credential_type', 'status', 'allowed_scopes', 'allowed_audiences')}
destination = ROOT / 'ory-foundation-evidence/workload-profiles.json'
destination.write_text(json.dumps({'shared_commit': lock['source']['commit'],
                                   'workloads': profiles}, indent=2) + '\n')
print('Loaded three workload fixture profiles from the exact Shared commit')
