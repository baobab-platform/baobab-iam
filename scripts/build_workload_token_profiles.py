#!/usr/bin/env python3
"""Build hook configuration from pinned Shared plus governed runtime bindings."""
import argparse
import json
from pathlib import Path
from urllib.parse import urlsplit
import yaml

from iam_capability_matrix import ROOT, shared_file


def build(commit, registry, selected, bindings, environment):
    # One projection serves one environment: a credential issued for one environment never authenticates as a workload of another
    # (ADR-0007 section 102), so a selected workload of any other environment is refused, never copied.
    if environment not in ('development', 'staging', 'production'):
        raise ValueError('An exact environment (development, staging or production) is required')
    if not isinstance(bindings, dict) or not selected or len(set(selected)) != len(selected):
        raise ValueError('Select distinct workloads and supply a binding object')
    if set(bindings) - set(selected):
        raise ValueError('Bindings must belong to selected workloads')
    profiles = {}
    seen_bindings = set()
    for name in selected:
        entry = registry['workloads'][name]
        profile = {key: entry[key] for key in
                   ('environment', 'credential_type', 'status', 'allowed_scopes', 'allowed_audiences')}
        if profile['environment'] != environment:
            raise ValueError(f'{name} belongs to environment {profile["environment"]}, not {environment}')
        if profile['credential_type'] == 'federated_workload_token':
            binding = bindings.get(name)
            if not isinstance(binding, dict) or set(binding) != {'issuer', 'subject'}:
                raise ValueError('Every selected federated workload needs an exact issuer/subject binding')
            if any(not isinstance(value, str) or not value or value.strip() != value
                   for value in binding.values()):
                raise ValueError('Bindings must contain canonical nonempty strings')
            issuer = urlsplit(binding['issuer'])
            if issuer.scheme != 'https' or not issuer.netloc or issuer.username or issuer.password or issuer.query or issuer.fragment:
                raise ValueError('Projected assertion issuer must be an exact HTTPS issuer without credentials/query/fragment')
            if '*' in binding['issuer'] or '*' in binding['subject']:
                raise ValueError('Wildcard federation bindings are forbidden')
            identity = (binding['issuer'], binding['subject'])
            if identity in seen_bindings:
                raise ValueError('Distinct workloads cannot share a projected issuer/subject identity')
            seen_bindings.add(identity)
        elif profile['credential_type'] == 'client_credentials':
            if name in bindings:
                raise ValueError('Client-credentials workloads cannot acquire federation bindings')
        else:
            raise ValueError('Unsupported Shared credential profile')
        profiles[name] = profile
    # Scope/audience/profile/lifecycle values are copied exclusively from Shared.
    # The deployment input can supply only exact federation bindings.
    return {'shared_commit': commit, 'environment': environment, 'workloads': profiles, 'bindings': bindings}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--workload', action='append', required=True)
    parser.add_argument('--bindings', type=Path)
    parser.add_argument('--environment', required=True, choices=('development', 'staging', 'production'))
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    lock = yaml.safe_load((ROOT / 'contracts.lock.yaml').read_text())
    registry = shared_file(lock, 'contracts/identity/v1/workload-registry.yaml')
    bindings = json.loads(args.bindings.read_text()) if args.bindings else {}
    config = build(lock['source']['commit'], registry, args.workload, bindings, args.environment)
    args.output.write_text(json.dumps(config, indent=2) + '\n')
    print('Built selected token profiles from the exact Shared pin and governed bindings')


if __name__ == '__main__':
    main()
