#!/usr/bin/env python3
"""Build hook configuration from pinned Shared plus governed runtime bindings."""
import argparse
import json
from pathlib import Path
from urllib.parse import urlsplit
import yaml

from iam_capability_matrix import ROOT, shared_file


def human_scope_audiences(profile, scope_registry):
    """Copy each profile scope's audience exactly from the pinned scope registry.

    Governed buyer consent grants the audience the registry issues the granted
    scopes for (internal/tokenprofile HumanConsent), never one the requester
    names. The Shared validator already requires every profile scope to be
    human-only and issued for a profile audience; a projection that disagrees
    is refused rather than repaired.
    """
    if not isinstance(scope_registry, dict) or not isinstance(scope_registry.get('scopes'), list):
        raise ValueError('A human token profile needs the pinned scope registry')
    entries = {}
    for entry in scope_registry['scopes']:
        if entry.get('name') in entries:
            raise ValueError(f'Duplicate scope registry entry {entry.get("name")}')
        entries[entry.get('name')] = entry
    audiences = {}
    for scope in profile['scopes']:
        entry = entries.get(scope)
        if entry is None or entry.get('allowed_actors') != ['human']:
            raise ValueError(f'{scope} is not a registered human-only scope')
        audience = entry.get('audience')
        if not isinstance(audience, list) or not audience or not set(audience) <= set(profile['audiences']):
            raise ValueError(f'{scope} is not issued for the human token profile audiences')
        audiences[scope] = list(audience)
    return audiences


def build(commit, registry, selected, bindings, environment, scope_registry=None):
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
        # ADR-SHARED-042 section 14: an estate BFF's human token profile is
        # copied exactly from Shared, like every other ceiling, and only for a
        # confidential client.
        if 'human_token_profile' in entry:
            if entry['credential_type'] != 'client_credentials':
                raise ValueError('Only a client-credentials estate BFF may carry a human token profile')
            profile['human_token_profile'] = entry['human_token_profile']
            profile['human_scope_audiences'] = human_scope_audiences(entry['human_token_profile'], scope_registry)
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
    # Scope/audience/profile/lifecycle values, including human scope audiences, are copied exclusively from Shared.
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
    scopes = shared_file(lock, 'contracts/authorization/v1/scope-registry.yaml')
    bindings = json.loads(args.bindings.read_text()) if args.bindings else {}
    config = build(lock['source']['commit'], registry, args.workload, bindings, args.environment, scopes)
    args.output.write_text(json.dumps(config, indent=2) + '\n')
    print('Built selected token profiles from the exact Shared pin and governed bindings')


if __name__ == '__main__':
    main()
