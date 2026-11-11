#!/usr/bin/env python3
"""Validate IAM classifications against the exact Shared pin; render Markdown."""
import argparse
import os
from pathlib import Path
import re
import subprocess
import urllib.request
import yaml

ROOT = Path(__file__).resolve().parents[1]
FIELDS = ('capability_family', 'capability_operation', 'classification', 'tier',
          'owning_adr', 'shared_contract', 'iam_port', 'primary_provider', 'ory_mechanism',
          'keycloak_source', 'cp_dependency', 'digital_estate_dependency',
          'observability', 'security_requirements', 'retirement_dependency',
          'migration_phase', 'implementation_status', 'tests', 'conformance_evidence')
CLASSES = {'PLATFORM_RESOLVABLE_CAPABILITY', 'CANDIDATE_PLATFORM_CAPABILITY',
           'IAM_MANAGEMENT_OPERATION', 'PROVIDER_INTERNAL_OPERATION'}


def shared_file(lock, path):
    commit = lock['source']['commit']
    repository = lock['source']['repository']
    if repository != 'baobab-platform/shared' or not re.fullmatch(r'[0-9a-f]{40}', commit):
        raise ValueError('Shared source must be baobab-platform/shared at an exact commit')
    checkout = os.environ.get('SHARED_REPO_DIR')
    if checkout:
        content = subprocess.check_output(['git', '-C', checkout, 'show', f'{commit}:{path}'])
    else:
        token = os.environ.get('GH_TOKEN', '')
        if token:
            url = f'https://api.github.com/repos/{repository}/contents/{path}?ref={commit}'
            headers = {'Authorization': f'Bearer {token}', 'Accept': 'application/vnd.github.raw+json'}
        else:
            url = f'https://raw.githubusercontent.com/{repository}/{commit}/{path}'
            headers = {}
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=30) as response:
            content = response.read()
    return yaml.safe_load(content)


def validate(matrix, catalogue, definitions):
    keys = {row['capability_key'] for row in catalogue['capabilities'] if row['owner'] == 'baobab-iam'}
    defined = {row['capability_key'] for row in definitions['capabilities']}
    if not keys or not keys <= defined:
        raise ValueError('IAM catalogue entries must have pinned identity definitions')
    seen = set()
    families = set()
    for row in matrix['capabilities']:
        if any(not isinstance(row.get(field), str) or not row[field].strip() for field in FIELDS):
            raise ValueError('Every matrix row must populate every required field')
        key = row['capability_operation']
        if key in seen or row['classification'] not in CLASSES:
            raise ValueError(f'Duplicate operation or invalid classification: {key}')
        seen.add(key)
        families.add(row['capability_family'])
        if row['classification'] == 'PLATFORM_RESOLVABLE_CAPABILITY' and key not in keys:
            raise ValueError(f'{key} is not an IAM capability in the pinned Shared catalogue')
    # ADR-SHARED-017: the catalogue is WHAT, IAM's provider declaration is
    # WHO. Every declared support key must be canonical at the pinned Shared
    # commit. Reconcile the two new November 2026 capabilities explicitly
    # without treating a PARTIAL provider as registered, ACTIVE or certified.
    declaration = yaml.safe_load((ROOT / '.baobab/capability-provider.yaml').read_text())
    if declaration.get('engine', {}).get('engine_id') != 'baobab-iam':
        raise ValueError('IAM provider declaration must belong to baobab-iam')
    expected_provider_support = {
        'baobab-iam.kratos': {'identity.authentication.perform', 'identity.authentication.assurance'},
        'baobab-iam.hydra': {'identity.workload-token.issue'},
        'baobab-iam.keycloak': {'identity.authentication.perform', 'identity.federation.enterprise'},
    }
    actual_provider_support = {}
    for provider in declaration.get('providers', []):
        name = provider['provider_key']
        if name in actual_provider_support:
            raise ValueError(f'duplicate capability provider: {name}')
        if provider.get('simulated') or provider.get('implementation_key') != name.rsplit('.', 1)[-1]:
            raise ValueError(f'{name}: incorrect provider identity or simulation classification')
        supported = set()
        for support in provider['support']:
            key = support['capability_key']
            if key in supported or key not in keys or key not in defined:
                raise ValueError(f'{name}: invalid/uncatalogued/duplicate support {key}')
            if support['implementation_status'] != 'PARTIAL' or support['contract_versions'] != [1]:
                raise ValueError(f'{name}/{key}: full implementation or version cannot be assumed')
            supported.add(key)
        actual_provider_support[name] = supported
    if actual_provider_support != expected_provider_support:
        raise ValueError(f'out-of-sync IAM provider support declarations: {actual_provider_support}')
    matrix_resolvable = {row['capability_operation'] for row in matrix['capabilities']
                         if row['classification'] == 'PLATFORM_RESOLVABLE_CAPABILITY'}
    if matrix_resolvable != keys:
        raise ValueError(f'catalogued IAM matrix classification mismatch: {matrix_resolvable ^ keys}')
    for planned in declaration.get('planned_capabilities', []):
        if planned.get('proposed_key') in keys:
            raise ValueError('an already catalogued capability must not stay planned')
    rows = {row['capability_operation']: row for row in matrix['capabilities']}
    expected = {'identity.federation.enterprise': 'Keycloak',
                'identity.authentication.perform': 'Ory Kratos (native authentication); Keycloak (enterprise federation only)',
                'identity.workload-token.issue': 'Ory Hydra',
                'identity.workload.provision': 'Ory Hydra',
                'identity.token.issuance': 'Ory Hydra',
                'identity.human.provision': 'Ory Kratos',
                'identity.recovery.perform': 'Ory Kratos'}
    for key, provider in expected.items():
        row = rows.get(key, {})
        if row.get('primary_provider') != provider or 'ADR-IAM-0033' not in row.get('owning_adr', ''):
            raise ValueError(f'{key}: target ownership must match Accepted ADR-IAM-0033')
    for key in ('identity.federation.enterprise', 'provider.adapter.normalize'):
        if not rows.get(key, {}).get('retirement_dependency', '').startswith('NONE ('):
            raise ValueError(f'{key}: retained federation/runtime adapter cannot require global retirement')
    if 'Operational Identity Platform' not in families or len(families) != 12:
        raise ValueError('All twelve required capability families must be present')


def render(matrix):
    def cell(value):
        return str(value).replace('|', '\\|').replace('\n', ' ')
    lines = ['# Baobab IAM Capability Matrix', '',
             'Generated from `.baobab/iam-capability-matrix.yaml` by `scripts/iam_capability_matrix.py --write`.', '',
             matrix['metadata']['authority'].strip(), '',
             'Primary Provider records target architecture, not runtime support, selection or activation. Shared governs canonical keys; provider capability labels do not create new platform capabilities.', '',
             'Tests and conformance evidence describe required or available evidence; unit tests do not certify a production provider.', '',
             '| ' + ' | '.join(field.replace('_', ' ').title() for field in FIELDS) + ' |',
             '| ' + ' | '.join('---' for _ in FIELDS) + ' |']
    lines += ['| ' + ' | '.join(cell(row[field]) for field in FIELDS) + ' |' for row in matrix['capabilities']]
    return '\n'.join(lines) + '\n'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    matrix = yaml.safe_load((ROOT / '.baobab/iam-capability-matrix.yaml').read_text())
    # Deliberately use a *read-only* capability-contract pin, not the
    # issuer's runtime contracts.lock.yaml. Its later Shared revision
    # catalogues two additional v1 capabilities but also introduces ACTIVE
    # workload profiles. Pinning those into issuance would be a separate
    # security decision, never an incidental metadata reconciliation.
    lock = yaml.safe_load((ROOT / '.baobab/capability-catalogue.lock.yaml').read_text())
    expected_contracts = {
        'contracts/capability/v1/catalogue.yaml',
        'contracts/capability/v1/catalogue.schema.json',
        'contracts/capability/v1/provider-declaration.schema.json',
        'contracts/identity/v1/capabilities.yaml',
        'contracts/identity/v1/assurance-evaluation.schema.json',
        'contracts/identity/v1/enterprise-federation-start.schema.json',
    }
    if lock.get('schema') != 'baobab-capability-catalogue-consumer-lock' or (
        lock.get('purpose') != 'read-only-provider-declaration-contracts'
        or set(lock.get('contracts', [])) != expected_contracts
        or len(lock.get('contracts', [])) != len(expected_contracts)
    ):
        raise ValueError('read-only capability catalogue pin is invalid')
    validate(matrix, shared_file(lock, 'contracts/capability/v1/catalogue.yaml'),
             shared_file(lock, 'contracts/identity/v1/capabilities.yaml'))
    destination = ROOT / 'docs/governance/iam-capability-matrix.md'
    expected = render(matrix)
    if args.write:
        destination.write_text(expected)
    elif destination.read_text() != expected:
        raise ValueError('Generated Markdown differs; run with --write')
    print('IAM capability classifications and generated Markdown match the pinned Shared catalogue')


if __name__ == '__main__':
    main()
