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
          'owning_adr', 'shared_contract', 'iam_port', 'ory_mechanism',
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
    if 'Operational Identity Platform' not in families or len(families) != 12:
        raise ValueError('All twelve required capability families must be present')


def render(matrix):
    def cell(value):
        return str(value).replace('|', '\\|').replace('\n', ' ')
    lines = ['# Baobab IAM Capability Matrix', '',
             'Generated from `.baobab/iam-capability-matrix.yaml` by `scripts/iam_capability_matrix.py --write`.', '',
             matrix['metadata']['authority'].strip(), '',
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
    lock = yaml.safe_load((ROOT / 'contracts.lock.yaml').read_text())
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
