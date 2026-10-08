#!/usr/bin/env python3
"""Read-only IAM registration preflight; never activate or publish authority.

Uses the exact clean Shared checkout named by contracts.lock.yaml. Output is a
construction report, not a runtime profile, support attestation or readiness
decision. --require-registrable fails if any provider has no canonical support.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile

import yaml

ROOT = Path(__file__).resolve().parents[1]
INDEX_PATH = 'capability/v1/registration-bundles.yaml'
INDEX_REF = 'capability/v1/registration.schema.json#/$defs/RegistrationBundleIndex'


def bundle_candidate(module, contracts, registrations, index, provider_key, path):
    """Prospective Shared review input; never CP registration or activation."""
    errors = contracts.errors(INDEX_REF, index)
    if errors:
        raise ValueError('invalid pinned registration index: ' + '; '.join(errors))
    selected = [r for r in registrations if r['provider']['provider_key'] == provider_key]
    if len(selected) != 1:
        raise ValueError('selected provider has no canonical IMPLEMENTED support')
    # Round-trip through the same canonical comparison used for reviewed exports.
    compare_exports(module, contracts, selected, selected)
    paths, keys = set(), set()
    for entry in index['bundles']:
        key = entry['provider_key']
        if entry['path'] in paths or key in keys:
            raise ValueError('duplicate pinned registration index entry')
        paths.add(entry['path'])
        keys.add(key)
    if path in paths or provider_key in keys:
        raise ValueError('registration already indexed; reconcile the existing bundle')
    proposed = {'schema': dict(index['schema']), 'bundles': [dict(e) for e in index['bundles']] + [
        {'path': path, 'engine_id': 'baobab-iam', 'provider_key': provider_key}]}
    errors = contracts.errors(INDEX_REF, proposed)
    if errors:
        raise ValueError('invalid candidate registration index: ' + '; '.join(errors))
    return proposed, selected[0]


def write_bundle_candidate(output, path, index, registration, receipt):
    """Publish a complete review directory atomically, refusing replacement."""
    if output.exists() or output.is_symlink():
        raise ValueError('candidate output already exists')
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=output.parent) as temporary:
        root = Path(temporary) / 'candidate'
        target = root / 'contracts' / path
        target.parent.mkdir(parents=True)
        target.write_text(json.dumps(registration, indent=2, sort_keys=True) + '\n')
        target = root / 'contracts' / INDEX_PATH
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(yaml.safe_dump(index, sort_keys=False))
        (root / 'receipt.json').write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
        root.rename(output)


def load_shared(checkout, repository=ROOT):
    lock = yaml.safe_load((repository / 'contracts.lock.yaml').read_text())
    source = lock['source']
    if source['repository'] != 'baobab-platform/shared':
        raise ValueError('unapproved contract authority')
    commit = subprocess.check_output(
        ['git', '-C', str(checkout), 'rev-parse', 'HEAD'], text=True).strip()
    if commit != source['commit']:
        raise ValueError('Shared checkout does not match the immutable IAM pin')
    if subprocess.check_output(
            ['git', '-C', str(checkout), 'status', '--porcelain', '--untracked-files=all'], text=True).strip():
        raise ValueError('Shared checkout must be clean, including untracked files')
    spec = importlib.util.spec_from_file_location(
        'iam_pinned_capability_catalogue', checkout / 'scripts/capability_catalogue.py')
    module = importlib.util.module_from_spec(spec)
    previous = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    return module, commit


def prepare(module, checkout, declaration, repository=ROOT):
    contracts = module.Contracts(checkout / 'contracts')
    errors = module.validate_catalogue(contracts)
    errors += module.validate_declaration(contracts, declaration, repository, 'baobab-iam')
    if errors:
        raise ValueError('; '.join(errors))
    registrations, excluded = [], []
    for provider in sorted(declaration['providers'], key=lambda p: p['provider_key']):
        for support in provider['support']:
            if support['implementation_status'] != 'IMPLEMENTED':
                excluded.append({
                    'provider_key': provider['provider_key'],
                    'capability_key': support['capability_key'],
                    'implementation_status': support['implementation_status'],
                })
        if any(s['implementation_status'] == 'IMPLEMENTED' for s in provider['support']):
            # Shared validates and generates the wire format; no IAM shadow schema.
            registrations.append(module.generate_registration(
                contracts, declaration, provider['provider_key'], 'DRAFT'))
    return contracts, registrations, excluded


def compare_exports(module, contracts, registrations, exports):
    """Compare reviewed EngineRegistration exports, not CP lifecycle/health.

    Input is a JSON array of canonical EngineRegistration documents. Missing,
    extra, duplicate and substituted declarations all count as drift. This
    offline comparison has no freshness or runtime-authority claim.
    """
    if not isinstance(exports, list):
        raise ValueError('registration export must be a JSON array')
    actual = {}
    for entry in exports:
        errors = contracts.errors(module.REGISTRATION_REF, entry)
        if errors:
            raise ValueError('invalid registration export: ' + '; '.join(errors))
        key = entry['provider']['provider_key']
        if entry['repository'] != 'baobab-iam' or key in actual:
            raise ValueError('foreign or duplicate registration export')
        actual[key] = entry
    expected = {entry['provider']['provider_key']: entry for entry in registrations}
    drift = []
    for key in sorted(set(actual) | set(expected)):
        if key not in expected:
            drift.append({'provider_key': key, 'reason': 'UNDECLARED_SUPPORT'})
        elif key not in actual:
            drift.append({'provider_key': key, 'reason': 'MISSING_REGISTRATION'})
        else:
            if actual[key] != expected[key]:
                drift.append({'provider_key': key, 'reason': 'DECLARATION_MISMATCH'})
    return drift


def compare_executable_support(declaration, census):
    """Bind publication eligibility to adapter declarations; never runtime truth."""
    if not isinstance(census, dict) or set(census) != {'classification', 'providers'} or census['classification'] != 'EXECUTABLE_CONSTRUCTION_CENSUS':
        raise ValueError('invalid executable support census')
    rows = census['providers']
    if not isinstance(rows, list):
        raise ValueError('invalid executable provider list')
    actual = {}
    for row in rows:
        if not isinstance(row, dict) or set(row) != {'provider_key', 'implementation_key', 'support'}:
            raise ValueError('invalid executable provider declaration')
        key = row['provider_key']
        if not isinstance(key, str) or key in actual:
            raise ValueError('duplicate or invalid executable provider')
        if not isinstance(row['implementation_key'], str) or not row['implementation_key']:
            raise ValueError('invalid executable implementation key')
        support = row['support']
        if not isinstance(support, list):
            raise ValueError('invalid executable support list')
        seen_capabilities = set()
        for entry in support:
            if not isinstance(entry, dict) or set(entry) != {'capability_key', 'contract_versions', 'implementation_status'}:
                raise ValueError('invalid executable support entry')
            capability = entry['capability_key']
            if not isinstance(capability, str) or not capability or capability in seen_capabilities:
                raise ValueError('duplicate or invalid executable capability')
            seen_capabilities.add(capability)
            versions = entry['contract_versions']
            if (not isinstance(versions, list) or not versions or
                    any(type(version) is not int or version < 1 for version in versions) or
                    len(set(versions)) != len(versions)):
                raise ValueError('invalid executable contract versions')
            if entry['implementation_status'] not in ('IMPLEMENTED', 'PARTIAL', 'UNSUPPORTED'):
                raise ValueError('invalid executable implementation status')
        actual[key] = row
    expected = {p['provider_key']: {k: p[k] for k in ('provider_key', 'implementation_key', 'support')}
                for p in declaration['providers']}
    # Evidence paths remain validated through Shared; executable code reports
    # conformance, not copies of the declaration's documentary evidence.
    for row in expected.values():
        row['support'] = [{k: s[k] for k in ('capability_key', 'contract_versions', 'implementation_status')}
                          for s in row['support']]
    if actual != expected:
        raise ValueError('canonical declaration and executable support drift')


def read_evidence_export(path):
    """Reject ambiguous wire evidence before any schema or drift comparison."""
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate registration evidence property')
            result[key] = value
        return result

    def reject_constant(value):
        raise ValueError('non-finite registration evidence number')

    return json.loads(path.read_text(), object_pairs_hook=unique_object,
                      parse_constant=reject_constant)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--shared-checkout', type=Path, required=True)
    parser.add_argument('--registration-export', type=Path)
    parser.add_argument('--executable-support-export', type=Path)
    parser.add_argument('--require-registrable', action='store_true')
    parser.add_argument('--bundle-provider')
    parser.add_argument('--bundle-path')
    parser.add_argument('--bundle-output', type=Path)
    parser.add_argument('--expected-source-revision')
    parser.add_argument('--expected-index-sha256')
    args = parser.parse_args(argv)
    try:
        module, commit = load_shared(args.shared_checkout.resolve())
        path = ROOT / '.baobab/capability-provider.yaml'
        raw = path.read_bytes()
        declaration = yaml.safe_load(raw)
        contracts, registrations, excluded = prepare(
            module, args.shared_checkout.resolve(), declaration)
        if args.executable_support_export:
            compare_executable_support(declaration, read_evidence_export(args.executable_support_export))
        elif args.require_registrable:
            raise ValueError('strict publication requires an executable support census')
        drift = compare_exports(module, contracts, registrations,
                                read_evidence_export(args.registration_export)) if args.registration_export else None
        eligible = {r['provider']['provider_key'] for r in registrations}
        blocked = sorted(p['provider_key'] for p in declaration['providers'] if p['provider_key'] not in eligible)
        report = {
            'classification': 'CONSTRUCTION_PREFLIGHT',
            'shared_commit': commit,
            'declaration_sha256': hashlib.sha256(raw).hexdigest(),
            'source_revision': subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip(),
            'source_dirty': bool(subprocess.check_output(['git', '-C', str(ROOT), 'status', '--porcelain'], text=True).strip()),
            'draft_registrations': registrations,
            'excluded_support': excluded,
            'executable_support_verified': bool(args.executable_support_export),
            'blocked_providers': blocked,
            'registration_drift': drift,
            'runtime_authority_verified': False,
        }
        bundle_options = (args.bundle_provider, args.bundle_path, args.bundle_output,
                          args.expected_source_revision, args.expected_index_sha256)
        if any(bundle_options):
            if not all(bundle_options):
                raise ValueError('bundle preparation requires provider, path, output, source revision and index digest')
            if report['source_dirty'] or report['source_revision'] != args.expected_source_revision:
                raise ValueError('bundle source must be clean and match the reviewed revision')
            if drift:
                raise ValueError('registration export drift blocks bundle preparation')
            if args.require_registrable and blocked:
                raise ValueError('strict registration requires every provider to be registrable')
            # Execute this revision, rather than trust an unbound census export.
            census = json.loads(subprocess.check_output(
                ['go', 'run', './cmd/provider-support-census'], cwd=ROOT, text=True))
            compare_executable_support(declaration, census)
            index_raw = (args.shared_checkout / 'contracts' / INDEX_PATH).read_bytes()
            digest = hashlib.sha256(index_raw).hexdigest()
            if digest != args.expected_index_sha256:
                raise ValueError('registration index changed; reconcile the reviewed base')
            proposed, registration = bundle_candidate(
                module, contracts, registrations, yaml.safe_load(index_raw), args.bundle_provider, args.bundle_path)
            if (args.shared_checkout / 'contracts' / args.bundle_path).exists():
                raise ValueError('candidate path already exists in Shared')
            receipt = {'classification': 'SHARED_REGISTRATION_REVIEW_CANDIDATE',
                       'source_revision': report['source_revision'], 'shared_commit': commit,
                       'base_index_sha256': digest, 'declaration_sha256': report['declaration_sha256'],
                       'provider_key': args.bundle_provider, 'bundle_path': args.bundle_path,
                       'bundle_sha256': hashlib.sha256((json.dumps(registration, indent=2, sort_keys=True) + '\n').encode()).hexdigest(),
                       'runtime_authority_verified': False, 'published': False}
            output = args.bundle_output.resolve()
            if output.is_relative_to(ROOT) or output.is_relative_to(args.shared_checkout.resolve()):
                raise ValueError('review output must be outside IAM and the pinned Shared checkout')
            if subprocess.check_output(['git', '-C', str(ROOT), 'status', '--porcelain', '--untracked-files=all'], text=True).strip():
                raise ValueError('bundle source changed during preparation')
            if subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip() != args.expected_source_revision:
                raise ValueError('bundle source revision changed during preparation')
            load_shared(args.shared_checkout.resolve())
            write_bundle_candidate(output, args.bundle_path, proposed, registration, receipt)
            report['bundle_candidate'] = receipt
        print(json.dumps(report, indent=2, sort_keys=True))
        return 2 if drift or (args.require_registrable and blocked) else 0
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError, yaml.YAMLError) as error:
        print(f'publication preflight denied: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
