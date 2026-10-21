#!/usr/bin/env python3
"""IAM-owned documents/read-back checks for the two named CMS proof identities.

Only a disposable orchestrator may provision these documents through its real
issuer administration. This helper issues no token or grant and never declares
runtime qualification. Shared remains the canonical registry authority.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import secrets
import sys
import subprocess
import uuid

CALLER = 'baobab-int03-cms-consumer'
VALIDATOR = 'baobab-int03-cms-validator'
EXPECTED = {
    CALLER: {
        'repository': 'baobab-platform/infrastructure', 'owner': 'baobab-platform/infrastructure',
        'runtime': 'INT-03 disposable real-component CMS qualification consumer',
        'environment': 'development', 'allowed_audiences': ['baobab-control-plane', 'baobab-cms'],
        'allowed_scopes': ['context:resolve', 'content:entry:resolve'], 'credential_type': 'client_credentials',
        'rotation_owner': 'baobab-platform/infrastructure', 'status': 'ACTIVE',
    },
    VALIDATOR: {
        'repository': 'baobab-platform/baobab-cms', 'owner': 'baobab-platform/baobab-cms',
        'runtime': 'INT-03 disposable real-component CMS context validator',
        'environment': 'development', 'allowed_audiences': ['baobab-control-plane'],
        'allowed_scopes': ['context:validate'], 'validates_audiences': ['baobab-cms'],
        'credential_type': 'client_credentials', 'rotation_owner': 'baobab-platform/baobab-cms', 'status': 'ACTIVE',
    },
}


def fixture_only(client_id, entry):
    return client_id in EXPECTED and isinstance(entry, dict) and entry == EXPECTED[client_id]


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate fixture field')
        result[key] = value
    return result


def client_document(name, credential):
    row = EXPECTED[name]
    return {
        'clientId': name, 'enabled': True, 'publicClient': False, 'bearerOnly': False,
        'protocol': 'openid-connect', 'clientAuthenticatorType': 'client-secret',
        'serviceAccountsEnabled': True, 'standardFlowEnabled': False,
        'directAccessGrantsEnabled': False, 'implicitFlowEnabled': False,
        'authorizationServicesEnabled': False, 'fullScopeAllowed': False,
        'secret': credential, 'redirectUris': [], 'webOrigins': [],
        'attributes': {'access.token.lifespan': '60', 'oauth2.device.authorization.grant.enabled': 'false'},
        'defaultClientScopes': ['basic', 'actor-type-workload'],
        'optionalClientScopes': list(row['allowed_scopes']),
    }


def build_clients(registry, deadline, now=None):
    """Copy only accepted ceilings, with independent per-run random secrets.

    Scope mappers belong to IAM's maintained scope inventory. Optional scope
    allocation yields one resource audience per token, without validator scope
    on the caller, content scope on the validator or default business scopes.
    """
    now = now or datetime.now(timezone.utc)
    if not isinstance(deadline, datetime) or not isinstance(now, datetime) or deadline.tzinfo is None or now.tzinfo is None or not 60 < (deadline - now).total_seconds() <= 5400:
        raise ValueError('invalid immutable proof deadline')
    rows = registry.get('workloads', {}) if isinstance(registry, dict) else {}
    if not isinstance(rows, dict):
        raise ValueError('invalid registry document')
    if any(not fixture_only(name, rows.get(name)) for name in EXPECTED):
        raise ValueError('unapproved development registry boundary')
    clients = {}
    for name, row in EXPECTED.items():
        clients[name] = client_document(name, secrets.token_urlsafe(48))
    if clients[CALLER]['secret'] == clients[VALIDATOR]['secret']:
        raise ValueError('independent fixture credentials required')
    return clients


def verify_readback(expected, observed, secret_response):
    """Judge issuer API read-back, not a create command's zero exit code.

    Server-managed fields may exist, but every configured security boundary,
    exact scope set, absence of extra protocol mappers and separately read-back
    secret must agree. The orchestrator owns the actual source/protocol evidence.
    """
    if not isinstance(expected, dict) or not isinstance(expected.get('clientId'), str) or expected.get('clientId') not in EXPECTED or not isinstance(observed, dict) or not isinstance(secret_response, dict):
        return False
    credential = expected.get('secret')
    if not isinstance(credential, str) or len(credential) < 32 or expected != client_document(expected['clientId'], credential):
        return False
    for field, value in expected.items():
        if field == 'secret':
            continue
        actual = observed.get(field)
        if isinstance(value, list):
            if not isinstance(actual, list) or not all(isinstance(v, str) for v in actual) or len(actual) != len(value) or sorted(actual) != sorted(value):
                return False
        elif field == 'attributes':
            if not isinstance(actual, dict) or any(actual.get(k) != v for k, v in value.items()):
                return False
            # Additional attributes can enable grant/exchange mechanisms. Read
            # back exactly the requested map rather than guessing which are safe.
            if actual != value:
                return False
        elif type(actual) is not type(value) or actual != value:
            return False
    if observed.get('protocolMappers', []) != []:
        return False
    if 'secret' in observed and observed['secret'] not in (expected['secret'], '**********'):
        return False
    actual_secret = secret_response.get('value')
    return (secret_response.get('type') == 'secret' and isinstance(actual_secret, str)
            and actual_secret.isascii() and credential.isascii()
            and secrets.compare_digest(actual_secret, credential))


def verify_runtime_readback(expected, client_uuid, read):
    """Read exact issuer endpoints through an orchestrator-owned transport.

    Construct the client/service-account association here: Keycloak's live
    service-account UserRepresentation omits serviceAccountClientId. Empty
    embedded fields likewise cannot prove absence of group or broker links.
    The caller owns authenticated bounded I/O and actual endpoint provenance;
    a synthetic transport is only a unit test, never qualification evidence.
    """
    def valid_uuid(value):
        try:
            return isinstance(value, str) and str(uuid.UUID(value)) == value
        except (ValueError, AttributeError):
            return False
    try:
        if not valid_uuid(client_uuid) or not callable(read):
            return False
        client_path = 'clients/' + client_uuid
        observed = read(client_path)
        secret_response = read(client_path + '/client-secret')
        if not verify_readback(expected, observed, secret_response) or observed.get('id') != client_uuid:
            return False
        # Only this client-specific endpoint establishes which service account
        # belongs to the client. Do not search by a caller-selected username.
        account = read(client_path + '/service-account-user')
        if (not isinstance(account, dict) or not valid_uuid(account.get('id'))
                or account['id'] == client_uuid or account.get('enabled') is not True
                or account.get('username') != 'service-account-' + expected['clientId']
                or account.get('serviceAccountClientId') not in (None, expected['clientId'])):
            return False
        user_path = 'users/' + account['id']
        mappings = read(user_path + '/role-mappings')
        # One result is sufficient to deny, but a later/selected page cannot
        # establish absence. Always read from the first page, never a hint.
        groups = read(user_path + '/groups?first=0&max=1')
        federated = read(user_path + '/federated-identity')
        if not isinstance(mappings, dict) or not isinstance(groups, list) or not isinstance(federated, list):
            return False
        if set(mappings) - {'realmMappings', 'clientMappings'}:
            return False
        if mappings.get('realmMappings', []) != [] or mappings.get('clientMappings', {}) != {} or groups or federated:
            return False
        if (account.get('federatedIdentities', []) not in (None, []) or account.get('realmRoles', []) not in (None, [])
                or account.get('clientRoles', {}) not in (None, {}) or account.get('groups', []) not in (None, [])
                or account.get('federationLink') not in (None, '')):
            return False
        return True
    except Exception:
        # Missing/malformed response or a failed administration read denies.
        # Never copy response bodies, paths or credential-bearing exceptions.
        return False


def load_registry(checkout, repository=None):
    """Require the committed IAM lock and immutable Shared registry blob."""
    from provider_publication import load_shared
    import yaml
    repository = repository or Path(__file__).resolve().parents[1]
    iam_head = subprocess.check_output(['git', '-C', str(repository), 'rev-parse', 'HEAD'], text=True).strip()
    committed_lock = subprocess.check_output(['git', '-C', str(repository), 'show', iam_head + ':contracts.lock.yaml'])
    if (repository / 'contracts.lock.yaml').read_bytes() != committed_lock:
        raise ValueError('IAM lock differs from committed authority')
    source = yaml.safe_load(committed_lock)['source']
    if source['repository'] != 'baobab-platform/shared':
        raise ValueError('unapproved Shared authority')
    _, shared_head = load_shared(checkout, repository=repository)
    if shared_head != source['commit']:
        raise ValueError('Shared verification differs from committed IAM lock')
    blob = subprocess.check_output(['git', '-C', str(checkout), 'show', shared_head + ':contracts/identity/v1/workload-registry.yaml'])
    return yaml.safe_load(blob)


def prepare(checkout, output, deadline):
    registry = load_registry(checkout)
    clients = build_clients(registry, deadline)
    output.mkdir(mode=0o700)  # exclusive: never overwrite an existing handoff
    created = []
    try:
        for name, document in clients.items():
            target = output / (name + '.json')
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            created.append(target)
            with os.fdopen(fd, 'w') as handle:
                json.dump(document, handle)
                handle.write('\n')
        return clients
    except BaseException:
        for target in created:
            target.unlink(missing_ok=True)
        output.rmdir()
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='action', required=True)
    check = commands.add_parser('check')
    check.add_argument('client_id', choices=tuple(EXPECTED))
    make = commands.add_parser('prepare')
    make.add_argument('--shared-checkout', type=Path, required=True)
    make.add_argument('--output', type=Path, required=True)
    make.add_argument('--deadline', required=True)
    args = parser.parse_args()
    try:
        if args.action == 'check':
            if not fixture_only(args.client_id, json.load(sys.stdin, object_pairs_hook=unique)):
                raise ValueError('unapproved fixture identity')
            print('Exact development CMS fixture identity verified')
        else:
            deadline = datetime.fromisoformat(args.deadline.replace('Z', '+00:00'))
            prepare(args.shared_checkout, args.output, deadline)
            print('Two private development CMS fixture documents prepared; qualification not claimed')
    except (ValueError, OSError, KeyError, TypeError, subprocess.CalledProcessError):
        print('Development CMS fixture refused', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
