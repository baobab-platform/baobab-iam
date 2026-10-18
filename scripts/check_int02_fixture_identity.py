#!/usr/bin/env python3
"""Recognise only Shared's owner-approved disposable INT-02 proof identity.

This is an inventory exclusion, never a credential/activation path. The live
suite must separately prove that no product client exists. Exact row equality
prevents the named exception expanding to another environment or authority.
"""
import json
import sys

CLIENT_ID = 'baobab-int02-pulse-consumer'
EXPECTED = {
    'repository': 'baobab-platform/infrastructure',
    'owner': 'baobab-platform/infrastructure',
    'runtime': 'INT-02 disposable real-component Pulse qualification consumer',
    'environment': 'development',
    'allowed_audiences': ['baobab-control-plane', 'baobab-pulse'],
    'allowed_scopes': ['context:resolve', 'intelligence:evidence:search'],
    'credential_type': 'client_credentials',
    'rotation_owner': 'baobab-platform/infrastructure',
    'status': 'ACTIVE',
}


def fixture_only(entry):
    return isinstance(entry, dict) and entry == EXPECTED


if __name__ == '__main__':
    try:
        valid = fixture_only(json.load(sys.stdin))
    except (ValueError, OSError):
        valid = False
    # No registry, issuer, credential or caller-controlled values in output.
    print('Exact INT-02 fixture identity verified' if valid else 'INT-02 fixture identity rejected')
    sys.exit(0 if valid else 1)
