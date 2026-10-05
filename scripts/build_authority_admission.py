#!/usr/bin/env python3
"""Publish a short-lived Shared workload projection; certificate grants stay separate."""
import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import tempfile
import yaml
from iam_capability_matrix import ROOT, shared_file


def build(commit, registry, environment, now, ttl):
    if environment not in ('development', 'staging', 'production') or not 0 < ttl <= 900:
        raise ValueError('An exact environment and validity of 1..900 seconds are required')
    if len(commit) != 40 or any(c not in '0123456789abcdef' for c in commit):
        raise ValueError('The reviewed Shared commit must be exact')
    workloads = {}
    for name, entry in registry['workloads'].items():
        if entry['environment'] != environment:
            continue
        if entry['status'] not in ('PROVISIONED', 'ACTIVE', 'SUSPENDED', 'REVOKED', 'RETIRED'):
            raise ValueError('Unknown canonical workload lifecycle')
        workloads[name] = {k: entry[k] for k in
                           ('status', 'environment', 'allowed_audiences', 'allowed_scopes')}
    stamp = lambda value: value.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')
    return {'shared_commit': commit, 'environment': environment,
            'issued_at': stamp(now), 'valid_until': stamp(now + timedelta(seconds=ttl)),
            'workloads': workloads}


def publish(path, document):
    # Atomic replacement ensures request readers see one complete projection.
    fd, temporary = tempfile.mkstemp(prefix='admission-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as output:
            json.dump(document, output, indent=2)
            output.write('\n')
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--environment', required=True)
    parser.add_argument('--ttl-seconds', type=int, default=300)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    lock = yaml.safe_load((ROOT / 'contracts.lock.yaml').read_text())
    registry = shared_file(lock, 'contracts/identity/v1/workload-registry.yaml')
    document = build(lock['source']['commit'], registry, args.environment,
                     datetime.now(timezone.utc), args.ttl_seconds)
    publish(args.output, document)
    print('Published finite canonical admission projection from reviewed Shared pin')


if __name__ == '__main__':
    main()
