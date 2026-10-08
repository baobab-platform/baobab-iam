#!/usr/bin/env python3
"""Validate or publish an owner-supplied Shared runtime profile to CP.

CP owns target registration, evidence admission, monotonic revisions and replay.
This client never creates support, bindings, lifecycle or readiness authority.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
import re
from pathlib import Path
import ssl
import sys
import subprocess
import urllib.error
import urllib.parse
import urllib.request

from provider_publication import load_shared

MAX_BODY = 65536
ENDPOINT = '/internal/identity-runtime/v1/profiles'


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON property')
        result[key] = value
    return result


def decode(raw):
    if len(raw) > MAX_BODY:
        raise ValueError('profile or receipt exceeds size limit')
    return json.loads(raw, object_pairs_hook=unique_object)


def timestamp(value):
    return datetime.fromisoformat(value.replace('Z', '+00:00'))


def validate(contracts, profile, target, now):
    # Do not echo schema errors: malformed owner input might contain secrets.
    if contracts.errors('identity/v1/provider-runtime-profile.schema.json', profile):
        raise ValueError('profile violates the pinned Shared contract')
    if any(profile[key] != value for key, value in target.items()):
        raise ValueError('profile does not match the reviewed publication target')
    published = timestamp(profile['published_at'])
    if published > now:
        raise ValueError('future publication denied')
    seen = set()
    for observation in profile['capability_observations']:
        facet = observation['capability']
        if facet in seen:
            raise ValueError('duplicate runtime facet')
        seen.add(facet)
        evidence = observation.get('evidence')
        if evidence and (evidence['artifact_digest'] != profile['artifact_digest'] or
                         timestamp(evidence['observed_at']) > published or
                         timestamp(evidence['expires_at']) <= now):
            raise ValueError('mismatched, future or expired runtime evidence')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('CP redirect denied')


def publish(origin, profile, token, ca_file=None, timeout=10, opener=None):
    parsed = urllib.parse.urlsplit(origin)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or
            parsed.password or parsed.query or parsed.fragment or parsed.path not in ('', '/')):
        raise ValueError('CP origin must be an HTTPS origin without credentials or path')
    if not re.fullmatch(r'[A-Za-z0-9._~+/\-]+=*', token):
        raise ValueError('missing or malformed observer bearer token')
    if not 0 < timeout <= 30:
        raise ValueError('timeout must be between zero and 30 seconds')
    if opener is None:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), NoRedirect(),
            urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=ca_file)))
    raw = json.dumps(profile, sort_keys=True, separators=(',', ':')).encode()
    request = urllib.request.Request(origin.rstrip('/') + ENDPOINT, data=raw, method='POST',
                                     headers={'Authorization': 'Bearer ' + token,
                                              'Content-Type': 'application/json', 'Accept': 'application/json'})
    try:
        # No retry: CP alone determines whether an exact revision is a replay.
        with opener.open(request, timeout=timeout) as response:
            status = response.status
            receipt = decode(response.read(MAX_BODY + 1))
    except (urllib.error.URLError, OSError) as error:
        raise ValueError('CP publication unavailable or denied; no receipt accepted') from error
    expected = {'status': 'RECORDED' if status == 201 else 'REPLAY',
                'provider_id': profile['provider_id'],
                'engine_instance_id': profile['engine_instance_id'], 'revision': profile['revision']}
    if status not in (200, 201) or receipt != expected or type(receipt.get('revision')) is not int:
        raise ValueError('CP receipt does not match the submitted revision and target')
    return receipt, hashlib.sha256(raw).hexdigest()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--shared-checkout', type=Path, required=True)
    parser.add_argument('--profile', type=Path, required=True)
    for name in ('provider-id', 'engine-instance-id', 'artifact-digest',
                 'configuration-reference', 'security-domain-reference'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--publish', action='store_true')
    parser.add_argument('--cp-origin')
    parser.add_argument('--ca-file')
    parser.add_argument('--timeout', type=float, default=10)
    args = parser.parse_args(argv)
    try:
        module, commit = load_shared(args.shared_checkout.resolve())
        profile = decode(args.profile.read_bytes())
        target = {key: getattr(args, key) for key in ('provider_id', 'engine_instance_id',
                  'artifact_digest', 'configuration_reference', 'security_domain_reference')}
        validate(module.Contracts(args.shared_checkout / 'contracts'), profile, target, datetime.now(timezone.utc))
        report = {'classification': 'CONSTRUCTION_PREFLIGHT', 'shared_commit': commit,
                  'runtime_authority_verified': False, 'published': False}
        if args.publish:
            receipt, digest = publish(args.cp_origin or '', profile,
                                      os.environ.get('CP_RUNTIME_OBSERVER_TOKEN', ''), args.ca_file, args.timeout)
            report.update(classification='CP_PROFILE_RECORDED', published=True,
                          receipt=receipt, submitted_sha256=digest)
        print(json.dumps(report, sort_keys=True))
        return 0
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as error:
        # No server body, input values or credential material in errors.
        print('runtime profile publication denied: ' + (str(error) if isinstance(error, ValueError)
              and not isinstance(error, json.JSONDecodeError) else 'invalid input or unavailable configuration'), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
