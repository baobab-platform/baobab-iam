"""Canonical publication client tests; no provider activation or live evidence."""
import copy
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock
import urllib.error

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
spec = importlib.util.spec_from_file_location('runtime_publication', ROOT / 'scripts/runtime_profile_publication.py')
publication = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publication)


class RuntimePublicationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        checkout = Path(os.environ['SHARED_REPO_DIR']).resolve()
        module, _ = publication.load_shared(checkout)
        cls.contracts = module.Contracts(checkout / 'contracts')

    def setUp(self):
        self.now = datetime(2026, 10, 8, 10, tzinfo=timezone.utc)
        self.profile = {
            'provider_id': 'provider_aaaaaaaa', 'engine_instance_id': 'ei_aaaaaaaa',
            'configuration_reference': 'ref_config', 'security_domain_reference': 'ref_domain',
            'artifact_digest': 'sha256:' + 'a' * 64, 'revision': 1,
            'published_at': '2026-10-08T09:00:00Z', 'capability_observations': [{
                'capability': 'WORKLOAD_TOKEN_ISSUANCE', 'verification_status': 'VERIFIED',
                'evidence': {'evidence_reference': 'ref_support', 'artifact_digest': 'sha256:' + 'a' * 64,
                             'observed_at': '2026-10-08T08:00:00Z', 'expires_at': '2026-10-08T11:00:00Z'}}]}
        self.target = {k: self.profile[k] for k in ('provider_id', 'engine_instance_id', 'artifact_digest',
                      'configuration_reference', 'security_domain_reference')}

    def validate(self):
        publication.validate(self.contracts, self.profile, self.target, self.now)

    def test_valid_canonical_profile(self):
        self.validate()

    def test_exact_targets(self):
        for key in self.target:
            with self.subTest(key=key):
                target = dict(self.target, **{key: 'substituted'})
                with self.assertRaises(ValueError):
                    publication.validate(self.contracts, self.profile, target, self.now)

    def test_duplicate_facet_even_with_different_status(self):
        self.profile['capability_observations'].append({'capability': 'WORKLOAD_TOKEN_ISSUANCE',
                                                       'verification_status': 'UNSUPPORTED'})
        with self.assertRaises(ValueError):
            self.validate()

    def test_invalid_or_stale_evidence(self):
        for field, value in (('artifact_digest', 'sha256:' + 'b' * 64),
                             ('observed_at', '2026-10-08T09:01:00Z'),
                             ('expires_at', '2026-10-08T10:00:00Z')):
            with self.subTest(field=field):
                changed = copy.deepcopy(self.profile)
                changed['capability_observations'][0]['evidence'][field] = value
                with self.assertRaises(ValueError):
                    publication.validate(self.contracts, changed, self.target, self.now)

    def test_schema_missing_evidence_and_unknown_field(self):
        del self.profile['capability_observations'][0]['evidence']
        with self.assertRaises(ValueError):
            self.validate()
        self.profile['credential'] = 'not-a-profile-field'
        with self.assertRaises(ValueError):
            self.validate()

    def test_duplicate_json_and_oversize_denied(self):
        for raw in (b'{"revision":1,"revision":2}', b' ' * (publication.MAX_BODY + 1)):
            with self.assertRaises(ValueError):
                publication.decode(raw)

    def response(self, status=201, mutate=None):
        receipt = {k: self.profile[k] for k in ('provider_id', 'engine_instance_id', 'revision')}
        receipt['status'] = 'RECORDED' if status == 201 else 'REPLAY'
        if mutate:
            receipt.update(mutate)
        opener = Mock()
        # Mock's special methods are absent; use a real context-manager wrapper.
        class Response:
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def read(self, size):
                return json.dumps(receipt).encode()
        result = Response()
        result.status = status
        opener.open.return_value = result
        return opener

    def test_post_receipt_and_exact_replay(self):
        for status in (201, 200):
            opener = self.response(status)
            receipt, digest = publication.publish('https://cp.example', self.profile, 'fixture-token', opener=opener)
            request = opener.open.call_args.args[0]
            self.assertEqual(request.full_url, 'https://cp.example' + publication.ENDPOINT)
            self.assertEqual(request.method, 'POST')
            self.assertEqual(json.loads(request.data), self.profile)
            self.assertEqual(opener.open.call_args.kwargs['timeout'], 10)
            self.assertEqual(len(digest), 64)
            self.assertEqual(receipt['revision'], 1)

    def test_substituted_or_malformed_receipt_denied(self):
        for change in ({'revision': 2}, {'revision': True}, {'provider_id': 'provider_bbbbbbbb'},
                       {'status': 'ACTIVE'}, {'unexpected': True}):
            with self.assertRaises(ValueError):
                publication.publish('https://cp.example', self.profile, 'fixture-token', opener=self.response(mutate=change))

    def test_outage_no_retry_no_secret_in_error(self):
        opener = Mock()
        opener.open.side_effect = urllib.error.URLError('fixture-token')
        with self.assertRaises(ValueError) as error:
            publication.publish('https://cp.example', self.profile, 'fixture-token', opener=opener)
        self.assertNotIn('fixture-token', str(error.exception))
        opener.open.assert_called_once()

    def test_unsafe_origin_token_timeout_denied_before_send(self):
        for origin, token, timeout in (('http://cp.example', 'token', 10),
                                      ('https://user:secret@cp.example', 'token', 10),
                                      ('https://cp.example/path', 'token', 10),
                                      ('https://cp.example?query', 'token', 10),
                                      ('https://cp.example', 'bad\nheader', 10),
                                      ('https://cp.example', '', 10),
                                      ('https://cp.example', 'token', 31)):
            opener = Mock()
            with self.assertRaises(ValueError):
                publication.publish(origin, self.profile, token, timeout=timeout, opener=opener)
            opener.open.assert_not_called()

    def test_redirect_denied(self):
        with self.assertRaises(ValueError):
            publication.NoRedirect().redirect_request(None, None, 307, '', {}, 'https://other.example')


if __name__ == '__main__':
    unittest.main()
