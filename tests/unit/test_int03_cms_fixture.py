"""Preparation is least-privilege and cannot stand in for registry activation."""
import copy
from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
spec = importlib.util.spec_from_file_location('int03_fixture', ROOT / 'scripts/int03_cms_fixture.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class FixtureTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime.now(timezone.utc)
        self.deadline = self.now + timedelta(minutes=30)
        self.registry = {'workloads': copy.deepcopy(m.EXPECTED)}

    def clients(self):
        return m.build_clients(self.registry, self.deadline, self.now)

    def test_all_row_fields_and_extra_authority_are_closed(self):
        for name, row in m.EXPECTED.items():
            self.assertTrue(m.fixture_only(name, row))
            for key in row:
                changed = copy.deepcopy(row)
                changed[key] = ['unexpected'] if isinstance(changed[key], list) else 'unexpected'
                self.assertFalse(m.fixture_only(name, changed))
                del changed[key]
                self.assertFalse(m.fixture_only(name, changed))
            self.assertFalse(m.fixture_only(name, dict(row, extra_authority=True)))
        self.assertFalse(m.fixture_only('nabhold-backend', m.EXPECTED[m.CALLER]))
        for name in m.EXPECTED:
            for file in (ROOT / 'config/clients').glob('*.json'):
                self.assertNotEqual(json.loads(file.read_text()).get('clientId'), name)

    def test_absent_or_half_pair_cannot_prepare(self):
        for registry in ({}, None, {'workloads': None}, {'workloads': {m.CALLER: m.EXPECTED[m.CALLER]}}):
            with self.assertRaises(ValueError):
                m.build_clients(registry, self.deadline, self.now)

    def test_deadline_is_bounded_and_timezone_aware(self):
        for deadline in (None, self.now, self.now + timedelta(seconds=60), self.now + timedelta(seconds=5401), self.now.replace(tzinfo=None)):
            with self.subTest(deadline=deadline), self.assertRaises(ValueError):
                m.build_clients(self.registry, deadline, self.now)
        self.assertEqual(len(m.build_clients(self.registry, self.now + timedelta(seconds=5400), self.now)), 2)

    def test_independent_secrets_and_separate_optional_scopes(self):
        clients = self.clients()
        next_clients = self.clients()
        self.assertNotEqual(clients[m.CALLER]['secret'], clients[m.VALIDATOR]['secret'])
        self.assertNotEqual(clients[m.CALLER]['secret'], next_clients[m.CALLER]['secret'])
        self.assertEqual(clients[m.CALLER]['optionalClientScopes'], ['context:resolve', 'content:entry:resolve'])
        self.assertEqual(clients[m.VALIDATOR]['optionalClientScopes'], ['context:validate'])
        for client in clients.values():
            self.assertFalse(client['fullScopeAllowed'])
            self.assertEqual(client['attributes']['access.token.lifespan'], '60')
            self.assertEqual(client['defaultClientScopes'], ['basic', 'actor-type-workload'])
        with patch.object(m.secrets, 'token_urlsafe', return_value='s' * 64), self.assertRaises(ValueError):
            self.clients()

    def test_readback_security_fields_and_secret_are_independent(self):
        for expected in self.clients().values():
            observed = copy.deepcopy(expected)
            observed['id'] = 'issuer-managed-id'
            observed['secret'] = '**********'
            secret = {'type': 'secret', 'value': expected['secret']}
            self.assertTrue(m.verify_readback(expected, observed, secret))
            for key in expected:
                if key == 'secret':
                    continue
                changed = copy.deepcopy(observed)
                changed[key] = ['unapproved'] if isinstance(expected[key], list) else None
                self.assertFalse(m.verify_readback(expected, changed, secret), key)
            for changed in (dict(observed, protocolMappers=[{'name': 'extra'}]), dict(observed, attributes=dict(observed['attributes'], extra='true')), dict(observed, enabled=1)):
                self.assertFalse(m.verify_readback(expected, changed, secret))
            for value in ('wrong', None, [], 'nonascii\N{SNOWMAN}'):
                self.assertFalse(m.verify_readback(expected, observed, {'type': 'secret', 'value': value}))
            tampered = dict(expected, fullScopeAllowed=True)
            self.assertFalse(m.verify_readback(tampered, tampered, secret))
        self.assertFalse(m.verify_readback(None, {}, {}))

    def test_duplicate_json_fields_refused(self):
        with self.assertRaises(ValueError):
            json.loads('{"status":"ACTIVE","status":"REVOKED"}', object_pairs_hook=m.unique)

    def test_private_exclusive_files_and_no_write_on_pin_refusal(self):
        import yaml
        with tempfile.TemporaryDirectory() as temp:
            checkout = Path(temp) / 'shared'
            registry = checkout / 'contracts/identity/v1/workload-registry.yaml'
            registry.parent.mkdir(parents=True)
            registry.write_text(yaml.safe_dump(self.registry))
            output = Path(temp) / 'private'
            with patch('provider_publication.load_shared', side_effect=ValueError('pin refusal')):
                with self.assertRaises(ValueError):
                    m.prepare(checkout, output, self.deadline)
            self.assertFalse(output.exists())
            with patch('provider_publication.load_shared') as authority:
                documents = m.prepare(checkout, output, self.deadline)
                authority.assert_called_once_with(checkout)
                self.assertEqual(output.stat().st_mode & 0o777, 0o700)
                for name, document in documents.items():
                    file = output / (name + '.json')
                    self.assertEqual(file.stat().st_mode & 0o777, 0o600)
                    self.assertEqual(json.loads(file.read_text()), document)
                with self.assertRaises(FileExistsError):
                    m.prepare(checkout, output, self.deadline)

    def test_partial_write_is_cleaned(self):
        import yaml
        with tempfile.TemporaryDirectory() as temp:
            checkout = Path(temp) / 'shared'
            registry = checkout / 'contracts/identity/v1/workload-registry.yaml'
            registry.parent.mkdir(parents=True)
            registry.write_text(yaml.safe_dump(self.registry))
            output = Path(temp) / 'private'
            original = m.os.open
            count = 0
            def fail_second(*args):
                nonlocal count
                count += 1
                if count == 2:
                    raise OSError('simulated disk failure')
                return original(*args)
            with patch('provider_publication.load_shared'), patch.object(m.os, 'open', side_effect=fail_second):
                with self.assertRaises(OSError):
                    m.prepare(checkout, output, self.deadline)
            self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
