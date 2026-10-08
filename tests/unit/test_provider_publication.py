"""Contract-bound construction tests; synthetic IMPLEMENTED is never published."""
import copy
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('publication', ROOT / 'scripts/provider_publication.py')
publication = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publication)


class PublicationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.checkout = Path(os.environ['SHARED_REPO_DIR']).resolve()
        cls.module, cls.commit = publication.load_shared(cls.checkout)
        cls.declaration = yaml.safe_load((ROOT / '.baobab/capability-provider.yaml').read_text())

    def generated_fixture(self):
        declaration = copy.deepcopy(self.declaration)
        declaration['providers'][0]['support'][0]['implementation_status'] = 'IMPLEMENTED'
        return publication.prepare(self.module, self.checkout, declaration)

    def test_partial_and_planned_never_generate_support(self):
        _, registrations, excluded = publication.prepare(self.module, self.checkout, self.declaration)
        self.assertEqual(registrations, [])
        self.assertEqual(len(excluded), 3)
        self.assertTrue(all(s['implementation_status'] == 'PARTIAL' for s in excluded))

    def test_canonical_generation_draft_only(self):
        _, registrations, excluded = self.generated_fixture()
        self.assertEqual(len(registrations), 1)
        self.assertEqual(len(excluded), 2)
        self.assertEqual(registrations[0]['provider']['lifecycle'], 'DRAFT')
        self.assertEqual(registrations[0]['support'], [{
            'capability_key': 'identity.authentication.perform', 'contract_versions': [1]}])

    def test_missing_and_unsupported_registration(self):
        contracts, registrations, _ = self.generated_fixture()
        self.assertEqual(publication.compare_exports(self.module, contracts, registrations, [])[0]['reason'],
                         'MISSING_REGISTRATION')
        self.assertEqual(publication.compare_exports(self.module, contracts, [], registrations)[0]['reason'],
                         'UNDECLARED_SUPPORT')

    def test_runtime_lifecycle_is_not_a_registration_document(self):
        contracts, registrations, _ = self.generated_fixture()
        exported = copy.deepcopy(registrations)
        exported[0]['provider']['lifecycle'] = 'ACTIVE'
        with self.assertRaises(ValueError):
            publication.compare_exports(self.module, contracts, registrations, exported)
        self.assertEqual(registrations[0]['provider']['lifecycle'], 'DRAFT')

    def test_substitution_and_metadata_drift(self):
        contracts, registrations, _ = self.generated_fixture()
        for mutate in (lambda e: e['provider'].update(engine_key='keycloak'),
                       lambda e: e['provider'].update(production_permitted=False)):
            exported = copy.deepcopy(registrations)
            mutate(exported[0])
            self.assertEqual(publication.compare_exports(self.module, contracts, registrations, exported)[0]['reason'],
                             'DECLARATION_MISMATCH')

    def test_duplicate_and_malformed_export_denied(self):
        contracts, registrations, _ = self.generated_fixture()
        for exported in (registrations * 2, {}, [{}]):
            with self.assertRaises(ValueError):
                publication.compare_exports(self.module, contracts, registrations, exported)

    def test_invalid_contract_and_evidence_denied(self):
        for field, value in (('contract_versions', [999]), ('implementation_evidence', [
                {'type': 'source', 'path': 'does-not-exist.go'}])):
            declaration = copy.deepcopy(self.declaration)
            declaration['providers'][0]['support'][0][field] = value
            with self.assertRaises(ValueError):
                publication.prepare(self.module, self.checkout, declaration)

    def census(self):
        return {'classification': 'EXECUTABLE_CONSTRUCTION_CENSUS', 'providers': [
            {'provider_key': p['provider_key'], 'implementation_key': p['implementation_key'],
             'support': [{k: entry[k] for k in ('capability_key', 'contract_versions', 'implementation_status')}
                         for entry in p['support']]}
            for p in self.declaration['providers']]}

    def test_ambiguous_wire_evidence_denied(self):
        for raw in ('{"providers":[],"providers":[]}',
                    '[{"provider":{"lifecycle":"ACTIVE","lifecycle":"DRAFT"}}]',
                    '{"providers":[{"support":[{"implementation_status":"IMPLEMENTED",'
                    '"implementation_status":"PARTIAL"}]}]}',
                    '{"revision":NaN}', '{"revision":Infinity}', '{} {}'):
            with self.subTest(raw=raw), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'export.json'
                path.write_text(raw)
                with self.assertRaises(ValueError):
                    publication.read_evidence_export(path)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'export.json'
            path.write_text('{"providers":[]}')
            self.assertEqual(publication.read_evidence_export(path), {'providers': []})

    def test_executable_contract_version_types_denied(self):
        for versions in ([True], [1.0], ["1"], [0], [-1], [], [1, 1], None):
            with self.subTest(versions=versions):
                census = self.census()
                census['providers'][0]['support'][0]['contract_versions'] = versions
                with self.assertRaises(ValueError):
                    publication.compare_executable_support(self.declaration, census)

    def test_executable_convergence(self):
        publication.compare_executable_support(self.declaration, self.census())

    def test_executable_drift_and_premature_promotion_denied(self):
        for field, value in (('implementation_status', 'IMPLEMENTED'),
                             ('contract_versions', [2]), ('capability_key', 'identity.human.provision')):
            census = self.census()
            census['providers'][0]['support'][0][field] = value
            with self.assertRaises(ValueError):
                publication.compare_executable_support(self.declaration, census)

    def test_provider_substitution_missing_duplicate_and_extra_denied(self):
        for mutate in (lambda c: c['providers'].pop(),
                       lambda c: c['providers'].append(copy.deepcopy(c['providers'][0])),
                       lambda c: c['providers'][0].update(implementation_key='hydra'),
                       lambda c: c['providers'][0].update(provider_key='unregistered'),
                       lambda c: c.update(classification='CP_AUTHORITY')):
            census = self.census()
            mutate(census)
            with self.assertRaises(ValueError):
                publication.compare_executable_support(self.declaration, census)

    def test_wrong_pin_denied_before_loading_shared_code(self):
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            (repository / 'contracts.lock.yaml').write_text(yaml.safe_dump({
                'source': {'repository': 'baobab-platform/shared', 'commit': '0' * 40}}))
            with self.assertRaisesRegex(ValueError, 'immutable IAM pin'):
                publication.load_shared(self.checkout, repository)


if __name__ == '__main__':
    unittest.main()
