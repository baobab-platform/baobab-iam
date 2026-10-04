import copy
import importlib.util
from pathlib import Path
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('matrix', ROOT / 'scripts/iam_capability_matrix.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class MatrixTests(unittest.TestCase):
    def setUp(self):
        self.matrix = yaml.safe_load((ROOT / '.baobab/iam-capability-matrix.yaml').read_text())
        self.entries = {'capabilities': [{'capability_key': key, 'owner': 'baobab-iam'} for key in
                        ('identity.authentication.perform', 'identity.workload-token.issue')]}

    def test_valid_and_generated(self):
        module.validate(self.matrix, self.entries, self.entries)
        self.assertEqual(module.render(self.matrix), (ROOT / 'docs/governance/iam-capability-matrix.md').read_text())

    def test_management_operation_cannot_be_promoted(self):
        row = next(row for row in self.matrix['capabilities'] if row['capability_operation'] == 'identity.human.provision')
        row['classification'] = 'PLATFORM_RESOLVABLE_CAPABILITY'
        with self.assertRaises(ValueError):
            module.validate(self.matrix, self.entries, self.entries)

    def test_definition_without_catalogue_is_not_canonical(self):
        row = self.matrix['capabilities'][0]
        definitions = copy.deepcopy(self.entries)
        catalogue = {'capabilities': [self.entries['capabilities'][1]]}
        with self.assertRaises(ValueError):
            module.validate(self.matrix, catalogue, definitions)

    def test_missing_field_and_family(self):
        del self.matrix['capabilities'][0]['observability']
        with self.assertRaises(ValueError):
            module.validate(self.matrix, self.entries, self.entries)


    def test_workloads_cannot_return_to_keycloak(self):
        row = next(r for r in self.matrix['capabilities'] if r['capability_operation'] == 'identity.workload-token.issue')
        row['primary_provider'] = 'Keycloak'
        with self.assertRaises(ValueError):
            module.validate(self.matrix, self.entries, self.entries)

    def test_enterprise_federation_cannot_move_to_ory_by_assumption(self):
        row = next(r for r in self.matrix['capabilities'] if r['capability_operation'] == 'identity.federation.enterprise')
        row['primary_provider'] = 'Ory Hydra'
        with self.assertRaises(ValueError):
            module.validate(self.matrix, self.entries, self.entries)

    def test_retained_capability_and_adapter_cannot_require_retirement(self):
        for key in ('identity.federation.enterprise', 'provider.adapter.normalize'):
            with self.subTest(key=key):
                matrix = copy.deepcopy(self.matrix)
                row = next(r for r in matrix['capabilities'] if r['capability_operation'] == key)
                row['retirement_dependency'] = 'Keycloak deleted after cutover'
                with self.assertRaises(ValueError):
                    module.validate(matrix, self.entries, self.entries)
