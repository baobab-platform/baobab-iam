import json
import os
from pathlib import Path
import unittest

from test_canonical_workload_request import load_shared

ROOT = Path(__file__).resolve().parents[2]


class HumanAuthenticationContractTests(unittest.TestCase):
    def test_pinned_shared_human_authentication_corpus(self):
        checkout = Path(os.environ['SHARED_REPO_DIR']).resolve()
        module, _ = load_shared(checkout)
        contracts = module.Contracts(checkout / 'contracts')
        cases = json.loads((ROOT / 'tests/fixtures/canonical-human-authentication.json').read_text())
        for index, case in enumerate(cases):
            with self.subTest(index=index):
                errors = contracts.errors(case['schema'], case['value'])
                self.assertEqual(not errors, case['valid'])
