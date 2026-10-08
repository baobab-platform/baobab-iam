"""Shared independently validates the same request corpus consumed by Go."""
import json
import os
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from provider_publication import load_shared


class WorkloadRequestContractTests(unittest.TestCase):
    def test_pinned_shared_corpus(self):
        checkout = Path(os.environ['SHARED_REPO_DIR']).resolve()
        module, _ = load_shared(checkout)
        contracts = module.Contracts(checkout / 'contracts')
        cases = json.loads((ROOT / 'tests/fixtures/canonical-workload-request.json').read_text())
        self.assertTrue(cases)
        for index, case in enumerate(cases):
            with self.subTest(index=index):
                errors = contracts.errors('identity/v1/workload-token-request.schema.json', case['request'])
                self.assertEqual(not errors, case['valid'])
