"""Definitions must never accidentally activate human/workload admission."""
import json
from pathlib import Path
import unittest
ROOT = Path(__file__).resolve().parents[2]
class TradeBindingScopes(unittest.TestCase):
    def test_human_cp_vocabulary_without_assignments(self):
        clients = '\n'.join(p.read_text() for p in (ROOT/'config/clients').glob('*.json'))
        for op in ('propose','approve','activate','revoke'):
            name = 'trade-binding:'+op
            value = json.loads((ROOT/f'config/scopes/trade-binding-{op}.json').read_text())
            self.assertEqual(name,value['name'])
            mapper = value['protocolMappers'][0]
            self.assertEqual('baobab-control-plane',mapper['config']['included.custom.audience'])
            self.assertEqual('false',mapper['config']['id.token.claim'])
            self.assertNotIn(name,clients)
