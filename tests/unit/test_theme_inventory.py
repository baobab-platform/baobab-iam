"""Regression for missing themes that token-only integration cannot see."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("theme_inventory", ROOT / "scripts/check_theme_inventory.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class ThemeInventoryTest(unittest.TestCase):
    def test_actual_configured_theme_is_packaged(self):
        self.assertTrue(m.check())

    def test_missing_type_and_untrusted_parent_fail_closed(self):
        for parent in (None, "baobab", "https://foreign.invalid", "../../other"):
            with self.subTest(parent=parent), tempfile.TemporaryDirectory() as d:
                root = Path(d)
                (root / "config/realm").mkdir(parents=True)
                (root / "config/realm/baobab-realm.json").write_text(json.dumps({"loginTheme":"baobab"}))
                if parent:
                    target = root / "themes/baobab/login"
                    target.mkdir(parents=True)
                    (target / "theme.properties").write_text("parent=" + parent)
                with self.assertRaises(ValueError):
                    m.check(root)
