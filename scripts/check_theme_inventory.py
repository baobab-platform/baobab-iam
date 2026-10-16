#!/usr/bin/env python3
"""Fail when a configured custom browser theme is absent from the image.

Docker copies themes/ verbatim. JSON/token endpoint tests cannot detect a
missing login template, so check each selected custom type at source time.
The only accepted built-in parents here are the ones bundled by the exact
upstream Keycloak version; this is not an arbitrary filesystem/URL resolver.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# Type-specific, deliberately narrow inventory for the pinned release. An
# account application is not a login-template parent. Extend only after
# checking that upstream actually packages that name for the selected type.
BUILT_INS = {
    "login": {"keycloak", "keycloak.v2", "base"},
    "account": {"keycloak.v3", "base"},
    "admin": {"keycloak", "keycloak.v2", "base"},
    "email": {"keycloak", "base"},
}


def check(root=ROOT):
    realm = json.loads((root / "config/realm/baobab-realm.json").read_text())
    for kind in ("login", "account", "admin", "email"):
        name = realm.get(kind + "Theme")
        if not name or name in BUILT_INS[kind]:
            continue
        if not isinstance(name, str) or not name.replace("-", "").isalnum():
            raise ValueError("invalid theme name")
        properties = root / "themes" / name / kind / "theme.properties"
        if not properties.is_file():
            raise ValueError("configured browser theme type is missing")
        fields = dict(line.split("=", 1) for line in properties.read_text().splitlines()
                      if line.strip() and not line.lstrip().startswith("#"))
        if fields.get("parent") not in BUILT_INS[kind]:
            raise ValueError("browser theme must inherit a bundled parent")
    return True


if __name__ == "__main__":
    check()
    print("Configured browser themes have packaged, maintained parents")
