#!/usr/bin/env python3
"""Offline ADR-IAM-0028 JWKS rollover preflight; never accepts private JWK material."""
import argparse
import base64
import binascii
import json
import re
import sys

PRIVATE = {"d", "p", "q", "dp", "dq", "qi", "oth", "k"}
ASYMMETRIC = {"RSA": {"RS256", "PS256"}, "EC": {"ES256", "ES384", "ES512"},
              "OKP": {"EdDSA"}}
MATERIAL = {"RSA": ("n", "e"), "EC": ("crv", "x", "y"), "OKP": ("crv", "x")}


def material(key):
    return key["kty"], *(key[name] for name in MATERIAL[key["kty"]])


def valid_component(value):
    if not isinstance(value, str) or re.fullmatch(r"[A-Za-z0-9_-]+", value) is None:
        return False
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (binascii.Error, ValueError):
        return False
    return bool(decoded) and base64.urlsafe_b64encode(decoded).decode().rstrip("=") == value


def public_keys(document):
    if not isinstance(document, dict) or not isinstance(document.get("keys"), list):
        raise ValueError("invalid JWKS")
    found = {}
    for key in document["keys"]:
        if not isinstance(key, dict):
            raise ValueError("invalid key entry")
        if PRIVATE.intersection(key):
            raise ValueError("private or symmetric key material in public JWKS")
        kid = key.get("kid")
        kty = key.get("kty")
        alg = key.get("alg")
        if not isinstance(kid, str) or not kid.strip() or kid in found:
            raise ValueError("missing or duplicate kid")
        if not isinstance(kty, str) or not isinstance(alg, str) or kty not in ASYMMETRIC or alg not in ASYMMETRIC[kty]:
            raise ValueError("unapproved key type or algorithm")
        if key.get("use", "sig") != "sig":
            raise ValueError("key not restricted to signing verification")
        if kty == "RSA" and not all(isinstance(key.get(x), str) and key[x] for x in ("n", "e")):
            raise ValueError("incomplete RSA public key")
        if kty == "EC" and not all(isinstance(key.get(x), str) and key[x] for x in ("crv", "x", "y")):
            raise ValueError("incomplete EC public key")
        if kty == "OKP" and not all(isinstance(key.get(x), str) and key[x] for x in ("crv", "x")):
            raise ValueError("incomplete OKP public key")
        if not all(valid_component(key[name]) for name in MATERIAL[kty] if name != "crv"):
            raise ValueError("invalid JWK public material encoding")
        if kty == "RSA" and any(base64.urlsafe_b64decode(key[name] + "=" * (-len(key[name]) % 4))[0] == 0 for name in MATERIAL[kty]):
            raise ValueError("non-canonical RSA public integer")
        found[kid] = key
    return found


def verify(before, after, plan):
    old, new = public_keys(before), public_keys(after)
    if not old or not new:
        raise ValueError("empty signing JWKS")
    if not isinstance(plan, dict) or plan.get("mode") not in {"routine", "compromise"}:
        raise ValueError("explicit rotation mode required")
    previous = plan.get("old_kid")
    replacement = plan.get("new_kid")
    if not isinstance(previous, str) or not isinstance(replacement, str) or previous not in old or replacement not in new or previous == replacement:
        raise ValueError("old/new kid missing or identical")
    if replacement in old:
        raise ValueError("new signing key was not introduced")
    if material(new[replacement]) in {material(key) for key in old.values()}:
        raise ValueError("replacement reuses previously trusted key material")
    if plan["mode"] == "routine":
        if previous not in new or new[previous] != old[previous]:
            raise ValueError("old verification key must remain unchanged through overlap")
        if plan.get("verification_distributed") is not True:
            raise ValueError("new verification trust not independently distributed")
        for field in ("max_token_lifetime_seconds", "jwks_cache_seconds",
                      "clock_skew_seconds", "overlap_seconds"):
            if type(plan.get(field)) is not int or plan[field] < 0:
                raise ValueError(f"invalid {field}")
        required = sum(plan[k] for k in ("max_token_lifetime_seconds",
                                          "jwks_cache_seconds", "clock_skew_seconds"))
        if plan["overlap_seconds"] < required:
            raise ValueError("verification overlap too short")
    else:
        if plan.get("incident_approved") is not True:
            raise ValueError("compromise rotation requires incident approval")
        if previous in new or material(old[previous]) in {material(key) for key in new.values()}:
            raise ValueError("compromised key remains trusted")
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("before")
    parser.add_argument("after")
    parser.add_argument("plan")
    args = parser.parse_args()
    try:
        with open(args.before, encoding="utf-8") as f:
            before = json.load(f)
        with open(args.after, encoding="utf-8") as f:
            after = json.load(f)
        with open(args.plan, encoding="utf-8") as f:
            plan = json.load(f)
        verify(before, after, plan)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"JWKS ROTATION HELD: {exc}", file=sys.stderr)
        return 1
    print("JWKS ROTATION PREFLIGHT PASS (NOT LIVE CRYPTOGRAPHIC QUALIFICATION)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
