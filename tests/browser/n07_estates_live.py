#!/usr/bin/env python3
"""IAM-N07 real Chromium estate journey (NEVER acceptance by itself).

Owner-operated on a disposable development topology. No fake issuer, mock CP,
session injection, saved browser storage state, screenshots, videos or traces.
Browser login and local logout are not issuer-wide revocation or CP business
authorization. The protected evidence gate is deliberately external.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import time
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "n07_consumers", ROOT / "scripts" / "n07_connected_consumers.py")
n07 = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = n07
SPEC.loader.exec_module(n07)

SCHEMA = "baobab.iam.n07.estates-browser.v1"
ESTATES = {
    "nabhold": ("/api/auth/session", "/api/auth/context"),
    "zuribeans": ("/api/iam/session", None),
    "thamani": ("/api/auth/session", None),
}


def validate_browser_profile(p: dict[str, Any]) -> None:
    if (p.get("schema") != SCHEMA or p.get("environment") != "development"
            or not isinstance(p.get("run_id"), str)
            or not n07.RUN.fullmatch(p["run_id"])):
        raise n07.Blocked("PRIVATE_BROWSER_PROFILE_REQUIRED")
    pins = p.get("source_pins")
    if (not isinstance(pins, dict) or
            not {"baobab-iam", "baobab-cp", "shared", *ESTATES}.issubset(pins) or
            any(not isinstance(v, str) or not n07.SHA.fullmatch(v) for v in pins.values())):
        raise n07.Blocked("BROWSER_PEER_PINS_REQUIRED")
    estates = p.get("estates")
    if not isinstance(estates, dict) or set(estates) != set(ESTATES):
        raise n07.Blocked("THREE_INDEPENDENT_FIRST_PARTY_ESTATES_REQUIRED")
    for name, details in estates.items():
        if not isinstance(details, dict):
            raise n07.Blocked("ESTATE_CONFIGURATION_REQUIRED")
        n07.trusted_origin(details.get("origin"))
        if details.get("session_path") != ESTATES[name][0]:
            raise n07.Blocked("UNREVIEWED_FIRST_PARTY_SESSION")
        if name == "nabhold" and details.get("context_path") != ESTATES[name][1]:
            raise n07.Blocked("NABHOLD_CP_NAVIGATION_REQUIRED")
        n07.resource_path(details.get("entry_path"))
        for key in ("identifier_selector", "password_selector", "submit_selector",
                    "login_button_selector", "logout_button_selector"):
            if not isinstance(details.get(key), str) or not details[key] or len(details[key]) > 180:
                raise n07.Blocked("REAL_OWNER_UI_SELECTORS_REQUIRED")
        for key in ("identifier_file", "password_file"):
            if not isinstance(details.get(key), str) or not Path(details[key]).is_absolute():
                raise n07.Blocked("PRIVATE_SYNTHETIC_IDENTITY_REQUIRED")
        if name == "nabhold":
            expected = details.get("executive_navigation")
            if (not isinstance(expected, dict) or not isinstance(expected.get("tenant_id"), str)
                    or not isinstance(expected.get("market"), str) or
                    not re.fullmatch(r"tn_[a-z0-9]{3,60}", expected["tenant_id"]) or
                    not re.fullmatch(r"[A-Z]{2}", expected["market"])):
                raise n07.Blocked("CURRENT_CP_CONTEXT_EXPECTED")


def cookie_free_json(response) -> dict[str, Any]:
    if (response.status != 200 or
            "application/json" not in response.headers.get("content-type", "").lower() or
            "no-store" not in response.headers.get("cache-control", "").lower()):
        raise n07.Blocked("CURRENT_SESSION_UNAVAILABLE")
    raw = response.body()
    if len(raw) > 8192:
        raise n07.Blocked("OVERSIZED_SESSION_REPLY")
    try:
        obj = json.loads(raw, object_pairs_hook=n07.pairs_unique)
    except (ValueError, TypeError):
        raise n07.Blocked("SESSION_REPLY_INVALID") from None
    if not isinstance(obj, dict):
        raise n07.Blocked("SESSION_REPLY_INVALID")
    return obj


def current_session(name: str, reply: dict[str, Any]) -> None:
    expire = reply.get("expiresAt")
    if (isinstance(expire, bool) or not isinstance(expire, (int, float)) or
            expire < time.time() * 1000 + 10_000):
        raise n07.Blocked("CURRENT_SESSION_EXPIRED")
    if name == "nabhold":
        try:
            if not isinstance(reply.get("principalId"), str):
                raise ValueError()
            UUID(reply["principalId"])
        except ValueError:
            raise n07.Blocked("CP_PRINCIPAL_NOT_OBSERVED") from None
    elif reply.get("authenticated") is not True:
        raise n07.Blocked("CURRENT_NATIVE_SESSION_NOT_OBSERVED")


def current_executive_context(reply: dict[str, Any], expect: dict[str, str]) -> None:
    market = reply.get("market")
    if (reply.get("kind") != "EXECUTIVE_NAVIGATION" or
            reply.get("executionAuthority") is not False or
            reply.get("tenantId") != expect["tenant_id"] or
            not isinstance(market, dict) or
            market.get("countryCode") != expect["market"]):
        raise n07.Blocked("CURRENT_CP_EXECUTIVE_NAVIGATION_NOT_OBSERVED")
    expiry = reply.get("expiresAt")
    if (isinstance(expiry, bool) or not isinstance(expiry, (int, float)) or
            expiry < time.time() * 1000 + 5_000):
        raise n07.Blocked("STALE_CP_NAVIGATION")


def actual_estates(profile: dict[str, Any]) -> dict[str, str]:
    from playwright.sync_api import Error as PlaywrightError, sync_playwright

    results: dict[str, str] = {}
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            for name, cfg in profile["estates"].items():
                prefix = "N07_" + name.upper()
                for suffix in ("FIRST_PARTY", "ANONYMOUS_DENIAL", "LOGIN_SESSION",
                               "CP_READ_ONLY", "LOCAL_LOGOUT"):
                    results[prefix + "_" + suffix] = "BLOCKED"
                context = browser.new_context(
                    ignore_https_errors=False,
                    service_workers="block",
                    accept_downloads=False,
                    permissions=[],
                )
                try:
                    base = n07.trusted_origin(cfg["origin"])
                    page = context.new_page()
                    page.set_default_timeout(12000)
                    start = page.goto(base + cfg["entry_path"], wait_until="domcontentloaded", timeout=15000)
                    landed = urlsplit(page.url)
                    if (start is None or start.status != 200 or
                            landed.scheme + "://" + landed.netloc != base or
                            "text/html" not in start.headers.get("content-type", "").lower()):
                        continue
                    results[prefix + "_FIRST_PARTY"] = "OBSERVED"
                    denied = context.request.get(base + cfg["session_path"],
                                                 max_redirects=0, timeout=5000)
                    if denied.status not in (401, 403):
                        continue
                    results[prefix + "_ANONYMOUS_DENIAL"] = "OBSERVED"

                    # Start only through a real first-party owner UI. No injected
                    # form, bearer, localStorage or programmatically forged OAuth.
                    page.locator(cfg["login_button_selector"]).click()
                    identifier = n07.private_read(cfg["identifier_file"], 4096).decode("utf-8").strip()
                    password = n07.private_read(cfg["password_file"], 4096).decode("utf-8").strip()
                    page.locator(cfg["identifier_selector"]).fill(identifier)
                    page.locator(cfg["password_selector"]).fill(password)
                    page.locator(cfg["submit_selector"]).click()
                    # Poll the *actual* same-origin issuer-backed session. Do not
                    # log URLs, credentials, response text or browser state.
                    confirmed: dict[str, Any] | None = None
                    for _ in range(20):
                        page.wait_for_timeout(500)
                        response = context.request.get(base + cfg["session_path"],
                                                       max_redirects=0, timeout=5000)
                        if response.status == 200:
                            confirmed = cookie_free_json(response)
                            current_session(name, confirmed)
                            break
                    if confirmed is None:
                        continue
                    results[prefix + "_LOGIN_SESSION"] = "OBSERVED"

                    if name == "nabhold":
                        navigation = context.request.get(base + cfg["context_path"],
                                                         max_redirects=0, timeout=5000)
                        nav = cookie_free_json(navigation)
                        current_executive_context(nav, cfg["executive_navigation"])
                        results[prefix + "_CP_READ_ONLY"] = "OBSERVED"
                    # Other estate CP buyer/legal-actor authority requires
                    # separate owner-native and N02/N03 current-CP receipts.
                    page.goto(base + cfg["entry_path"], wait_until="domcontentloaded")
                    page.locator(cfg["logout_button_selector"]).click()
                    after = context.request.get(base + cfg["session_path"],
                                                max_redirects=0, timeout=5000)
                    if after.status in (401, 403):
                        results[prefix + "_LOCAL_LOGOUT"] = "OBSERVED"
                except (n07.Blocked, OSError, UnicodeError, ValueError, PlaywrightError):
                    pass
                finally:
                    context.close()
        finally:
            browser.close()
    return results


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description="N07 real Chromium; evidence never accepts itself")
    parser.add_argument("--profile", required=True)
    parser.add_argument("--output-dir", required=True)
    opts = parser.parse_args()
    try:
        if os.environ.get("BAOBAB_ENVIRONMENT") != "development":
            raise n07.Blocked("PROTECTED_BROWSER_NOT_AUTHORIZED")
        profile = n07.private_json(opts.profile)
        validate_browser_profile(profile)
        n07.exact_source(profile)
        observed = actual_estates(profile)
        receipt = {
            "schema": "baobab.iam.n07.estates-observation.v1",
            "classification": "REAL_CHROMIUM_UNATTESTED",
            "run_id": profile["run_id"], "source_pins": profile["source_pins"],
            "cases": observed, "development_only": True, "protected_accepted": False,
            "cp_privilege_certified": False, "issuer_revocation_certified": False,
            "fully_qualified": False,
        }
        n07.original_write(opts.output_dir, "estates", receipt)
        print(json.dumps({"classification": "N07_REAL_BROWSER_UNATTESTED"
                          if all(v == "OBSERVED" for v in observed.values())
                          else "N07_BROWSER_BLOCKED", "accepted": False,
                          "observed": sum(v == "OBSERVED" for v in observed.values()),
                          "required": len(observed)}, sort_keys=True))
        return 3 if all(v == "OBSERVED" for v in observed.values()) else 2
    except (n07.Blocked, OSError, ValueError, TypeError, KeyError):
        print('{"classification":"N07_BROWSER_BLOCKED","accepted":false}', file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
