#!/usr/bin/env python3
"""IAM-N02 actual Chromium consumer probe.

Runs only against an explicitly configured private/disposable browser estate;
never starts a fake issuer, CP service, user or acceptance clock. No screenshots,
video, trace, console dumps, URLs, account identifiers or credentials leave the
process. The companion qualification gate decides what external CP evidence is
needed. An unexecuted or missing case is BLOCKED, never PASS.

Python 3.14 + playwright==1.64.1; independent infrastructure approval is needed
before protected staging. The development path is permitted by ADR-SHARED-043.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
import urllib.parse
from typing import Any

CASES = (
    "N02_BROWSER_ORIGIN_CSRF_DENIAL",
    "N02_REAL_KRATOS_HYDRA_LOGIN",
    "N02_PKCE_STATE_CALLBACK_REPLAY_DENIAL",
    "N02_CP_ACTIVE_PRINCIPAL_SESSION",
    "N02_REAL_AAL2_STEP_UP",
    "N02_REAL_RECOVERY_NO_AUTO_GRANT",
    "N02_ALL_NATIVE_SESSIONS_LOGOUT",
)
STAGE = "PROFILE"


class Denied(Exception):
    pass


def private_file(path: str, limit: int = 32768) -> bytes:
    ref = Path(path)
    if not ref.is_absolute():
        raise Denied("PRIVATE_FILE_PATH")
    fd = os.open(ref, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        with os.fdopen(fd, "rb") as handle:
            info = os.fstat(handle.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_nlink != 1 or info.st_mode & 0o077
                    or info.st_size > limit):
                raise Denied("PRIVATE_FILE_PERMISSIONS")
            return handle.read(limit + 1)
    except Exception:
        raise


def origin(value: Any, environment: str) -> str:
    if not isinstance(value, str):
        raise Denied("ORIGIN_REQUIRED")
    url = urllib.parse.urlsplit(value)
    if (not url.hostname or url.username or url.password or url.query
            or url.fragment or url.path not in ("", "/")):
        raise Denied("INVALID_ORIGIN")
    if url.scheme != "https":
        if not (environment == "development" and url.scheme == "http"
                and url.hostname == "127.0.0.1"):
            raise Denied("VERIFIED_HTTPS_REQUIRED")
    return value.rstrip("/")


def load_profile() -> dict[str, Any]:
    raw = os.environ.get("BAOBAB_N02_PRIVATE_PROFILE", "")
    data = json.loads(private_file(raw))
    if not isinstance(data, dict) or data.get("schema") != "baobab.iam.n02.browser-qualification.v1":
        raise Denied("PROFILE_SCHEMA")
    environment = data.get("environment")
    if environment != "development" or os.environ.get("BAOBAB_ENVIRONMENT") != "development":
        # Protected interactive access is only permitted through Infrastructure
        # #49 supervised approval/custody, not a browser job with a flag.
        raise Denied("PROTECTED_EXECUTION_REQUIRES_SEPARATE_APPROVAL")
    data["bff_origin"] = origin(data.get("bff_origin"), environment)
    data["kratos_origin"] = origin(data.get("kratos_origin"), environment)
    data["hydra_origin"] = origin(data.get("hydra_origin"), environment)
    if len({data["bff_origin"], data["kratos_origin"], data["hydra_origin"]}) != 3:
        raise Denied("AUTHORITY_ORIGIN_COLLISION")
    if not re.fullmatch(r"[0-9a-f]{40}", data.get("iam_source_sha", "")):
        raise Denied("UNPINNED_SOURCE")
    if not re.fullmatch(r"[0-9a-f]{32}", data.get("run_id", "")):
        raise Denied("UNBOUNDED_SYNTHETIC_RUN")
    for key in ("shared_source_sha", "cp_source_sha", "infrastructure_harness_sha"):
        if not isinstance(data.get(key), str) or not re.fullmatch(r"[0-9a-f]{40}", data[key]):
            raise Denied("PEER_SOURCE_PIN_REQUIRED")
    if data.get("require_aal2") is not True:
        raise Denied("AAL2_REQUIRED_FOR_QUALIFICATION")
    # Profile SHA alone is not executable provenance; verify actual clean checkout.
    source = Path(__file__).resolve().parents[2]
    try:
        revision = subprocess.run(["git", "-C", str(source), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True, timeout=10)
        clean = subprocess.run(["git", "-C", str(source), "diff", "--quiet", "HEAD", "--"],
            capture_output=True, check=False, timeout=10)
    except (OSError, subprocess.SubprocessError):
        raise Denied("IMMUTABLE_SOURCE_UNVERIFIED") from None
    if revision.stdout.strip() != data["iam_source_sha"] or clean.returncode != 0:
        raise Denied("IMMUTABLE_SOURCE_MISMATCH")
    if not isinstance(data.get("post_recovery_password_file"), str):
        raise Denied("POST_RECOVERY_CREDENTIAL_REQUIRED")
    if not isinstance(data.get("selectors"), dict):
        raise Denied("REAL_BROWSER_SELECTORS_REQUIRED")
    for name in ("identifier", "password", "submit", "recovery_identifier",
                 "recovery_submit", "recovery_code", "recovery_complete"):
        if not isinstance(data["selectors"].get(name), str) or not data["selectors"][name]:
            raise Denied("REAL_ESTATE_UX_REQUIRED")
    if not isinstance(data.get("synthetic_identifier"), str):
        raise Denied("SYNTHETIC_IDENTITY_REQUIRED")
    return data


def read_secret(profile: dict[str, Any], field: str) -> str:
    return private_file(profile[field], 4096).decode("utf-8").strip()


def run_browser(profile: dict[str, Any]) -> dict[str, str]:
    from playwright.sync_api import sync_playwright
    global STAGE

    results = {name: "BLOCKED" for name in CASES}
    bff = profile["bff_origin"]
    kratos = profile["kratos_origin"]
    selectors = profile["selectors"]
    with sync_playwright() as engine:
        browser = engine.chromium.launch(headless=True)
        try:
            context = browser.new_context(
                ignore_https_errors=False,
                service_workers="block",
                accept_downloads=False,
                permissions=[],
            )
            page = context.new_page()
            page.set_default_timeout(12000)
            # 1) Actual BFF unauthenticated response, original browser origin
            # and cross-site POST denial, never solely an HTTP mock.
            STAGE = "ORIGIN_CSRF"
            response = context.request.get(bff + "/auth/session", max_redirects=0)
            if response.status != 401 or response.headers.get("cache-control") != "no-store":
                raise Denied("UNAUTHENTICATED_SESSION_NOT_REFUSED")
            wrong = context.request.post(
                bff + "/auth/start", headers={"Origin": "https://wrong-estate.invalid"},
                max_redirects=0,
            )
            if wrong.status != 403:
                raise Denied("CROSS_ORIGIN_START_ACCEPTED")
            results[CASES[0]] = "OBSERVED"

            # Use a real browser top-level form POST (not Playwright APIRequest)
            # so the browser emits an Origin and receives genuine host cookies.
            STAGE = "HYDRA_KRATOS_BROWSER"
            page.goto(bff + "/auth/session", wait_until="domcontentloaded")
            seen_callback = []
            def remember_callback(request):
                target = urllib.parse.urlsplit(request.url)
                if (target.scheme + "://" + target.netloc == bff
                        and target.path == "/auth/callback"):
                    seen_callback.append(request.url)  # memory-only, never log
            page.on("request", remember_callback)
            page.evaluate("""() => {
                const form = document.createElement('form');
                form.method='POST';
                form.action='/auth/start';
                document.body.appendChild(form);
                form.submit();
            }""")
            page.locator(selectors["identifier"]).fill(profile["synthetic_identifier"])
            page.locator(selectors["password"]).fill(read_secret(profile, "password_file"))
            page.locator(selectors["submit"]).click()
            if profile.get("require_aal2") is True:
                STAGE = "KRATOS_AAL2"
                for name in ("totp_input", "totp_submit", "totp_seed_file"):
                    if not profile.get(name) and not selectors.get(name):
                        raise Denied("REAL_SECOND_FACTOR_REQUIRED")
                import base64
                import hmac
                import struct
                import hashlib as digests
                seed = read_secret(profile, "totp_seed_file")
                secret = base64.b32decode(seed, casefold=True)
                counter = int(time.time()) // 30
                digest = hmac.new(secret, struct.pack(">Q", counter), digests.sha1).digest()
                offset = digest[-1] & 15
                code = str((int.from_bytes(digest[offset:offset+4], "big") & 0x7fffffff) % 1000000).zfill(6)
                page.locator(selectors["totp_input"]).fill(code)
                page.locator(selectors["totp_submit"]).click()
                # A clicked OTP submit is not proof: observe actual Kratos AAL.
                current = context.request.get(kratos + "/sessions/whoami", max_redirects=0)
                if (current.status != 200 or
                        current.json().get("authenticator_assurance_level") != "aal2"):
                    raise Denied("KRATOS_AAL2_NOT_OBSERVED")
            STAGE = "EXPLICIT_CONSENT"
            page.get_by_role("button", name="Allow").click()
            page.wait_for_url(bff + "/", wait_until="domcontentloaded")
            session = context.request.get(bff + "/auth/session", max_redirects=0)
            if session.status != 200:
                raise Denied("CP_CURRENT_PRINCIPAL_SESSION_REFUSED")
            exposed = session.json()
            if set(exposed) != {"authenticated", "principal_id", "csrf"} or exposed["authenticated"] is not True:
                raise Denied("BROWSER_SESSION_EXPOSED_EXTRA_AUTHORITY")
            if (not isinstance(exposed["principal_id"], str) or
                    not exposed["principal_id"]):
                raise Denied("CP_PRINCIPAL_ID_INVALID")
            principal_id = exposed["principal_id"]
            results[CASES[1]] = "OBSERVED"
            results[CASES[3]] = "OBSERVED"
            results[CASES[4]] = "OBSERVED"

            # A one-time code must remain unusable after the initial callback.
            STAGE = "CALLBACK_REPLAY"
            if len(seen_callback) != 1:
                raise Denied("SINGLE_CALLBACK_NOT_OBSERVED")
            replay = context.request.get(seen_callback[0], max_redirects=0)
            if replay.status in (200, 302, 303):
                raise Denied("REPLAYED_CODE_ACCEPTED")
            results[CASES[2]] = "OBSERVED"

            # Explicit user-wide session revocation, not just dropping a cookie.
            STAGE = "GLOBAL_NATIVE_LOGOUT"
            logout = context.request.post(bff + "/auth/logout-all",
                headers={"Origin": bff, "X-CSRF-Token": exposed["csrf"]},
                max_redirects=0)
            if logout.status != 204:
                raise Denied("GLOBAL_LOGOUT_UNCONFIRMED")
            if context.request.get(bff + "/auth/session", max_redirects=0).status != 401:
                raise Denied("GLOBAL_LOGOUT_SESSION_RESURRECTED")
            whoami = context.request.get(kratos + "/sessions/whoami", max_redirects=0)
            if whoami.status not in (401, 403):
                raise Denied("KRATOS_SESSION_REMAINS_ACTIVE")
            results[CASES[6]] = "OBSERVED"

            # Recovery uses a *different* provider ceremony and cannot grant
            # a new CP Principal automatically. To count as observed, the
            # actual recovery email/code courier and branded estate UI must
            # be connected, and a fresh OAuth login separately verified.
            STAGE = "RECOVERY"
            page.goto(bff + "/auth/recovery", wait_until="domcontentloaded")
            page.locator(selectors["recovery_identifier"]).fill(profile["synthetic_identifier"])
            page.locator(selectors["recovery_submit"]).click()
            code = read_secret(profile, "recovery_code_file")
            page.locator(selectors["recovery_code"]).fill(code)
            page.locator(selectors["recovery_complete"]).click()
            if context.request.get(bff + "/auth/session", max_redirects=0).status != 401:
                raise Denied("RECOVERY_AUTO_GRANTED_CP_SESSION")
            # Recovery alone must not grant anything. Require a new, distinct
            # OAuth authorization-code ceremony and current CP Principal.
            STAGE = "POST_RECOVERY_FRESH_LOGIN"
            page.goto(bff + "/auth/session", wait_until="domcontentloaded")
            page.evaluate("""() => {
                const form = document.createElement('form');
                form.method = 'POST'; form.action = '/auth/start';
                document.body.appendChild(form); form.submit();
            }""")
            page.locator(selectors["identifier"]).fill(profile["synthetic_identifier"])
            page.locator(selectors["password"]).fill(read_secret(profile, "post_recovery_password_file"))
            page.locator(selectors["submit"]).click()
            seed = read_secret(profile, "totp_seed_file")
            import base64
            import hmac
            import struct
            import hashlib as digests
            secret = base64.b32decode(seed, casefold=True)
            digest = hmac.new(secret, struct.pack(">Q", int(time.time()) // 30), digests.sha1).digest()
            offset = digest[-1] & 15
            code = str((int.from_bytes(digest[offset:offset+4], "big") & 0x7fffffff) % 1000000).zfill(6)
            page.locator(selectors["totp_input"]).fill(code)
            page.locator(selectors["totp_submit"]).click()
            current = context.request.get(kratos + "/sessions/whoami", max_redirects=0)
            if (current.status != 200 or
                    current.json().get("authenticator_assurance_level") != "aal2"):
                raise Denied("POST_RECOVERY_AAL2_NOT_OBSERVED")
            page.get_by_role("button", name="Allow").click()
            page.wait_for_url(bff + "/", wait_until="domcontentloaded")
            recovered = context.request.get(bff + "/auth/session", max_redirects=0)
            if recovered.status != 200:
                raise Denied("POST_RECOVERY_FRESH_SESSION_MISSING")
            current = recovered.json()
            if (set(current) != {"authenticated", "principal_id", "csrf"} or
                    current["authenticated"] is not True or
                    current["principal_id"] != principal_id):
                raise Denied("POST_RECOVERY_CP_PRINCIPAL_DRIFT")
            results[CASES[5]] = "OBSERVED"
        finally:
            browser.close()
    return results


def main() -> int:
    global STAGE
    report = {name: "BLOCKED" for name in CASES}
    try:
        profile = load_profile()
        result = run_browser(profile)
        report.update(result)
    except Exception as error:
        reason = error.args[0] if isinstance(error, Denied) else "BROWSER_OR_PROVIDER_UNAVAILABLE"
        if not isinstance(reason,str) or not re.fullmatch(r"[A-Z_]+", reason):
            reason = "BROWSER_OR_PROVIDER_UNAVAILABLE"
        # Only constant identifiers, never passwords, URLs, exception bodies,
        # API request/response payloads or browser traces.
        print("N02_BROWSER_BLOCKED stage=" + STAGE + " reason=" + reason, file=sys.stderr)
        return 1
    if any(value != "OBSERVED" for value in report.values()):
        print("N02_BROWSER_BLOCKED mandatory case not observed", file=sys.stderr)
        return 1
    # This is a *candidate* consumer observation only. CP/issuer independent
    # signed evidence, protected approval and source/trust freshness are checked
    # separately. Emit no browser identifiers or secrets.
    output = {
        "schema": "baobab.iam.n02.browser-observation.v1",
        "classification": "REAL_BROWSER_SYNTHETIC_DATA",
        "source_sha": profile["iam_source_sha"],
        "shared_source_sha": profile["shared_source_sha"],
        "cp_source_sha": profile["cp_source_sha"],
        "infrastructure_harness_sha": profile["infrastructure_harness_sha"],
        "run_id": profile["run_id"],
        "provider_and_cp_independently_attested": False,
        "protected_accepted": False,
        "cases": report,
    }
    destination = Path(os.environ["BAOBAB_N02_EVIDENCE_DIR"])
    if not destination.is_absolute() or not destination.exists():
        raise Denied("EVIDENCE_DIRECTORY_NOT_PRIVATE")
    info = destination.stat()
    if info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise Denied("EVIDENCE_DIRECTORY_NOT_PRIVATE")
    encoded = json.dumps(output, sort_keys=True, separators=(",", ":")).encode()
    temporary = destination / ".browser-observation.tmp"
    with os.fdopen(os.open(temporary, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600), "wb") as f:
        f.write(encoded)
        f.flush()
        os.fsync(f.fileno())
    target = destination / "browser-observation.json"
    if target.exists() or (destination / "browser-observation.sha256").exists():
        raise Denied("ORIGINAL_EVIDENCE_ALREADY_EXISTS")
    os.replace(temporary,target)
    # Gate requires 0600 original sidecars. Path.write_text may create 0644.
    digest_temp = destination / ".browser-observation.sha256.tmp"
    with os.fdopen(os.open(digest_temp, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600), "w") as f:
        f.write(hashlib.sha256(encoded).hexdigest()+"\n")
        f.flush()
        os.fsync(f.fileno())
    os.replace(digest_temp, destination / "browser-observation.sha256")
    folder_fd = os.open(destination, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(folder_fd)
    finally:
        os.close(folder_fd)
    print("N02_BROWSER_OBSERVED_UNATTESTED; no CP/protected certification")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
