#!/usr/bin/env python3
"""G04B-04: guarded, non-authorising Nabhold human-to-CP acceptance checks.

The immutable source template is DISABLED. This program neither creates an
identity, approves a Keycloak client, enables a grant, nor signs a staging GO.
In --protected mode it consumes operator-supplied REAL staging observations.
All secrets and tokens must arrive through private environment variables.
Outputs contain boolean checks only, never bearer material or identifiers.
"""
import argparse
import base64
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "config/clients/nabhold-executive.json"
CLIENT = "nabhold-executive"
AUDIENCE = "baobab-control-plane"
SCOPE = "authority:self"
MAX_BYTES = 65536
class Denied(Exception):
    """Safe error without provider bodies or credential-bearing URLs."""

def require(condition):
    if not condition:
        raise Denied("governed acceptance condition not met")

def https_origin(value):
    u = urllib.parse.urlsplit(value)
    require(u.scheme == "https" and u.hostname and not u.username and not u.password
            and not u.query and not u.fragment and (u.path in ("", "/")))
    require(u.netloc == u.hostname or (u.port is not None and u.netloc == f"{u.hostname}:{u.port}"))
    return f"https://{u.netloc}"

def check_template(value):
    """A source document MUST NOT accidentally enable a privileged client."""
    require(value.get("clientId") == CLIENT and value.get("enabled") is False)
    require(value.get("publicClient") is False and value.get("bearerOnly") is False)
    require(value.get("standardFlowEnabled") is True)
    require(all(value.get(k) is False for k in ("directAccessGrantsEnabled", "implicitFlowEnabled", "serviceAccountsEnabled")))
    require(value.get("protocol") == "openid-connect" and value.get("redirectUris") == []
            and value.get("webOrigins") == [] and value.get("optionalClientScopes") == [])
    require(value.get("defaultClientScopes") == ["openid", "actor-type-human", SCOPE])
    require(value.get("attributes", {}).get("pkce.code.challenge.method") == "S256")
    require("secret" not in value and "authorizationServicesEnabled" not in value)
    return True

def check_reviewed_client(value, callback):
    """Fail if an operator attempts wildcard/open redirects or privilege by scope."""
    # A reviewed Keycloak record must not acquire ANY additional capability,
    # mapper, OAuth grant type, origin, policy or vendor extension. Only these
    # two fields may differ from the committed dormant source profile.
    # Operators must redact the provider's generated IDs/secret and compare
    # the explicitly governed security-relevant client representation.
    expected = json.loads(TEMPLATE.read_text())
    expected["enabled"] = True
    expected["redirectUris"] = [callback]
    require(value == expected)
    return True

def response_json(response):
    require(response.status == 200)
    require(response.headers.get_content_type() == "application/json")
    raw = response.read(MAX_BYTES + 1)
    require(len(raw) <= MAX_BYTES)
    # Parsing JSON never authorises anything. Fail on duplicate attributes.
    def unique(pairs):
        out = {}
        for key, val in pairs:
            require(key not in out)
            out[key] = val
        return out
    return json.loads(raw, object_pairs_hook=unique)

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise Denied("redirect refused")

def fetch(url, method="GET", headers=None, data=None):
    """Exact operator-owned HTTPS endpoints, with redirects forbidden."""
    require(url.startswith("https://") and not os.environ.get("NODE_TLS_REJECT_UNAUTHORIZED") == "0")
    req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    return opener.open(req, timeout=5)

def introspect(issuer, client_secret, token):
    endpoint = issuer + "/protocol/openid-connect/token/introspect"
    encoded = base64.b64encode(f"{CLIENT}:{client_secret}".encode()).decode("ascii")
    data = urllib.parse.urlencode({"token": token}).encode()
    with fetch(endpoint, "POST", {"Authorization": "Basic " + encoded,
                                "Content-Type": "application/x-www-form-urlencoded",
                                "Accept": "application/json"}, data) as result:
        return response_json(result)

def cp_self(cp, token):
    endpoint = cp + "/v1/admin/effective-authority"
    req_headers = {"Authorization": "Bearer " + token, "Accept": "application/json"}
    try:
        with fetch(endpoint, "GET", req_headers) as result:
            return result.status, response_json(result)
    except urllib.error.HTTPError as err:
        # Never read or emit a potentially credential-bearing upstream body.
        return err.code, None

def check_positive_claims(raw, issuer, subject, client_id=CLIENT):
    require(isinstance(raw, dict) and raw.get("active") is True and raw.get("iss") == issuer
            and raw.get("sub") == subject and raw.get("client_id") == client_id)
    aud = raw.get("aud")
    require(AUDIENCE in (aud if isinstance(aud, list) else [aud]))
    require(SCOPE in str(raw.get("scope", "")).split())
    require(type(raw.get("exp")) is int and raw["exp"] > time.time())
    return True

def check_cp_response(raw, expected):
    require(isinstance(raw, dict) and raw.get("principal_id") == expected)
    require(isinstance(raw.get("grants"), list))
    evaluated = raw.get("evaluated_at")
    require(isinstance(evaluated, str))
    at = datetime.fromisoformat(evaluated.replace("Z", "+00:00"))
    require(at.tzinfo is not None and abs((datetime.now(timezone.utc) - at).total_seconds()) <= 30)
    return True

def run_protected(env):
    # No tokens are embedded in an input file or command line. Required
    # negative credentials MUST be independently obtained by authorised IAM
    # operators; synthetic fixtures never satisfy this runner.
    require(env.get("NABHOLD_G04B_ENVIRONMENT") == "staging")
    issuer = env["NABHOLD_G04B_ISSUER"].rstrip("/")
    cp = https_origin(env["NABHOLD_G04B_CP_ORIGIN"])
    estate = https_origin(env["NABHOLD_G04B_ESTATE_ORIGIN"])
    u = urllib.parse.urlsplit(issuer)
    require(u.scheme == "https" and u.hostname and not u.username and not u.password
            and not u.query and not u.fragment and u.path == "/realms/baobab")
    require(cp != estate and cp != f"{u.scheme}://{u.netloc}")
    callback = estate + "/api/auth/callback"
    profile_path = Path(env["NABHOLD_G04B_REVIEWED_CLIENT_FILE"])
    require(profile_path.is_file() and profile_path.stat().st_size <= 16384)
    require(profile_path.stat().st_mode & 0o077 == 0)
    check_reviewed_client(json.loads(profile_path.read_text()), callback)
    principal = str(uuid.UUID(env["NABHOLD_G04B_PRINCIPAL_UUID"]))
    require(principal == env["NABHOLD_G04B_PRINCIPAL_UUID"])
    subject = env["NABHOLD_G04B_SUBJECT"]
    require(subject and len(subject) <= 256 and subject.strip() == subject)
    secret = env["NABHOLD_G04B_CLIENT_SECRET"]
    require(len(secret) >= 16)
    tokens = {key: env["NABHOLD_G04B_" + key + "_TOKEN"] for key in
              ("POSITIVE", "WRONG_AUDIENCE", "REVOKED", "UNMAPPED")}
    require(all(40 <= len(t) <= 16384 for t in tokens.values()) and len(set(tokens.values())) == 4)
    live = introspect(issuer, secret, tokens["POSITIVE"])
    check_positive_claims(live, issuer, subject)
    status, body = cp_self(cp, tokens["POSITIVE"])
    require(status == 200)
    check_cp_response(body, principal)
    # Test a real token for a different audience, a genuinely revoked token,
    # and a live identity that CP has NOT mapped. No fabricated 404s count.
    wrong = introspect(issuer, secret, tokens["WRONG_AUDIENCE"])
    require(wrong.get("active") is True)
    aud = wrong.get("aud")
    require(AUDIENCE not in (aud if isinstance(aud, list) else [aud]))
    require(cp_self(cp, tokens["WRONG_AUDIENCE"])[0] in (401, 403))
    revoked = introspect(issuer, secret, tokens["REVOKED"])
    require(revoked.get("active") is False)
    require(cp_self(cp, tokens["REVOKED"])[0] in (401, 403))
    unmapped = introspect(issuer, secret, tokens["UNMAPPED"])
    require(unmapped.get("active") is True and unmapped.get("sub") != subject)
    aud = unmapped.get("aud")
    require(AUDIENCE in (aud if isinstance(aud, list) else [aud]) and SCOPE in str(unmapped.get("scope", "")).split())
    require(cp_self(cp, tokens["UNMAPPED"])[0] in (401, 403))
    # This is technical observation ONLY; real browser/consent/logout,
    # canonical business authorisation and independent G17 approval remain.
    return {"status": "OBSERVED_NOT_ACCEPTED", "technical_checks": 4,
            "protected_staging_accepted": False, "production_authorized": False}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--protected", action="store_true", help="execute real protected staging observations")
    args = parser.parse_args()
    try:
        check_template(json.loads(TEMPLATE.read_text()))
        if args.protected:
            result = run_protected(os.environ)
        else:
            result = {"status": "SOURCE_TEMPLATE_VALIDATED_NOT_ACTIVATED",
                      "protected_staging_accepted": False, "production_authorized": False}
        print(json.dumps(result, sort_keys=True))
        return 0
    except (Denied, KeyError, ValueError, TypeError, OSError, json.JSONDecodeError, urllib.error.URLError):
        print(json.dumps({"status": "BLOCKED", "protected_staging_accepted": False,
                          "production_authorized": False}))
        return 2

if __name__ == "__main__":
    sys.exit(main())
