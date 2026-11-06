#!/usr/bin/env python3
"""Real disposable Kratos+Hydra recovery fixture; secrets held only in private file.

No remote endpoints, staging, production, CP grants, email/person data or
provider-state mocks. The same client/identity are independently checked after
both provider databases are destroyed and restored from original PG17 dumps.
"""
from __future__ import annotations

import json
import os
import secrets
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

KRATOS_PUBLIC = "http://127.0.0.1:4433"
KRATOS_ADMIN = "http://127.0.0.1:4434"
HYDRA_PUBLIC = "http://127.0.0.1:4444"
HYDRA_ADMIN = "http://127.0.0.1:4445"

class Refused(Exception):
    pass

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_):
        raise Refused("provider unexpected redirect")

opener = urllib.request.build_opener(
    urllib.request.ProxyHandler({}), NoRedirect())


def request(method: str, uri: str, body=None, *, token="", form=False):
    if not uri.startswith((KRATOS_PUBLIC + "/", KRATOS_ADMIN + "/",
                            HYDRA_PUBLIC + "/", HYDRA_ADMIN + "/")):
        raise Refused("only reviewed local disposable provider origin allowed")
    payload = None
    headers = {"Accept": "application/json"}
    if body is not None:
        if form:
            payload = urllib.parse.urlencode(body).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        else:
            payload = json.dumps(body, separators=(",", ":")).encode()
            headers["Content-Type"] = (
                "application/json-patch+json" if method == "PATCH" else "application/json"
            )
    if token:
        headers["X-Session-Token"] = token
    req = urllib.request.Request(uri, payload, headers, method=method)
    try:
        with opener.open(req, timeout=10) as response:
            if response.status < 200 or response.status > 299:
                raise Refused("unverified native provider state")
            raw = response.read(2_000_001)
            if len(raw) > 2_000_000:
                raise Refused("oversized provider receipt")
            return response.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as error:
        return error.code, {}


def ok(response, *codes):
    if response[0] not in codes:
        raise Refused("native provider returned an unexpected status")
    return response[1]


def save(path: Path, data):
    if path.exists():
        raise Refused("no pre-existing state file may be overwritten")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    fd = os.open(str(path), flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(data, stream, separators=(",", ":"))


def load(path: Path):
    s = path.lstat()
    if not stat.S_ISREG(s.st_mode) or s.st_nlink != 1 or s.st_mode & 0o077:
        raise Refused("private fixture state custody invalid")
    return json.loads(path.read_text())


def prepare(path: Path):
    nonce = secrets.token_hex(12)
    email = "n08-restore-" + nonce + "@baobab.invalid"
    pw = "Aa!9-" + secrets.token_hex(32)
    reg = ok(request("GET", KRATOS_PUBLIC + "/self-service/registration/api"), 200)
    identity = ok(request("POST", KRATOS_PUBLIC + "/self-service/registration?flow=" + reg["id"],
        {"method":"password", "password":pw, "traits":{"email":email}}), 200)
    subject = identity["identity"]["id"]
    session = identity["session_token"]
    if not subject or not session:
        raise Refused("Kratos native original credentials missing")
    ok(request("GET", KRATOS_PUBLIC + "/sessions/whoami", token=session), 200)
    # Explicit revocation; disabling credentials alone is not session withdrawal.
    ok(request("PATCH", KRATOS_ADMIN + "/admin/identities/" + subject,
       [{"op":"replace", "path":"/state", "value":"inactive"}]), 200)
    ok(request("DELETE", KRATOS_ADMIN + "/admin/identities/" + subject + "/sessions"), 204)
    current = ok(request("GET", KRATOS_ADMIN + "/admin/identities/" + subject), 200)
    if current.get("state") != "inactive":
        raise Refused("Kratos did not persist disabled identity")
    ok(request("GET", KRATOS_PUBLIC + "/sessions/whoami", token=session), 401)

    client_id = "n08-restore-" + nonce
    secret = secrets.token_urlsafe(48)
    client = {"client_id":client_id, "client_name":"N08 disposable restore proof",
              "client_secret":secret, "grant_types":["client_credentials"],
              "response_types":[], "scope":"context:resolve",
              "token_endpoint_auth_method":"client_secret_post"}
    ok(request("POST", HYDRA_ADMIN + "/admin/clients", client), 201, 200)
    observed = ok(request("GET", HYDRA_ADMIN + "/admin/clients/" + client_id), 200)
    if observed.get("client_id") != client_id or "client_credentials" not in observed.get("grant_types", []):
        raise Refused("actual Hydra client creation not observed")
    form = {"grant_type":"client_credentials","client_id":client_id,
            "client_secret":secret, "scope":"context:resolve"}
    token = ok(request("POST", HYDRA_PUBLIC + "/oauth2/token", form, form=True), 200)
    if not token.get("access_token"):
        raise Refused("actual Hydra access token was not issued")
    # Persist the client with no grants in the actual issuer.
    observed["grant_types"] = []
    observed["client_secret"] = ""
    ok(request("PUT", HYDRA_ADMIN + "/admin/clients/" + client_id, observed), 200)
    readback = ok(request("GET", HYDRA_ADMIN + "/admin/clients/" + client_id), 200)
    if readback.get("grant_types") != [] or readback.get("client_id") != client_id:
        raise Refused("Hydra grant withdrawal not independently observed")
    ok(request("POST", HYDRA_PUBLIC + "/oauth2/token", form, form=True), 400, 401, 403)
    # Never upload this file or put its contents into CI artifacts.
    save(path, {"identity_id":subject, "session":session,
                "client_id":client_id, "client_secret":secret})
    print("N08_REAL_KRATOS_HYDRA_REVOCATION_FIXTURES_OBSERVED")


def verify(path: Path):
    state = load(path)
    kratos = ok(request("GET", KRATOS_ADMIN + "/admin/identities/" + state["identity_id"]), 200)
    if kratos.get("state") != "inactive":
        raise Refused("Kratos restore resurrected disabled identity")
    ok(request("GET", KRATOS_PUBLIC + "/sessions/whoami", token=state["session"]), 401)
    client = ok(request("GET", HYDRA_ADMIN + "/admin/clients/" + state["client_id"]), 200)
    if client.get("client_id") != state["client_id"] or client.get("grant_types") != []:
        raise Refused("Hydra restore resurrected workload issuance")
    form = {"grant_type":"client_credentials","client_id":state["client_id"],
            "client_secret":state["client_secret"],"scope":"context:resolve"}
    ok(request("POST", HYDRA_PUBLIC + "/oauth2/token", form, form=True), 400, 401, 403)
    print("N08_REAL_KRATOS_HYDRA_RESTORE_DENIALS_OBSERVED")


if __name__ == "__main__":
    try:
        if os.getenv("GITHUB_ACTIONS") != "true" or os.getenv("ORY_FOUNDATION") != "1" or len(sys.argv) != 3 or sys.argv[1] not in ("prepare","verify"):
            raise Refused("requires isolated CI Foundation with explicit phase")
        file = Path(sys.argv[2]).resolve(strict=False)
        if not file.is_absolute() or file.parent.stat().st_mode & 0o077:
            raise Refused("owned private fixture directory required")
        (prepare if sys.argv[1] == "prepare" else verify)(file)
    except (Refused, OSError, ValueError, KeyError, TypeError, urllib.error.URLError):
        print("N08_ORY_LIVE_RESTORE_HELD", file=sys.stderr)
        raise SystemExit(2) from None
