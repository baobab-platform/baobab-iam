#!/usr/bin/env python3
"""Disposable original Keycloak broker-local session recovery witness.

A disposable Keycloak user authenticates through the native endpoint.
The administrator independently verifies that live user session, terminates
it, and disables the account. The restored provider must retain both denials.
This is NOT upstream enterprise SLO or CP/engine authority recovery.
Never persist passwords, access tokens or session IDs.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import secrets
import ssl
import stat
import sys
from urllib.error import HTTPError
from urllib.parse import urlencode, quote
from urllib.request import build_opener, HTTPSHandler, ProxyHandler, HTTPRedirectHandler, Request

ORIGIN = "https://localhost:8443"
REALM = "n08-revoked-recovery"
CLIENT = "n08-restore-native-client"
CA = "tests/enterprise/tls/ca.crt"
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

STAGE = "INITIAL"
LAST_HTTP = 0

def stage(name: str):
    global STAGE
    STAGE = name

class Denied(Exception):
    pass

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None

def request(method: str, path: str, payload=None, *, bearer="", form=False):
    if not path.startswith("/") or "//" in path or ".." in path or "#" in path:
        raise Denied("untrusted Keycloak route")
    body = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        if form:
            body = urlencode(payload).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        else:
            body = json.dumps(payload, separators=(",", ":")).encode()
            headers["Content-Type"] = "application/json"
    if bearer:
        if len(bearer) < 20 or len(bearer) > 8192 or any(ch.isspace() for ch in bearer):
            raise Denied("invalid private Admin credential")
        headers["Authorization"] = "Bearer " + bearer
    opener = build_opener(ProxyHandler({}), NoRedirect(),
                          HTTPSHandler(context=ssl.create_default_context(cafile=CA)))
    req = Request(ORIGIN + path, body, headers, method=method)
    try:
        with opener.open(req, timeout=10) as response:
            code = response.status
            raw = response.read(131073)
            if len(raw) > 131072:
                raise Denied("oversized Keycloak provider receipt")
            global LAST_HTTP
            LAST_HTTP = code
            return code, json.loads(raw) if raw else None
    except HTTPError as error:
        # Never surface returned bodies, credentials, session IDs or provider
        # messages. An error status cannot silently become accepted evidence.
        LAST_HTTP = error.code
        return error.code, None

def required(response, *codes):
    code, value = response
    if code not in codes:
        raise Denied("original Keycloak operation was refused")
    return value

def admin_token():
    data = required(request("POST",
        "/realms/master/protocol/openid-connect/token",
        {"grant_type":"password", "client_id":"admin-cli", "username":"admin",
         "password":"fixture-only-admin-password"}, form=True), 200)
    token = data.get("access_token", "") if isinstance(data, dict) else ""
    if not isinstance(token, str) or len(token) < 50:
        raise Denied("native Admin token unavailable")
    return token

def user_record(token: str, username: str):
    users = required(request("GET",
        "/admin/realms/" + REALM + "/users?username=" + quote(username)
        + "&exact=true", bearer=token), 200)
    if not isinstance(users, list) or len(users) != 1:
        raise Denied("exact original Keycloak user not unique")
    user = users[0]
    if not isinstance(user, dict) or user.get("username") != username:
        raise Denied("native Keycloak username binding mismatched")
    ident = user.get("id", "")
    if not isinstance(ident, str) or not UUID.fullmatch(ident):
        raise Denied("native user identifier invalid")
    return ident

def sessions(token: str, ident: str):
    data = required(request("GET", "/admin/realms/" + REALM + "/users/"
                            + ident + "/sessions", bearer=token), 200)
    if not isinstance(data, list) or len(data) > 20:
        raise Denied("native session readback ambiguous")
    seen = set()
    for item in data:
        if not isinstance(item, dict):
            raise Denied("invalid broker session record")
        sid = item.get("id", "")
        if not isinstance(sid, str) or not 12 <= len(sid) <= 160 or sid in seen:
            raise Denied("native broker session not uniquely readable")
        seen.add(sid)
        if item.get("userId") not in (None, ident):
            raise Denied("native broker session foreign subject")
    return len(data)

def state_file(path: Path, payload=None):
    if payload is None:
        st = path.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_mode & 0o077:
            raise Denied("private recovery evidence custody lost")
        return json.loads(path.read_text(encoding="utf-8"))
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, separators=(",", ":"))

def prepare(path: Path):
    stage("ORIGINAL_ADMIN_LOGIN")
    token = admin_token()
    stage("ORIGINAL_REALM_CREATE")
    required(request("POST", "/admin/realms",
       {"realm":REALM, "enabled":True}, bearer=token), 201)
    stage("ORIGINAL_CLIENT_CREATE")
    required(request("POST", "/admin/realms/" + REALM + "/clients",
       {"clientId":CLIENT, "enabled":True, "publicClient":True,
        "standardFlowEnabled":False, "directAccessGrantsEnabled":True},
       bearer=token), 201)
    username = "n08-restore-" + secrets.token_hex(10)
    password = "Aa!9-" + secrets.token_urlsafe(35)
    stage("ORIGINAL_USER_CREATE")
    required(request("POST", "/admin/realms/" + REALM + "/users",
        {"username":username, "enabled":True,
         "email":username + "@baobab.invalid", "emailVerified":True,
         "firstName":"N08", "lastName":"Disposable",
         "credentials":[{"type":"password","value":password,"temporary":False}]},
        bearer=token), 201)
    stage("ORIGINAL_USER_READBACK")
    ident = user_record(token, username)
    # A user-provisioning POST returning 201 does not attest that the native
    # credential provider installed the password. Use Keycloak's native Admin
    # reset-password operation, then read back required actions without
    # disclosing any password or provider response in the evidence.
    stage("ORIGINAL_NATIVE_PASSWORD_INSTALL")
    required(request("PUT", "/admin/realms/" + REALM + "/users/"
                     + ident + "/reset-password",
        {"type":"password", "value":password, "temporary":False},
        bearer=token), 204)
    stage("ORIGINAL_CLIENT_CONFIGURATION_READBACK")
    clients = required(request("GET", "/admin/realms/" + REALM
        + "/clients?clientId=" + quote(CLIENT), bearer=token), 200)
    if not isinstance(clients, list) or len(clients) != 1:
        raise Denied("native Keycloak direct-grant client not uniquely configured")
    client = clients[0]
    if not isinstance(client, dict) or client.get("clientId") != CLIENT \
            or client.get("enabled") is not True \
            or client.get("directAccessGrantsEnabled") is not True \
            or client.get("publicClient") is not True:
        raise Denied("native Keycloak direct-grant client configuration changed")
    stage("ORIGINAL_REQUIRED_ACTIONS_READBACK")
    current = required(request("GET", "/admin/realms/" + REALM
        + "/users/" + ident, bearer=token), 200)
    if not isinstance(current, dict) or current.get("enabled") is not True \
            or current.get("requiredActions", []) != []:
        raise Denied("disposable native user not ready for password grant")
    stage("ORIGINAL_USER_LOGIN")
    session_token = required(request("POST",
        "/realms/" + REALM + "/protocol/openid-connect/token",
        {"grant_type":"password", "client_id":CLIENT, "username":username,
         "password":password}, form=True), 200)
    if not isinstance(session_token, dict) or not isinstance(
        session_token.get("access_token"), str):
        raise Denied("genuine native Keycloak login not established")
    stage("ORIGINAL_SESSION_READBACK")
    if sessions(token, ident) < 1:
        raise Denied("original authenticated native session absent")
    stage("ORIGINAL_IDENTITY_DISABLE")
    required(request("PUT", "/admin/realms/" + REALM + "/users/" + ident,
                     {"enabled":False}, bearer=token), 204)
    stage("ORIGINAL_SESSION_LOGOUT")
    required(request("POST", "/admin/realms/" + REALM + "/users/" + ident
                     + "/logout", bearer=token), 204)
    stage("ORIGINAL_LOGOUT_READBACK")
    if sessions(token, ident) != 0:
        raise Denied("revoked native Keycloak session survived before snapshot")
    stage("ORIGINAL_DISABLED_READBACK")
    record = required(request("GET", "/admin/realms/" + REALM + "/users/"
                              + ident, bearer=token), 200)
    if not isinstance(record, dict) or record.get("enabled") is not False:
        raise Denied("native Keycloak user disablement not persisted")
    stage("ORIGINAL_PRIVATE_CUSTODY")
    state_file(path, {"realm":REALM, "username":username, "user_id":ident})
    print("N08_ORIGINAL_KEYCLOAK_LOGIN_REVOKED_AND_DISABLED")

def verify(path: Path):
    stage("RESTORED_PRIVATE_CUSTODY")
    item = state_file(path)
    if not isinstance(item, dict) or item.get("realm") != REALM or not UUID.fullmatch(
        str(item.get("user_id", ""))):
        raise Denied("original Keycloak restore witness invalid")
    stage("RESTORED_ADMIN_LOGIN")
    token = admin_token()
    stage("RESTORED_SUBJECT_READBACK")
    if user_record(token, item["username"]) != item["user_id"]:
        raise Denied("restored broker identity differs from original")
    stage("RESTORED_DISABLED_READBACK")
    state = required(request("GET", "/admin/realms/" + REALM + "/users/"
                             + item["user_id"], bearer=token), 200)
    if not isinstance(state, dict) or state.get("enabled") is not False:
        raise Denied("Keycloak restore resurrected disabled identity")
    stage("RESTORED_SESSIONS_READBACK")
    if sessions(token, item["user_id"]) != 0:
        raise Denied("Keycloak restore resurrected revoked native session")
    print("N08_RESTORED_KEYCLOAK_USER_DISABLED_AND_NO_REVOKED_SESSION")

if __name__ == "__main__":
    try:
        if os.getenv("GITHUB_ACTIONS") != "true" or os.getenv(
            "IAM_N08_ENTERPRISE_DISPOSABLE") != "1":
            raise Denied("only disposable original CI runtime authorised")
        if len(sys.argv) != 3 or sys.argv[1] not in ("prepare", "verify"):
            raise Denied("unknown recovery witness operation")
        target = Path(sys.argv[2])
        if not target.parent.is_dir() or not target.parent.stat().st_mode & stat.S_IXUSR:
            raise Denied("private recovery working directory required")
        (prepare if sys.argv[1] == "prepare" else verify)(target)
    except (Denied, ValueError, OSError, KeyError, TypeError):
        print("N08_KEYCLOAK_ORIGINAL_SESSION_RESTORE_HELD_" + STAGE + "_HTTP_" + str(LAST_HTTP), file=sys.stderr)
        sys.exit(2)
