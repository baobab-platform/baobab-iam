#!/usr/bin/env python3
"""Real Keycloak browser-flow regression, restricted to disposable loopback CI.

This submits the issuer's actual HTML forms, including privileged TOTP setup,
and exchanges the code with S256. It is not RP security qualification: the
Infrastructure INT-02 Chromium/OIDC verifier still owns that acceptance.
All session HTML, credentials, codes and tokens remain in memory. Exceptions
are reduced to a fixed failure marker; urllib error strings can contain codes.
"""
import base64
import hashlib
import hmac
from html.parser import HTMLParser
import http.cookiejar
import json
import os
import secrets
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


class Callback(Exception):
    def __init__(self, query):
        self.query = query


class Forms(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []
        self.current = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'form':
            self.current = {'action': attrs.get('action'), 'inputs': {}}
            self.forms.append(self.current)
        if tag == 'input' and self.current is not None and 'name' in attrs:
            self.current['inputs'][attrs['name']] = attrs.get('value', '')

    def handle_endtag(self, tag):
        if tag == 'form':
            self.current = None


class Redirects(urllib.request.HTTPRedirectHandler):
    def __init__(self, origin, callback):
        self.origin, self.callback = origin, callback

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urllib.parse.urlsplit(newurl)
        if (target.scheme, target.netloc, target.path) == self.callback:
            raise Callback(urllib.parse.parse_qs(target.query))
        if (target.scheme, target.netloc) != self.origin:
            raise RuntimeError('Unexpected redirect')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def run():
    origin = os.environ.get('KC_URL', 'http://localhost:8080').rstrip('/')
    parsed = urllib.parse.urlsplit(origin)
    if parsed.hostname not in {'localhost', '127.0.0.1'} or parsed.path or parsed.username or parsed.password:
        raise RuntimeError('Loopback issuer required')
    if os.environ.get('BAOBAB_ENVIRONMENT') not in {'local', 'ci', 'test'}:
        raise RuntimeError('Disposable environment required')
    admin = os.environ.pop('BROWSER_ADMIN_TOKEN')
    issuer = origin+'/realms/baobab'
    callback = 'http://localhost:3003/browser-assurance-probe'
    client = 'baobab-control-plane-admin'
    users = []

    def api(path, body=None, method='GET'):
        payload = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(origin+'/admin/realms/baobab/'+path, payload,
                                     {'Authorization': 'Bearer '+admin, 'Content-Type': 'application/json'}, method=method)
        with urllib.request.urlopen(req, timeout=20) as response:
            document = response.read()
            return json.loads(document) if document else None

    def user(privileged=False):
        username = 'browser-assurance-'+secrets.token_hex(8)
        password = secrets.token_urlsafe(32)
        api('users', {'username': username, 'enabled': True, 'email': username+'@example.invalid',
                     'firstName': 'Synthetic', 'lastName': 'Assurance', 'emailVerified': True,
                     'requiredActions': [], 'credentials': [{'type': 'password', 'value': password, 'temporary': False}]}, 'POST')
        found = api('users?'+urllib.parse.urlencode({'username': username, 'exact': 'true'}))
        assert len(found) == 1
        uid = found[0]['id']
        users.append(uid)
        if privileged:
            role = api('roles/cp:platform-admin')
            api('users/'+uid+'/role-mappings/realm', [role], 'POST')
        return username, password

    def login(identity, privileged=False, passkey=False, wrong_password=False):
        # Each ceremony gets a new cookie jar, state, verifier and nonce. A
        # previous enrolled session must not hide a broken first-login path.
        cb = urllib.parse.urlsplit(callback)
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
            Redirects((parsed.scheme, parsed.netloc), (cb.scheme, cb.netloc, cb.path)))
        verifier, state, nonce = (secrets.token_urlsafe(32) for _ in range(3))
        params = dict(client_id=client, response_type='code', redirect_uri=callback, scope='openid',
                      state=state, nonce=nonce, code_challenge_method='S256',
                      code_challenge=base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('='))
        if passkey:
            # Essential requested LoA 3 may not be satisfied by password/TOTP.
            params['claims'] = json.dumps({'id_token': {'acr': {'essential': True, 'values': ['3']}}})

        def page(req):
            try:
                response = opener.open(req, timeout=20)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                html = response.read().decode()
                forms = Forms()
                forms.feed(html)
                return response.status, forms.forms

        def submit(form):
            action = urllib.parse.urlsplit(form['action'])
            assert (action.scheme, action.netloc) == (parsed.scheme, parsed.netloc)
            return page(urllib.request.Request(form['action'], urllib.parse.urlencode(form['inputs']).encode()))

        status, forms = page(issuer+'/protocol/openid-connect/auth?'+urllib.parse.urlencode(params))
        assert status == 200
        form = next(f for f in forms if {'username', 'password'} <= f['inputs'].keys())
        form['inputs'].update(username=identity[0], password=secrets.token_urlsafe(32) if wrong_password else identity[1])
        try:
            status, forms = submit(form)
            if wrong_password:
                assert status == 200 and any('password' in f['inputs'] for f in forms)
                return
            if passkey:
                # An unenrolled user must fail or receive a passkey challenge,
                # never obtain a successful code using baseline credentials.
                assert status in {200, 400, 500}
                return
            assert privileged and status == 200
            form = next(f for f in forms if {'totp', 'totpSecret'} <= f['inputs'].keys())
            # Keycloak TotpBean.totpSecret is the raw secret, not the base32
            # manual display value. Use the source realm's SHA1/30s/6 policy.
            digest = hmac.new(form['inputs']['totpSecret'].encode(), struct.pack('>Q', int(time.time())//30), hashlib.sha1).digest()
            offset = digest[-1] & 15
            form['inputs']['totp'] = str((struct.unpack('>I', digest[offset:offset+4])[0] & 0x7fffffff) % 1000000).zfill(6)
            form['inputs']['userLabel'] = 'synthetic-ci-only'
            submit(form)
            raise RuntimeError('MFA did not complete')
        except Callback as result:
            if passkey or wrong_password:
                assert 'code' not in result.query
                return
            assert result.query.get('state') == [state] and len(result.query.get('code', [])) == 1
            body = urllib.parse.urlencode(dict(grant_type='authorization_code', client_id=client,
                code=result.query['code'][0], redirect_uri=callback, code_verifier=verifier)).encode()
            with urllib.request.urlopen(issuer+'/protocol/openid-connect/token', body, timeout=20) as response:
                tokens = json.load(response)
            # Inspect issuer output only. Do not confuse unverified decoding
            # in this provider regression with the maintained RP verifier.
            segment = tokens['id_token'].split('.')[1]
            claims = json.loads(base64.urlsafe_b64decode(segment+'='*((-len(segment)) % 4)))
            assert claims['iss'] == issuer and claims['nonce'] == nonce and claims['aud'] == client
            assert str(claims['acr']) in {'1', 'silver'}

    try:
        ordinary = user()
        login(ordinary, wrong_password=True)
        login(ordinary)
        privileged = user(privileged=True)
        login(privileged, privileged=True)
        login(ordinary, passkey=True)
    finally:
        # Delete users/sessions through the owning API even after failures.
        # Credentials and session HTML are never written to disk or output.
        for uid in users:
            api('users/'+uid, method='DELETE')
    print('PASS actual browser password, privileged TOTP enrollment, baseline LoA 1, wrong-password and unsatisfied passkey paths')


if __name__ == '__main__':
    try:
        run()
    except Exception:
        print('FAIL real browser assurance regression; no credential/session details emitted', file=sys.stderr)
        sys.exit(1)
