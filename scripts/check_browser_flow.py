#!/usr/bin/env python3
"""Validate the browser graph against Keycloak 26's execution semantics.

CONDITIONAL counts as REQUIRED before its condition is evaluated. Mixing it
with ALTERNATIVE at one level discards identification alternatives, even if
the condition would subsequently be disabled. Do not 'fix' that by disabling
MFA: establish primary identity in a required wrapper, then evaluate assurance.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def validate(realm):
    flows = {flow['alias']: flow for flow in realm['authenticationFlows']}
    if len(flows) != len(realm['authenticationFlows']):
        raise ValueError('duplicate flow alias')
    for flow in flows.values():
        active = [e for e in flow['authenticationExecutions'] if e['requirement'] != 'DISABLED']
        requirements = {e['requirement'] for e in active}
        if 'ALTERNATIVE' in requirements and requirements & {'REQUIRED', 'CONDITIONAL'}:
            raise ValueError('mixed required/conditional and alternative executions')
        for entry in active:
            if entry.get('authenticatorFlow') and entry['flowAlias'] not in flows:
                raise ValueError('missing child flow')
    root = flows[realm['browserFlow']]['authenticationExecutions']
    by_alias = {e.get('flowAlias'): e for e in root}
    primary = by_alias['Baobab - Primary Authentication']
    passkey = by_alias['Baobab - Passkey Step-Up']
    otp = by_alias['Baobab - Step-Up']
    if primary['requirement'] != 'REQUIRED' or not primary['priority'] < passkey['priority'] < otp['priority']:
        raise ValueError('identify the user before ordered assurance checks')
    if passkey['requirement'] != 'CONDITIONAL' or otp['requirement'] != 'CONDITIONAL':
        raise ValueError('assurance conditions must be retained')
    base = flows['Baobab - Primary Authentication']['authenticationExecutions']
    if [(e.get('authenticator') or e.get('flowAlias'), e['requirement']) for e in base] != [
        ('auth-cookie', 'ALTERNATIVE'), ('identity-provider-redirector', 'ALTERNATIVE'), ('Baobab forms', 'ALTERNATIVE')]:
        raise ValueError('primary authentication alternatives changed')
    forms = flows['Baobab forms']['authenticationExecutions']
    if [(e.get('authenticator') or e.get('flowAlias'), e['requirement']) for e in forms] != [
        ('auth-username-password-form', 'REQUIRED'), ('Baobab - Privileged MFA', 'CONDITIONAL')]:
        raise ValueError('password or privileged MFA changed')
    mfa = flows['Baobab - Privileged MFA']['authenticationExecutions']
    if [(e.get('authenticator'), e['requirement']) for e in mfa] != [
        ('conditional-user-role', 'REQUIRED'), ('auth-otp-form', 'REQUIRED')]:
        raise ValueError('privileged role/OTP gate changed')


if __name__ == '__main__':
    validate(json.loads((ROOT/'config/realm/baobab-realm.json').read_text()))
    print('Browser primary identity, MFA and ordered assurance graph verified.')
