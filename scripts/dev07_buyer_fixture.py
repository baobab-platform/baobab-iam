"""IAM-owned native Hydra registrations for a leased DEV-07 identity proof.

Pure configuration builder. The orchestrator supplies a live, private run,
creates these clients through actual Hydra admin, reads them back and destroys
them. This helper signs no token and grants no CP or commercial authority.
"""
from datetime import datetime, timezone
import re

BFF = 'baobab-dev-zuribeans-bff'
VALIDATOR = 'baobab-dev-trade-buyer-validator'
CALLBACK = 'https://rp.baobab-dev.test/dev07/callback'
VALIDATOR_SCOPES = ['context:resolve', 'identity:principal:resolve', 'estate:client-binding:resolve']

def build_clients(registry, run_id, deadline, secrets, now=None):
    now = now or datetime.now(timezone.utc)
    if (not re.fullmatch('[0-9a-f]{32}', run_id) or deadline.tzinfo is None or now.tzinfo is None
            or not 60 <= (deadline - now).total_seconds() <= 3600):
        raise ValueError('DEV07_LEASE_REFUSED')
    workloads = registry.get('workloads', {})
    validator, bff = workloads.get(VALIDATOR, {}), workloads.get(BFF, {})
    if (validator.get('environment') != 'development' or validator.get('status') != 'ACTIVE'
            or validator.get('allowed_audiences') != ['baobab-control-plane']
            or validator.get('allowed_scopes') != VALIDATOR_SCOPES
            or validator.get('subject_principal_audiences') != ['baobab-trade']
            or validator.get('credential_type') != 'client_credentials'
            or bff.get('environment') != 'development' or bff.get('status') != 'ACTIVE'
            or bff.get('allowed_audiences') != ['baobab-trade']
            or bff.get('allowed_scopes') != ['trade:buyer-handoff']
            or bff.get('human_token_profile') != {'purpose': 'ESTATE_BFF_BUYER', 'audiences': ['baobab-trade'], 'scopes': ['trade:buy']}
            or bff.get('credential_type') != 'client_credentials'):
        raise ValueError('DEV07_REGISTRATION_REFUSED')
    if set(secrets) != {BFF, VALIDATOR} or any(not isinstance(s, str) or len(s) < 32 for s in secrets.values()) or len(set(secrets.values())) != 2:
        raise ValueError('DEV07_CREDENTIAL_REFUSED')
    result = {}
    for name in (BFF, VALIDATOR):
        human = name == BFF
        result[name] = {
            'client_id': name, 'client_secret': secrets[name],
            'grant_types': ['authorization_code', 'client_credentials'] if human else ['client_credentials'],
            'response_types': ['code'] if human else [],
            'redirect_uris': [CALLBACK] if human else [],
            # openid is OIDC protocol scope; business ceilings remain unchanged.
            'scope': 'openid trade:buy trade:buyer-handoff' if human else ' '.join(VALIDATOR_SCOPES),
            'audience': ['baobab-trade'] if human else ['baobab-control-plane'],
            'token_endpoint_auth_method': 'client_secret_basic' if human else 'client_secret_post',
            'client_credentials_grant_access_token_lifespan': '55s',
            'authorization_code_grant_access_token_lifespan': '300s',
            'metadata': {'environment': 'development', 'development_run_id': run_id,
                         'expires_at': deadline.isoformat(), 'owner': 'baobab-platform/baobab-iam', 'profile': 'dev07-buyer'},
        }
    return result


def normalised_claims(client, grant, subject, native_humans, assurance=None):
    """Identity only, from a verified native grant. Never roles/tenant/company.

    The same BFF has two legitimate grant types. Classifying it solely by
    client ID would turn its own workload token into a counterfeit human.
    """
    human = client == BFF and grant == ['authorization_code']
    workload = client in (BFF, VALIDATOR) and grant == ['client_credentials']
    if not (human or workload) or (human and subject not in native_humans) or (workload and subject != client):
        raise ValueError('DEV07_GRANT_REFUSED')
    claims = {'actor_type': 'human' if human else 'workload', 'azp': client, 'client_id': client}
    if human:
        if not isinstance(assurance, str) or not 0 < len(assurance) <= 255:
            raise ValueError('DEV07_ASSURANCE_ABSENT')
        claims['acr'] = assurance
    return claims
