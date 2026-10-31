"""LOCAL compatibility harness, not OAuth issuer, provider client or deployed adapter.

Official profiles are explicit. No network defaults, token issuance, credential
storage, auto-enrollment or implicit conversion to the 0.3 kernel Principal.
"""
from dataclasses import dataclass
import math
import time
from typing import Callable

import jwt

from identity import SCOPES
from production import bounded_text, https_url


class Denied(Exception):
    pass


@dataclass(frozen=True)
class WorkOSIdentity:
    profile: str
    issuer: str
    owner_subject: str
    organization_id: str
    oauth_client_id: str | None
    agent_registration_id: str | None
    scopes: frozenset[str]
    expires_at: float
    token_id: str

    @property
    def binding(self):
        # The discriminator prevents collisions or accidental profile migration.
        workload = self.oauth_client_id if self.profile == 'connect_user' else self.agent_registration_id
        return (self.profile, self.issuer, self.organization_id, self.owner_subject, workload)


@dataclass(frozen=True)
class ApprovedBinding:
    """Explicit local policy test double; NOT provider consent or auto-admission."""
    binding: tuple[str, str, str, str, str]
    actor: str
    grant_id: str
    control_domain: str
    spaces: frozenset[str]
    scopes: frozenset[str]
    expires_at: float


@dataclass(frozen=True)
class Authorization:
    identity: WorkOSIdentity
    actor: str
    grant_id: str
    control_domain: str
    effective_scopes: frozenset[str]
    expires_at: float


class WorkOSCompatibility:
    def __init__(self, *, profile, issuer, audience, key_client, status_checker: Callable,
                 approval: ApprovedBinding, max_token_lifetime=3600):
        if profile not in {'connect_user', 'agent_registration'}:
            raise ValueError('explicit supported profile required')
        https_url(issuer)
        https_url(audience)  # exact configured resource, path allowed; no env-client-ID fallback
        if key_client is None or not callable(status_checker):
            raise ValueError('approved verification keys and live status boundary required')
        if type(max_token_lifetime) is not int or not 0 < max_token_lifetime <= 3600:
            raise ValueError('explicit bounded token lifetime required')
        if (not isinstance(approval, ApprovedBinding) or len(approval.binding) != 5
                or approval.binding[:2] != (profile, issuer)
                or any(not bounded_text(v) for v in approval.binding)
                or any(not bounded_text(v) for v in (approval.actor, approval.grant_id, approval.control_domain))
                or not isinstance(approval.spaces, frozenset) or not approval.spaces
                or any(not bounded_text(v) for v in approval.spaces)
                or not isinstance(approval.scopes, frozenset) or not approval.scopes <= set(SCOPES.values())
                or type(approval.expires_at) not in (int, float) or not math.isfinite(approval.expires_at)):
            raise ValueError('exact bounded approval required')
        self.profile, self.issuer, self.audience = profile, issuer, audience
        self.key_client, self.status_checker = key_client, status_checker
        self.approval, self.max_token_lifetime = approval, max_token_lifetime

    def verify(self, token):
        """Provider validation/refresh wire protocols are intentionally not invented."""
        try:
            if not isinstance(token, str) or not 0 < len(token) <= 8192:
                raise ValueError()
            key = self.key_client.get_signing_key_from_jwt(token).key
            claims = jwt.decode(token, key, algorithms=['RS256'], issuer=self.issuer,
                                audience=self.audience, options={'require': [
                                    'iss', 'aud', 'sub', 'org_id', 'scope', 'jti', 'iat', 'exp'],
                                    'strict_aud': True})
            if any(not bounded_text(claims.get(k)) for k in ['sub','org_id','jti']):
                raise ValueError()
            if (type(claims['iat']) not in (int,float) or type(claims['exp']) not in (int,float)
                    or not math.isfinite(claims['iat']) or not math.isfinite(claims['exp'])
                    or not 0 < claims['exp']-claims['iat'] <= self.max_token_lifetime
                    or not isinstance(claims['scope'],str) or len(claims['scope']) > 4096):
                raise ValueError()
            if self.profile == 'connect_user':
                # Reject M2M and delegated/agent tokens instead of interpreting a
                # machine subject as its human owner. sid is documented consent ID.
                if (not bounded_text(claims.get('client_id')) or not bounded_text(claims.get('sid'))
                        or 'act' in claims or claims['sub'].startswith('agent_reg_')):
                    raise ValueError()
                owner, client, registration = claims['sub'], claims['client_id'], None
            else:
                act = claims.get('act')
                if (not claims['sub'].startswith('agent_reg_') or not isinstance(act,dict)
                        or not bounded_text(act.get('sub')) or 'act' in act):
                    raise ValueError()
                owner, client, registration = act['sub'], None, claims['sub']
            result = WorkOSIdentity(self.profile, self.issuer, owner, claims['org_id'], client,
                                    registration, frozenset(claims['scope'].split()), claims['exp'], claims['jti'])
            if result.binding != self.approval.binding:
                raise ValueError()
            # Strict True; unavailable, expired, unverified, revoked and malformed
            # decisions deny. No positive cache. Tests inject synthetic doubles.
            if self.status_checker(token, result) is not True:
                raise ValueError()
            if not time.time() < min(result.expires_at, self.approval.expires_at):
                raise ValueError()
            return result
        except Exception:
            raise Denied('invalid_or_inactive_identity') from None

    def authorize(self, token, *, operation, space):
        identity = self.verify(token)  # every call, including a renewed token
        effective = identity.scopes & self.approval.scopes
        if space not in self.approval.spaces or operation not in SCOPES or SCOPES[operation] not in effective:
            raise Denied('permission_missing')
        return Authorization(identity, self.approval.actor, self.approval.grant_id,
                             self.approval.control_domain, effective,
                             min(identity.expires_at,self.approval.expires_at))
