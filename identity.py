"""Trusted injection boundary, NOT a token verifier or production auth implementation.

An approved adapter must validate authentication with an established library/provider,
then supply immutable Principal values. Never derive these fields from request JSON.
"""
from dataclasses import dataclass
import time

AUDIENCE = 'gptopia-local-kernel'
SCOPES = {
    'discover': 'world:discover', 'inbox': 'messages:read', 'send': 'messages:send',
    'get': 'objects:read', 'history': 'objects:read', 'create': 'objects:write',
    'update': 'objects:write', 'accept': 'objects:accept', 'events': 'events:read',
    'roots':'world:discover','spaces':'world:discover','space_get':'world:discover',
    'space_create':'spaces:write','space_invite':'spaces:write','space_accept':'spaces:write',
    'space_remove':'spaces:write','space_leave':'spaces:write',
    'post':'messages:send','entries':'messages:read','catalog':'objects:read',
}

@dataclass(frozen=True)
class Principal:
    actor: str
    issuer: str
    subject: str
    control_domain: str
    spaces: frozenset[str]
    scopes: frozenset[str]
    audience: str
    expires_at: float
    revoked: bool = False
    assurance: str = 'synthetic'  # fixture | synthetic | verified (trusted adapter only)
    client_id: str | None = None  # validated signed azp; NOT runtime attestation
    grant_id: str | None = None  # immutable operator admission identity

class AuthenticationError(Exception):
    pass


class AuthorizationError(AuthenticationError):
    pass


def validate(principal, op, space):
    """Defense-in-depth claim checks; signature/revocation lookup belongs to verifier."""
    if not isinstance(principal, Principal):
        raise AuthenticationError('verified principal required')
    if (type(principal.revoked) is not bool or principal.revoked or not isinstance(principal.expires_at, (float, int))
            or not time.time() < principal.expires_at < float('inf')):
        raise AuthenticationError('identity expired or revoked')
    if principal.audience != AUDIENCE:
        raise AuthenticationError('identity audience mismatch')
    if (not isinstance(principal.assurance, str) or principal.assurance not in {'fixture', 'synthetic', 'verified'}
            or not all(isinstance(v, str) and 0 < len(v) <= 200 for v in
                       [principal.actor, principal.issuer, principal.subject, principal.control_domain, principal.client_id, principal.grant_id])):
        raise AuthenticationError('identity attribution missing or invalid')
    if any(not isinstance(values, frozenset) or any(not isinstance(v, str) or not 0 < len(v) <= 200 for v in values) for values in (principal.spaces, principal.scopes)):
        raise AuthenticationError('identity scope claims malformed')
    if (space is not None and space not in principal.spaces) or SCOPES.get(op) not in principal.scopes:
        raise AuthorizationError('authenticated principal lacks operation or root-space permission')
    return principal


def fixture(actor):
    """Insecure local assertion. Caller must explicitly enable fixture mode."""
    return Principal(actor, 'insecure-fixture', str(actor), str(actor),
                     frozenset({'plaza', 'garden', 'outside'}), frozenset(SCOPES.values()),
                     AUDIENCE, time.time() + 60, assurance='fixture', client_id='fixture-client-' + str(actor),
                     grant_id='fixture-grant-' + str(actor))
