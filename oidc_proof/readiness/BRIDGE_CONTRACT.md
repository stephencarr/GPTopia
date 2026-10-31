# Portable issuer → kernel identity bridge: local readiness finding

Checked 31 October 2026 against local `oidc-proof-03` parent commit
`a5686b24c8a39d9fb6657d4ebbafec2107b3e698`. No deployed code, credentials,
permissions or world data were changed.

## Finding

The portable OAuth proof and the existing 0.3 kernel do **not** yet share an
identity contract. The proof's resource handler resolves a server-assigned actor
from `(owner, client, OAuth grant)` and checks the current provider grant. The
0.3 production verifier intentionally selects an operator admission by
`(issuer, owner subject, signed azp/client)` and passes that operator admission
ID as `Principal.grant_id`. These are two different meanings of “grant”.

A configuration change or `client_id` → `azp` alias alone is not a safe bridge:
- Without the alias, 0.3 rejects the portable claim profile, as intended.
- With a synthetic alias, two different signed OAuth grant IDs resolve to the
  same old actor/admission; the OAuth grant claim is ignored.
- An unknown/revoked OAuth grant ID is not independently checked by 0.3. Its
  existing operator admission revocation policy still applies; this is not a
  claim of a new flaw in the currently configured Auth0 deployment.
- Adding two same-owner/same-client actors fails old registry validation.
- Substituting the OAuth grant ID into a Principal fails the kernel's immutable
  binding check instead of silently reassigning historical attribution.

## Reproduce

From repository root, with existing Python test dependencies:

```sh
python oidc_proof/readiness/test_bridge_contract.py
```

Five characterization tests pass. Keys are generated in memory, claims use
reserved `.example` domains, temporary SQLite state is deleted, and there are
no network calls. These are signed synthetic claim/real verifier tests, not real
provider-to-kernel interoperability, real agent onboarding, or a bridge fix.
A green test here confirms the documented incompatibility, not deployment readiness.

## Minimal next implementation contract

1. Keep the legacy binding mode explicit and unchanged. Introduce a separate,
   versioned grant-bound mode, never guess by presence of an untrusted claim.
2. Distinguish the stable application admission ID from the provider OAuth grant
   ID in names/schema. Bind the provider grant to exact validated issuer, owner,
   client and server-assigned actor. Never use display names as identity.
3. Verify signature, issuer, audience, lifetime and client profile through the
   configured provider. Consult current grant/revocation and current application
   admission before producing a Principal; unavailable state must deny access.
4. Make actor/admission creation transactional or implement an explicit recovery
   state that is non-admitted until complete. Preserve immutable old provenance.
5. Define owner-approved reconnect semantics. A fresh OAuth grant must not
   silently become an old actor, and reconnect must not strand access accidentally.
6. Test scope intersection, cross-grant actor confusion, stale/revoked grants,
   interrupted saves, concurrent reconnect, restart and historical acceptance
   readback with the actual bridge. Separate owner-client identity from evidence
   of independently operated runtimes.
7. Before any live migration, back up and test restoration of persistent data,
   choose compatible rollback semantics, and obtain the specific deployment,
   credential/grant and resource approvals. Do not weaken immutable checks merely
   to make new credentials work.

This finding is a bounded next engineering task. It does not justify another
host sign-in or a replacement public deployment today.

## Local V2 seam prototype (same-day follow-on)

`grant_bridge.py` adds an explicitly selected `GrantBoundVerifier` and
`ProofBoundary` outside production code. It distinguishes `oauth_grant_id` from
`admission_id`; the latter remains the kernel Principal's immutable `grant_id`.
It verifies synthetic signed portable JWTs, requires both current provider grant
and application admission, intersects token ∩ current provider-grant ∩ current application-admission scopes, and produces no actor from token
name/actor claims. Wrong binding, expiry, inactive or unavailable state denies.

`ProofBoundary` serializes local revocation and token verification plus the
complete kernel request under one process lock. The request path does not reuse
cached Principals. This prevents between-request local revocation being ignored;
it is **not distributed atomicity** against an independently running provider.

The test-only fresh V2 SQLite registry preserves authentic same-owner/client
attribution while allowing separate immutable admission IDs/actors. It refuses
any existing registry or identities and never migrates the pilot database. Schema
creation and in-memory grant/admission installation are not a durable recovery
protocol: setup failure can require discarding this temporary test database.

Run the thirteen seam tests:

```sh
python oidc_proof/readiness/test_grant_bridge.py
```

The tests perform real kernel create/update operations as distinct synthetic
actors sharing the same owner/client/control domain. This does not attest
independent runtimes. Additional tests cover revocation between requests,
unknown/wrong bindings, inactive admission, unavailable state, scope escalation,
inert actor claims, current provider-scope narrowing, missing/mismatched/expired provider state, setup rollback of all identity/binding/member rows, concurrent local request/revoke ordering, and immutable-registry mismatch/reinitialization rejection.

**Not implemented:** connection to the real proof provider's live Grant store,
durable admission storage, cross-process revocation synchronization, restart and
transactional recovery, owner approval/reconnect flows, signing key lifecycle,
legacy data migration or production wiring. Existing legacy verifier, kernel and
MCP deployment code remain unchanged. The seam is a local design/test artifact,
not a release candidate or replacement authentication server.
