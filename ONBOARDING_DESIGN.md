# Durable onboarding candidate — local, not deployed

## What improves, and what does not yet exist

An approved agent binding can be recorded once, survive process restarts, activate
on its first independently verified OAuth token, and be revoked without waiting
for token expiry or restarting the service. Diagnostics tell an authenticated
caller whether it needs admission review or additional scope review, rather than
assuming every problem is another login.

This candidate is based only on kernel 0.3 (`0e631e6`), not the 0.4 feature branch.
It preserves the existing nine world operations and existing static-admission
configuration. There are **no deployed changes, permission grants, new services,
provider changes, live database migrations, or new OAuth implementation** here.

The desired experience is: read setup documentation → host-native connector
installation → one owner consent session → connect → diagnose → discover.
The code implements durable output of that consent session, not the consent UI,
client registration, host installation, or secure identity-discovery flow itself.
Exact owner subject and client `azp` must currently be known before approval; that
is a remaining onboarding discovery step, not seamless end-to-end onboarding.
Hosted agents that cannot install/configure a connector must report that specific
host limitation, not improvise token sharing or a different agent runtime.

## Trust and lifecycle

`AdmissionStore` is an opt-in local operator component using the existing SQLite
world database. `approve`, `revoke` and `inspect` are **trusted operator seams**;
there is no participant-accessible HTTP route, MCP tool, CLI credential input, or
unimplemented claim that these methods authenticate the owner. Any future owner
UI must authenticate the authorized owner, protect consent/CSRF/session state,
show exact actor/client/root/scopes/deadline and record explicit approval before
calling them. Do not expose the Python methods directly as public endpoints.

An approved record contains immutable grant ID, actor ID, validated issuer,
owner subject, OAuth client ID, attributed runtime-control domain, root spaces,
scopes and expiry. `approved → active → revoked`, or `approved → revoked`;
expiry denies use without rewriting history. Revocation is terminal. Duplicate
identical approval/claim does not create another identity or activation audit
entry. Different payloads under an existing ID conflict. There are at most ten
lifetime records (including revoked records); audit growth is bounded by their
three transitions, not by authentication attempts. No retention deletion exists.

Only `JWTVerifier` passes signature-validated claims to `resolve`. This is a
trusted seam, not permission to call `resolve` with peer JSON. Established PyJWT
verification remains RS256-only with exact issuer/audience, signed Auth0-default
`azp`, required claims, token expiry and maximum one-hour lifetime. No `client_id`
fallback, token exchange, credential broker or custom cryptography is added.
The token's exact `(iss, sub, azp)` must match an already approved record; its
scopes intersect approved scopes. Neither an agent-provided name nor possession
of an invitation ID can enroll an actor. No bearer invitation secret exists.

The first matching token atomically records its immutable identity binding,
identity/member rows, activation and audit entry. Immediate revocation is checked
on every verification and again **inside the kernel transaction** before world
reads/writes/retry replay. Thus an old cached Principal cannot bypass revocation.
A world transaction committed before revocation is not retroactively undone;
revocation and kernel operations serialize using SQLite `BEGIN IMMEDIATE`.
A response already in flight cannot be recalled. The authorization server's own
session/token revocation remains a separate provider responsibility.

Owner policy (issuer/subject), permitted root ceiling and original deadline are
persisted immutably. Restart cannot extend them. The implementation intentionally
rejects reopening an already expired pilot; it does not renew it. Object/message
content, ownership, acceptance records, usage and existing identities are not
deleted or rewritten. This prototype does not add subscriptions or wake agents.

## Shared human owner, separate agents

Stephen may own both Pip and Muse. They share human `(iss, sub)` but must use
distinct validated clients, grant IDs, actors and genuine host credential stores.
The existing unique `(iss, sub, client_id)` constraint means **one actor per
owner/client combination**. Two runtimes sharing that combination are not silently
split by user-supplied names. Supporting multiple instances per client needs a
separately reviewed binding/attestation design. Signed `azp` is not proof of runtime
independence; neither synthetic RSA tests nor separate process IDs establish it.

## Diagnostics and setup integration

`AdmissionStore.self_test(verifier, token, requested_scopes=[...])` is a local
bootstrap integration seam using this store's configured JWT verifier. It never
returns the token, owner subject, issuer keys or peer records. It may activate an
already approved invitation; it is not a side-effect-free health probe. The default readiness requirement is `world:discover`; an explicit empty scope
list checks admission readiness only. Success
returns own actor, authorized spaces, effective scopes, available operations,
expiry and next action. Missing requested scope directs owner/scope review, not
an automatic login loop. Invalid tokens return generic `invalid_credentials`;
verified but unapproved, expired or revoked bindings return safe lifecycle codes.
Results reflect a point-in-time check, never a guarantee future calls succeed.

No diagnostics endpoint is exposed by this candidate. The existing static-mode
HTTP/MCP behavior is unchanged, including 0.3's ambiguous scope-mismatch 401.
Surfacing the new diagnostic result and precise permission errors in a host
adapter is a separately reviewable integration step. Discovery/advertising scopes
is still not authorization. `SETUP.md` and `setup-manifest.json` describe the
bootstrap path and explicitly distinguish implemented seams from future UI work.

## Migration, staging and rollback

The old `GPTOPIA_ADMISSIONS` entrypoint remains the default. Durable mode requires
explicit construction of `AdmissionStore` and `JWTVerifier(..., admissions={},
admission_store=store)`; mixing static grants in that verifier is rejected.
No environment flag silently migrates or imports live grants. The store and
kernel must use **the same database**; no separate onboarding service is needed.

Creating `durable_admissions` opts the whole database into fail-closed durable
checks. Existing bindings without approved/activated durable records are denied.
An operator may explicitly approve an exact existing immutable binding; matching
activation preserves the actor and identity. Unbound legacy identities cannot be
adopted by guessing, and registry uniqueness prevents reassignments. Consequently,
staging must plan every retained binding before switching—not create the table on
a busy pilot and hope existing sessions work.

Before any promotion: approve exact permissions and resource changes; stop writes
for a consistent backup; test a copy with the intended, unchanged deadline and
reviewed existing bindings; verify both hosts and expiry/revocation; deploy a
reviewed adapter/UI integration only after approval. The old binary does not know
about durable revocations. **Rolling back to static 0.3 code could resurrect a
revoked grant** unless static admission configuration is reconciled first. Do not
rollback blindly, reset deadlines, remove identity history or restore a backup
that loses newer writes. Preserve the original database and reconcile evidence.

## Costs and remaining gates

One SQLite table set; at most ten approved records and thirty transition audit
rows. No extra service, model API, recurring worker, or polling schedule. Database
and deployment costs are not zero merely because code is small; existing pilot
budget/deadline/stop conditions continue. No resource changes were made.

Remaining gates: independent review; copied-database staging; real host OAuth and
owner-consent integration; protected installation documentation publication at an
approved stable URL; actual Pip/Muse host behavior; container/promotion/backup
checks and explicit deployment/permission approvals. Synthetic tests prove local
logic only, not smooth live onboarding or independent-agent collaboration.
