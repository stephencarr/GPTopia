# One-prompt onboarding acceptance gate

Prepared 2026-10-31. Design only; no deployment or credential grant is authorized by this file.

## Outcome

An independently operated agent receives one setup prompt, discovers the service,
and completes normal owner approval in one or two meaningful confirmations. It
then performs an authorized read, returns after access-token expiry without asking
the owner to sign in again, and loses access promptly when its grant is revoked.
No operator must copy tokens, hand-edit a client ID, or repair callback parameters.

OAuth protocol success is not enough: record the real host, its credential context,
and the actual number of owner/operator steps. A synthetic client does not pass.

## Before any external test

- Finish and review the owner-login/consent boundary. The proof's test-owner header
  is not login and must never be publicly exposed.
- Integrate a versioned grant-to-actor bridge with the kernel. Never map a new grant
  onto existing `pip` or `muse` by display name, owner identity alone, or client alone.
- Review durable signing keys, secure credential storage/backups, atomic grant and
  actor persistence, revocation failure behavior, registration quotas and cleanup.
- Obtain specific approval identifying staging destination, resources/cost ceiling,
  exact host/client, owner identity, scopes, refresh lifetime and destruction policy.
  A provider-level offline toggle or new public issuer is a security change, not a
  routine continuation of the previous seven-scope Pilot approval.
- Keep existing Pilot source, issuer, actor bindings, volume and deadline unchanged.
  Use synthetic world content; do not copy private world data into staging.

## Test sequence and evidence

| Gate | Evidence required | Failure means |
| --- | --- | --- |
| Setup | Exact prompt, host/version, discovered metadata, registration path, observed approval count | Not one-prompt onboarding if operator repair is needed |
| Consent | Owner sees resource, actor context, requested powers and renewal duration; decline causes no admission | Unsafe admission if a partial/cancelled flow creates access |
| First use | Host's own tool result identifies the correct actor and pilot/test space | HTTP 200 or a manually replayed token alone is insufficient |
| Renewal | Actual token expiry, then same host performs a fresh request without interactive consent; actor is unchanged | No unattended credential continuity |
| Isolation | Separate credential contexts for two agents, including same owner/client if host supports it; mismatched owner/client/grant denied | Do not advertise independent agents if host shares one grant |
| Revocation | Explicit owner revoke, then both refresh and resource access denied; failed storage operation never reported as success | Security blocker |
| Restart | Whole application restart with durable storage/keys, then renewed access preserves actor/provenance | Provider object recreation alone does not pass |
| Recovery | Cancel, Back, repeated approve, stale link, duplicate callback, lost callback, concurrent refresh | No duplicate identities, scope growth or silent credential loss |

Record redacted request IDs, timestamps, status/error classes and returned actor,
message or revision identifiers. Do not record authorization codes, tokens, cookie
values, private keys or full sign-in URLs. Bind evidence to the exact tested commit.

## Scope and stopping condition

First use read-only discovery and inbox scopes plus explicitly approved renewable
access. A later write test needs its own approved scope set; do not repeatedly add
one scope as a blind workaround for a host setup failure.

Choose one supported real host first. If its documented discovery/registration or
refresh flow cannot complete, collect the exact failing stage and stop that route.
One repaired, evidence-backed retry is reasonable; endless reconnect loops and
manual token brokers do not meet the goal. Do not call a replacement test client
Muse or Pip. Foreground refresh does not establish autonomous wake/scheduling.

Only after the first host passes should the second independently operated host
repeat the same gate. Successful identity onboarding still does not complete M1:
both runtimes must negotiate, contribute and explicitly accept the same durable
revision with inspectable provenance and permissions.
