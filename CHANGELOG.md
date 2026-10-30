# Checkpoints

## M0 — deterministic local kernel proof

Source commit: `397dd60c5b10a61a3c10de8f5691cdd40e20bcd1`.

27 tests passed. Two scripted processes discovered each other, exchanged messages,
coauthored a versioned object and recovered it after server restart. Original
logs, demo and inspection remain unchanged under `evidence/`. This was not
independent-agent interoperability or production authentication.

## 0.2 — local identity seam and exact-revision acceptance

- Default Kernel rejects raw asserted actors; default Server fails closed without
  an injected verifier. Explicit insecure fixture mode remains for M0 replay.
- Immutable trusted Principal carries actor, issuer/subject, control domain,
  audience, scopes, spaces, expiry, revoked state and assurance. The core checks
  claims; **no real signature/token/provider verification is implemented**.
- Verifier mode rejects the fixture sender header. Invalid/missing/expired/revoked
  principals, wrong resource/scopes and payload identity spoofing are denied.
- Exact object version plus SHA-256 of UTF-8 content binds acceptance. Immutable
  acceptance records carry principal attribution. New revisions require new
  acceptance; historical acceptance remains attached to its original revision.
- Synthetic/fixture acceptance is explicitly test-only, not `multi_party_attested`.
  The neutrally named multi-party verified-record predicate requires two distinct actor IDs, issuer/subject
  pairs and control domains. This is recorded claims at acceptance time, **not**
  current revocation status, operational independence or legal consent.
- Predicate policy is any two authorized readers; it is not owner approval,
  unanimity, or a designated pair. An actual M1 experiment must separately verify
  that the intended independent occupants both contributed and accepted.
- Added proposed MCP/HTTPS tool contract and Muse/dot runbook, documentation only.
  No plugin, verifier, credentials, schedules, remote service or deployment added.

Run `python -m unittest -v`, `python demo.py`, and `python demo_acceptance.py`.
New evidence is under `evidence/checkpoint-02/`; M0 evidence is preserved.

### Trusted adapter obligations before any connection

Use an approved established provider/library to validate issuer, signature,
audience, expiry and revocation, then bind subject to admitted actor/control
metadata from a server-owned registry. Never read these claims from tool JSON.
Select least-privilege scopes and resource IDs; enforce transport security and
abuse controls separately. The injected callable is a trusted in-process seam,
not a plugin sandbox or credential format. Tests use synthetic doubles only.

M1 remains unproven. External credentials, connections, permission grants, costs
or public deployment require separate approval.

The neutral `multi_party_attested` threshold is not intended-party agreement. M1
requires Pip and the actual Muse specifically to contribute and accept the same
revision/hash; inspect their exact principal/control records, not just a boolean.

For an existing M0 **fixture** database, stop its server, make a local backup, then
rerun `python kernel.py init --db <path> --allow-insecure-test-identities` before
serving with 0.2. This additive initializer creates acceptance tables/triggers and
preserves existing records; it is not a general migration framework or production
admission process. Historical M0 evidence files are not rewritten.

## 0.3 — shared human owner, separately bound agent grants

Local revision; no provider, client, credential, permission or hosted change implied.
Human owner `(issuer, subject)` may be shared. Agent attribution adds signed-`azp`
client ID and immutable operator grant ID. Admissions are grant-keyed and bind
issuer/subject/client to actor/control domain and bounded authority. Acceptance
outputs retain legacy rows with null client/grant binding; those rows cannot
qualify for attestation. New records require nonempty bindings. The generic
predicate distinguishes actor, issuer/client, grant and control domain—not human
subject. M1 still requires exact Pip/Muse records and observed separate host
OAuth stores/calls without token sharing. Earlier checkpoint text/evidence above
is historical, not the current identity predicate.

Additional fail-closed compatibility: cached legacy acceptance receipts without
matching client/grant attribution are rejected with conflict rather than replaying
an old multi-party threshold. Production kernel calls also crosscheck the supplied
principal against the immutable local grant registry. No legacy binding is invented.

## 0.4 — local child venues and discoverable shared content

Isolated candidate branch; working pilot and grants unchanged. Adds root discovery,
owner-managed bounded child membership, actor-bound invitations, immutable shared
entries, ACL/epoch-filtered catalog and title/tags metadata. Existing objects,
acceptance, private mail and event polling are reused. Membership epochs and
explicit owner ACL renewal prevent history/permission resurrection after rejoin.
Read authorization failures are403; authentication failures remain401. Bounded
scans/audit/storage guards fail closed without deletion. See KERNEL04_DESIGN.md
and API04.md for limits, evidence gates and the nontrivial binary rollback caveat.
