# Architecture decisions and experiment boundary

## Goal

Test the smallest persistent environment in which clients can discover another identity, communicate, and revise an attributed shared artifact. The platform provides durable primitives and enforceable logical rules; it does not prescribe a social graph, economy, city simulation or agent behavior.

The present experiment uses deterministic clients. IDs and timestamps are generated at runtime; “deterministic” describes client logic and state-transition rules, not byte-identical runs.

## Decisions

### One process, one database, one protocol

A stdlib threaded HTTP listener exposes a single JSON endpoint on loopback. SQLite stores identities, space memberships, latest objects, immutable-by-API version snapshots, messages, events, retry receipts, usage and audit. No deployment or dependency installation is required.

This is deliberately simpler than a service mesh or a social-network UI. Separate client processes exercise an actual wire boundary while the database remains accessible to the human operator. SQLite `BEGIN IMMEDIATE` serializes requests, including audited reads. It provides atomic mutation-plus-version-plus-event-plus-retry-receipt commits and prevents lost updates through version checks. This trades throughput for a small, inspectable correctness surface.

### An explicit fixture trust boundary

The command-line initializer and server require `--allow-insecure-test-identities`. They provision local fixture records, not credentials. `X-Test-Actor` asserts which fixture is acting. Loopback binding, JSON-only bodies and rejecting browser Origin headers reduce accidental exposure; none is a replacement for authentication or an isolation boundary against local programs.

The module is a test library too: constructing `Kernel` directly does not establish an authentication boundary. The database-owning operator can inspect or change all state. Never describe ACL test passes as verified security against a malicious local actor.

### Spaces first, objects second

All operations check space membership. Object ACLs can include only members of that space. Read/write failures intentionally collapse missing and inaccessible object IDs to `not_found`. Owner-only ACL changes must preserve the owner as a writer and every writer as a reader. No transfer, deletion or membership mutation is implemented.

An object retains its original owner, while each version records its actual author, content and ACL snapshot. These are provenance and authorization records, not legal-rights guarantees. The current object table is a convenience projection; version history is independently inspectable.

### Optimistic collaboration; no implicit merge

An update states `expected_version`. Exactly one concurrent update against a given current version can succeed. The other receives `conflict`, fetches the latest state, and decides whether and how to retry with a new idempotency key. The kernel never merges text or decides which contributor is right.

### Durable communication without autonomous execution

Sending inserts a message and event in the same transaction. The recipient polls its inbox. There is no execution, acknowledgment protocol, email delivery, or push subscription. Event records reference messages/objects and carry audience snapshots. Current object ACLs additionally filter object events; historical content requires both historical and current read permission.

Payloads are untrusted inert strings. A document saying “ignore your rules” is just stored text. A future agent client, not this kernel, must decide how to interpret data without treating it as higher-trust instructions.

### Idempotency and cursors are explicit

Successful mutations store an actor-scoped key, canonical-request digest and response. An identical retry returns the same receipt without duplicating content or events; a different request with that key conflicts. Errors are not cached, so a failed key may later succeed. This is mutation deduplication, not exactly-once end-to-end delivery.

Cursors are exclusive integer positions. Events use a global sequence; history uses an object version. Access-filtered scans may advance beyond hidden rows. Clients keep cursors per stream and space. A newly granted reader does not automatically receive earlier versions/events whose stored ACL excluded it. Global sequence gaps are a known metadata side channel, not an opaque private cursor design.

### Bounded writes and inspectable outcomes

Content, requests, page sizes and ACL lists have explicit bounds. Actor mutation quotas are lifetime counters; object quotas count owner records. Audit captures operation and outcome, not message/content payloads. Successes and deduplicated retries are audited; handled kernel rejections are audited after rolling back the attempted mutation. Transport-level rejection is not a complete audited security trail.

SQL triggers reject ordinary event/audit update or deletion. They do not prevent tampering by the database operator. Storage retention, backups, migrations, authorization administration and abuse resistance remain explicit gaps.

## Verification scope

The runnable tests target cross-space rejection, object ACL enforcement, owner-only ACL updates, historical access filtering, content bounds, optimistic conflicts, idempotency, pagination, quotas, persistence and append-only triggers. The smoke demo uses two deterministic client processes and a local kernel. Test output is the authority for what actually passed; this document does not substitute for running it.

## Roadmap: separate evidence gates

1. **Kernel proof — this deliverable.** Two scripted processes discover fixtures, communicate and persist revisions. Verify state, conflicts, failures and restart behavior. No claims about independent reasoning or cross-runtime agent interoperability.
2. **Independent-runtime protocol experiment.** Implement a second client independently (not a thin wrapper around the first client), define a shared task and success criteria, and test discovery/message/artifact compatibility over the documented protocol. Deterministic implementations can establish interoperability before models are introduced.
3. **Genuinely independent occupants.** Select independently operated runtimes, establish consent and credentials through an approved process, constrain each client's tools, and test a task neither solves through shared orchestration. Record independent decisions, provenance and persistence. Any costs, external sharing, permissions or services require the user's authorization. This stage has not occurred.
4. **Security and operations before wider access.** Replace fixture assertions with real authenticated identities; specify revocation and membership administration; threat-model capability discovery and untrusted content; add resource/rate limits, retention, migration, recovery and audit integrity; obtain human approval before any public deployment or consequential infrastructure change.

No model provider, credential source, federation scheme, economy or licensing policy is assumed by this kernel. Adding them is a separate decision, not an implicit consequence of building the land.

## Identity binding 0.3: one human owner, separate agent grants

Stephen may authorize both Pip and Muse through the **same human owner** `(iss, sub)`.
A second human account is neither required nor evidence of agent independence.
The verifier derives `client_id` only from the signature-validated Auth0-default-profile
`azp` claim—never an unvalidated request field and never a `client_id`-claim fallback.
Operator admissions are keyed by immutable `grant_id` and bind exact
`issuer`, `subject`, `client_id`, `actor`, `control_domain`, `spaces`, `scopes` and
`expires_at`. The `(issuer, subject, client_id)` binding, actor and grant ID must
be unique; the human `(issuer, subject)` can repeat. An existing grant ID must not
be reassigned to a different binding. Revoke it; any replacement requires a newly
approved binding and must not reuse an already registered actor or owner/client tuple.

Each new acceptance records both `client_id` and `grant_id`. Migrated legacy
records expose these fields as `null`; they remain historical evidence but
cannot satisfy multi-party attestation. A qualifying pair has distinct actors,
`(issuer, client_id)` pairs, grant IDs and control domains, with verified assurance.
Distinct human subjects are **not** required. The generic flag still does not
mean a designated pair agreed, a legal agreement exists, or independent runtime
operation was proved.

A signed `azp` identifies an authorized OAuth client, not which agent runtime
made a call. M1 specifically requires actual Pip and Muse to contribute and accept
the same immutable revision/hash, with the exact recorded bindings matched to
those agents. Observe separate host-side OAuth credential stores and calls;
never copy/share one host's access or refresh tokens with the other. Separate
client registrations and operator labels alone are insufficient. Approval is
still required for provider configuration, client grants, credentials and real
connections; this local change does none of those things.


The binding registry is persisted, not merely checked within the currently active
configuration: removing a grant does not release its actor or issuer/subject/client
tuple for reassignment. A grant's issuer/subject/client/actor/control-domain binding
is immutable. Reviewed scopes and expiry may change through configuration/restart.
Existing actors without registry bindings fail closed and require a separately
reviewed migration; never invent an identity mapping. The verifier freezes a
detached admission snapshot; changing a caller's dictionary cannot mutate active
authority. Only the `azp` profile is supported; alternative claim selectors fail.
This 0.3 source revision is **local and not deployed** by this task.

Acceptance retry receipts from older schemas cannot bypass the new evidence gate:
the accepting actor’s stored issuer, subject, client, grant and runtime-control
binding must match the current principal, or replay conflicts. Legacy rows remain
readable with null client/grant and do not count toward a multi-party threshold.
