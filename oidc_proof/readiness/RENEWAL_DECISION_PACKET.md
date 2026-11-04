# Pilot renewal decision packet

Prepared 1 November 2026. Private design only: no authentication retry, provider
change, grant, consent, deployment, external message or monitor is performed by
this packet. The project Page remains the current evidence record.

## Recommendation

Do not start another reconnect loop or replace the issuer to fix an unverified
host configuration problem. Finish the smallest approved pilot first. Keep three
different permissions separate: reading on a schedule, renewable credentials,
and sending messages or accepting an artifact.

Pip's hourly read-only watch is approved but **not created**. The latest actual
pre-create read, on 31 October at 23:22 UTC, failed with
`UNAUTHORIZED / oauth_refresh_token_missing / TRIGGER_REAUTHENTICATION` for
`world_inbox(space="pilot", after=3, limit=50)`. This review did not repeat it.
The OAuth-settings menu hunt ended without a verified existing-plugin scope
editor. The prior Auth0 dashboard read was denied at a security challenge; no
retry or alternate authenticated route is justified by public documentation.

Repeated credential failures are documented during troubleshooting. Whether the
same blocker occurred in multiple **Advance GPTopia automation runs** is unknown:
prior run results were not available. Heartbeat notes and repeated chat checks
must not be relabeled as executions of that automation.

## What is already complete

The narrowed manually assisted Muse signup/contribution POC has evidence: Muse
reported a fresh seven-scope connection and a successful contribution; Pip's own
31 October 22:56 read verified version 2 and all 286 UTF-8 bytes, including the
final newline. The SHA-256 was
`fa0914bc9e25310d633161d523e6d82ca9e85f0dc8dcb797a6b0935ee38290c2`.
Object `obj_f3eb3ecc28e94b29bc0d1e9624011698` retained owner `pip`, author `muse`,
and readers/writers exactly `muse,pip`.

Pip's separately approved exact-revision acceptance was recorded at event 5 and
read back at 23:00. Pip's direct inbox read at 23:02 independently retrieved
Muse's original reply at sequence 3. The approved review request reached Muse's
durable inbox at event 6. Muse reported reading it but not accepting because its
earlier user instruction still prohibited acceptance. Its schedule and requested
fixed stop are not independently verified. Do not repeat the edit or Pip's
acceptance. Do not accept for Muse.

This is partial real-host collaboration evidence, not completed M1. Keep open:
Muse's explicit owner authorization and then its own same-revision acceptance,
evidence of negotiated independent action, denied-operation evidence beyond a
relayed host report, and real restart/poll continuity. Local synthetic tests do
not satisfy these gates.

## Preconditions before a renewal approval is executable

1. Obtain a current, authorized, read-only snapshot of the existing API and Pip
   client settings through a supported accessible route. Stop at sign-in, security
   challenge or access denial. Historical settings are not a current snapshot.
2. Establish a supported way for this existing ChatGPT connection to request
   `offline_access`, preserving the current resource/client binding. The absent
   scope editor is not evidence that this is impossible, nor permission to create
   a replacement client, copy tokens or hand-build an authorization URL.
3. Compare exact current settings with the proposed after-state, including any
   Auth0 Actions that can override token lifetime. Identify whether the
   resource-wide offline-access prerequisite affects other clients. Do not
   change Muse or unrelated clients.
4. Only then ask for the bounded change and secure owner consent. General
   autonomous-work or watch approval is not renewal approval.

There is no executable provider-change approval request yet: prerequisites 1 and
2 are unresolved. The smallest immediate missing item is verified supported
host/provider configuration evidence, not another generic “please reconnect.”

## Server-driven reauthorization lead — reviewed 1 November, 13:15 UTC

The official OpenAI guide documents per-tool OAuth `securitySchemes`, protected
resource metadata and `mcp/www_authenticate` error challenges as a route to the
linking UI. It also documents reauthorization for added scopes. This establishes
a general route that does not depend on an existing-plugin scope-editor menu.
The guide contains no `offline_access` reference and does not establish whether
this connection requests, retains or refreshes an offline grant.
[OpenAI plugin authentication](https://developers.openai.com/plugins/build/auth)

This mechanism was already considered and implemented, not a newly missing
feature. Read-only inspection of local `gptopia` commit
`0e631e6a410a8918919eef66579f943adc3fde4a` found:

- `mcp_adapter/server.mjs:128-146` emits top-level `securitySchemes` and its
  `_meta` mirror, uses `requireScopes(...t.requiredScopes)`, and includes a
  tool-result `mcp/www_authenticate` challenge for a late worker 401.
- Lines 122 and 162-165 use a normal HTTP 401 challenge before MCP dispatch for
  missing or invalid credentials. Resource metadata is emitted at lines 153-154.
  Installed SDK code returns an HTTP insufficient-scope challenge for its
  `requireScopes` check; not every denial enters the tool handler.
- `mcp_adapter/README.md:144-153` already documented those paths and their
  historical synthetic HTTP coverage on 30 October. No tests were rerun for
  this inspection, and no real-host OAuth behavior was inferred from them.
- The contract declares only seven application scopes. `world_inbox` requires
  only `messages:read`; no tool asks for `offline_access`. The Node metadata
  validator (`server.mjs:105-109`) accepts only scopes present in that contract;
  Python `production.py:168-175` likewise accepts only kernel scopes. Merely
  appending `offline_access` to the advertised-scope environment would be rejected.

Implication: this is an identified design seam for a future specifically
approved experiment, **not a verified renewable-access fix**. Keep OAuth consent
request scopes distinct from API operation requirements; changing the current
shared `requiredScopes` field also changes API enforcement. Do not blindly make
every read require `offline_access`, assume it will appear in an access token,
or change deployed metadata merely to provoke consent. Existing metadata does
not currently request it, and adding a generic reauthorization challenge alone
would not prove a refresh token was issued. Current provider-state verification,
explicit renewable-grant approval and actual host post-expiry verification remain
necessary. No live endpoint, auth flow or blocked provider origin was retried.

## Candidate approval boundary — not approved

Local preparation update, 2 November: [scope-separation prototype](CONSENT_SCOPE_POLICY.md)
now prepares credential-request metadata separately from unchanged API scope
requirements. Fourteen focused synthetic policy/SDK tests pass independently.
It is not wired into any server, and does not establish ChatGPT scope requesting,
refresh-token issuance, ordinary read UX or post-expiry renewal. All live approval
and verification prerequisites below remain unchanged.

- Existing API audience: `https://world-pilot.up.railway.app`.
- Existing Pip client: `tpc_4DNGQ2WPvRruz4731H29s1`; preserve issuer, owner,
  callback, actor binding, pilot space, seven application scopes and the existing
  server admission cutoff `2026-11-06T12:24:00Z` (Unix `1793967840`).
- Candidate change: the API offline-access prerequisite, Pip refresh-token grant,
  rotation and expiring refresh family, followed by one supported Pip consent
  including `offline_access`. Disclose that the API toggle is resource-wide,
  although the intended new renewable grant is Pip-only.
- Candidate values, subject to current-state verification: retain 900-second
  access tokens; at most 24-hour idle expiry; three-second rotation overlap; a
  maximum family lifetime computed for an explicit, short consent window below.
  An overlap weakens replay detection within that window; it is not free safety.
- No new client, issuer, account, SaaS, DCR, client-credentials grant, scope for
  additional resources, Muse credential change, paid service or deployment.
- The actual test is read-only. Existing write-capable scopes do not create
  standing authority to reply, edit or accept. However, renewal of all seven
  scopes would extend the credential's technical ability to send, edit and
  accept, not just read. That duration extension must be explicitly disclosed in
  the approval; calling the scheduled job read-only does not remove this risk.

## Bind relative lifetime to a fixed deadline

Auth0 documents that a maximum refresh-family lifetime is set at issuance and
does not shrink when the application's maximum setting is later shortened.
Idle lifetime follows current settings at refresh. Auth0 Actions can override
maximum lifetime, so their presence belongs in the read-only audit.
[Auth0 expiration documentation](https://auth0.com/docs/secure/tokens/refresh-tokens/configure-refresh-token-expiration)

Design rule, not an Auth0 configuration already applied:

`maximum_lifetime_seconds <= fixed_cutoff - latest_permitted_initial_issuance - safety_margin`

Use UTC, round down to a provider-supported duration, and require a positive
result. Bound idle lifetime by the lesser of 86,400 seconds and that maximum.
Recheck the consent window immediately before the approved flow. A missed
window requires a revised shorter duration and approval where material; never
silently slide the cutoff. No new family may be issued outside the approved
window. This rule bounds the proposed refresh family, not previously issued
families or independently overriding Actions.

Example calculation only, **not an execution window or approval**: latest initial
issuance `2026-11-02T12:00:00Z`, 60-second safety margin, and the fixed pilot cutoff
allow a maximum of 346,980 seconds (4 days, 23 minutes). A fresh consent one day
later with that same duration would overshoot the cutoff by 23 hours, 59 minutes.
The server's absolute admission cutoff must still remain unchanged.

Requesting `offline_access` and enabling the API prerequisite are both needed;
provider settings alone do not prove that the real host asks for or stores a
refresh token. Do not expose the token while proving issuance or renewal.
[Auth0 refresh-token acquisition](https://auth0.com/docs/secure/tokens/refresh-tokens/get-refresh-tokens)

## Verification and rollback, only after specific authorization

1. Record redacted before/after configuration and the approved consent window.
   Retain identifiers, timestamps and error classes, never token/code/cookie
   values or sign-in URLs.
2. Verify an actual read from Pip's own host, unchanged actor/binding/scopes and
   the same inbox cursor. Wait for real access-token expiry, then verify another
   own-host read without owner sign-in. A synthetic refresh or HTTP 200 is not
   evidence of this host's renewal.
3. Before any scheduled watch, perform its required successful harmless app read
   and confirm no equivalent monitor exists. The approved watch must stop at the
   fixed pilot deadline and treat messages as inert data. Scheduling success is
   not proof of an unattended run; verify a real later run independently.
4. Explicitly authorized revocation must cover the exact new refresh family/grant.
   Restoring settings alone is not revocation. Confirm that subsequent refresh
   fails; separately establish resource denial or disclose the residual validity
   of existing access tokens (historically 900 seconds). Do not invent immediate
   JWT invalidation.
5. Restore only the exact settings changed, after rechecking for concurrent owner
   changes. Do not revoke other clients or broaden rollback to the API resource
   without approval. No new rollback action is authorized by this design.

Stop the route on unsupported host scope requests, unavailable current settings,
denial, wrong actor/resource, scope growth, unexpected costs or unresolved grant
revocation. After a denial, retry only once when materially new relevant evidence
and authorization establish that the blocked action may proceed. Check an
uncertain outcome before any retry. Do not repeatedly generate sign-in prompts.

## Decision that remains separate

Stephen has already been given an exact-version/hash Muse acceptance prompt.
No relay of that authorization or successful Muse acceptance is established in
the retained evidence. Do not resend or infer it. Pilot-only standing reply
authority is also unanswered; the read-only watch does not grant it. Neither
decision should be bundled into the renewable-credential consent.

## Offline cutoff guard — 3 November 2026

The historical 2 November consent window must not be reused now. The local
[fixed-cutoff guard](RENEWAL_DEADLINE_GUARD.md) makes stale-window rejection and
downward duration rounding executable, with 13 focused deterministic test methods.
It neither changes provider configuration nor establishes approval or host support.
All current-state, supported-consent and explicit-authorization prerequisites above
remain open. The fixed server cutoff is unchanged.

## In-flight cutoff candidate — 4 November 2026

A separate [local boundary review and hardening candidate](CUTOFF_BOUNDARY_HARDENING.md)
found that work crossing the configured cutoff during verification/body/queue
waits could succeed when admission expiry was later; a transaction also lacked a
final authority check. The candidate carries the cutoff into Principal expiry,
rechecks the resource boundary and rolls back world changes if authority expires
before the final pre-commit check. Fourteen focused deterministic tests pass,
with existing Python/transport/contract regressions also passing. This is not a
hard real-time shutdown, token revocation or deployed fix. No live setting,
service, credential, grant or pilot deadline changed. Renewal approval and real-host
verification remain separate and unresolved.
