# Portable OAuth feasibility proof — local only

## Morning recommendation

**Continue with a bounded real-host staging experiment, not a production rollout.**
A maintained permissively licensed provider handles the protocol we need without
an identity SaaS account. This local proof exercised actual OAuth HTTP flows—not
mocked provider tokens—including refresh rotation and replay-triggered revocation.
The remaining uncertainty is the actual hosts and real owner-login/consent
integration, not whether a portable library can implement these protocols.

This is **not** a ready login system or a completed one-prompt onboarding demo.
Operating the library means owning an authorization server: signing-key lifecycle,
secure owner authentication, consent, persistence, abuse controls, patches,
backups, TLS, availability and incident response remain our responsibility.
We are avoiding custom OAuth protocol/cryptography, not operational responsibility.

## Reproducible local proof

Node 24.22.1, `oidc-provider` **9.13.3**, `jose` **6.1.3**, exact lockfile. The provider
package is MIT licensed; no fork or paid account was created. Run from this folder:

```sh
npm ci --ignore-scripts --no-audit --no-fund
npm test
```

Choose a writable local npm cache when the default cache is unavailable. Tests
bind only `127.0.0.1` on temporary ports, generate test signing/cookie keys in
memory, use temporary SQLite files and remove them. No real credentials are read,
created or stored; the persisted tokens are ephemeral synthetic test artifacts.
Do not expose `server.mjs`: its owner login/consent is deliberately a test double,
protected only by a random in-memory test header. It is not production authentication.

Official sources, checked 2026-10-31:
- [Provider and MIT license](https://github.com/panva/node-oidc-provider)
- [Configuration and interaction documentation](https://github.com/panva/node-oidc-provider/blob/main/docs/README.md)
- [Persistent adapter contract](https://github.com/panva/node-oidc-provider/blob/main/example/my_adapter.js)
- [Security/version support](https://github.com/panva/node-oidc-provider/security/policy)

The version is pinned. CIMD remains experimental and **not enabled/tested** here;
this proof uses DCR. Do not fetch arbitrary client metadata URLs or enable CIMD
without reviewing its draft/version and SSRF/client policy. Package installation
used the public registry with scripts disabled. No package audit/security-service
claim is made; license/version checks do not establish absence of vulnerabilities.

## What passes

`npm test` runs ten tests: seven durable adapter tests and three provider-harness
tests. The main HTTP test covers multiple assertions:

- Protected-resource metadata points to the local issuer; provider discovery
  advertises DCR and S256. Fresh public/native test clients register without an
  operator editing a per-client server environment variable.
- Authorization-code flow uses S256 and a configured resource audience. Missing
  PKCE, wrong verifier, wrong resource and wrong JWT audience are rejected.
- A synthetic owner approves separate grants. Even the **same owner and same
  OAuth client** can have two server-assigned actor IDs when the grants differ.
- Resource access verifies JWT signature/issuer/audience, scope and current grant,
  and binds exact owner/client/grant to the previously recorded actor.
- Refresh calls return rotated credentials without another owner interaction;
  a separate real-time expiry test rejects the expired access token and renews it;
  reuse of the old refresh token invalidates the grant and successor tokens.
  Concurrent HTTP refresh replay also fails closed.
- Another client cannot refresh or revoke this client's credentials. Revocation
  denies subsequent refresh and resource access before the JWT expires.
- Closing and recreating the provider with the same temporary SQLite storage and
  in-memory signing keys preserves the dynamic client, grant and actor; refresh
  continues. This is provider recreation, **not a whole-host/container reboot**.
- Adapter races use two independent OS processes: replay insert and single-use
  consume have one winner. Revocation tombstones block late successor writes.
- Consumed-state persistence, expiry, row/payload limits, actual SQLite page-growth
  rollback and the actor table's separate connection/page cap are tested.

These are independent **test processes**, not independently operated personal
agents. A real host may reuse one OAuth grant across multiple agent conversations;
we must not invent per-agent identity from their names. If a host cannot keep
separate grant/credential contexts, those contexts cannot be represented as
independent agents by this design. Distinct grants alone are not runtime attestation.

## Storage boundary and known limitations

`adapter.mjs` is a small reviewed **test adapter**, not a production adapter claim.
It uses SQLite atomic transactions, indexes and a durable grant-revocation
tombstone. Limits are 5,000 total model/tombstone rows, 64KiB/model payload,
32MiB main database and 100 lifetime proof-actor records. The actor connection has
its own page ceiling because SQLite `max_page_count` is connection-specific.
Expired provider artifacts are removed during test adapter upserts; tombstones
and actor provenance are retained and eventually fail closed at their limits.
No cleanup policy was applied to any live data.

Plaintext test token storage is unacceptable to ship without a credential-storage,
filesystem/backup access and key-management review. SQLite temporary journals and
other process/filesystem costs are additional to the main database bound. A full
disk can make revocation fail: treat that as **unresolved revocation**, stop access
if needed, and never report success from a failed transaction. The test's
row-cap revocation success does not establish disk-reserve incident behavior.

The separate proof actor table and provider grant save are not a single atomic
application transaction. Failures may leave an unusable orphan grant, not an
admitted actor; production needs reviewed transaction/recovery semantics. No
rate limiter or real admin/owner UI is supplied by this harness. DCR is restricted
to the exact loopback test callback/public native clients; this is a test policy,
not a production registration policy. The ephemeral keys intentionally do not
survive actual process loss. Production durable key storage/rotation is unbuilt.

## Resource evidence, not a hosting guarantee

Local provider HTTP tests sampled about **104MB RSS** with a roughly **70KB** test
database; installed proof dependencies occupy about **4MB**. See captured results.

`footprint.mjs` separately loads the provider beside the existing 0.3 MCP Node
modules and synthetic Python worker. With Node heap capped at 96MiB, the recorded
probe sampled **133.9MB combined RSS**, while exercising provider discovery and
31 kernel writes plus reads. It does **not integrate the provider's credentials
with the kernel** and is not simultaneous sustained OAuth issuance load.

The probe needs the repository's existing MCP dependencies installed separately;
it does not download them itself. Ten-millisecond sampling can miss peaks. Local
CPU timing varies with host contention and is not a 0.25-vCPU capacity proof.
Docker/Podman are unavailable, so no image/container memory test was performed.
These numbers make a small footprint plausible, but do not certify the current
250MB memory/100MB storage budget or authorize a resource change.

## Exact next gate and stopping rule

Keep the current pilot/source/volume untouched. Before live staging, obtain the
required approval for any deployment, credentials, resource changes or grants.
Use a copy/backup and explicit rollback reconciliation, never silent identity
migration. Existing 0.3 accepts its old owner/client binding; a reviewed versioned
grant-based provenance bridge is needed. No auth changes were made to that code.

A useful go/no-go test starts with the actual fresh supported host, one setup
prompt and a normal owner login/consent session. The host must discover and
register, obtain only reviewed resource scopes, keep its own credentials, reach
its correctly bound identity, then return after token expiry without manual
per-agent provider edits, token copying or another custom script. Verify
revocation, wrong-owner/client/scope denial and persistence after an actual
restart. Run it for actual Pip and Muse independently; hosted limitations must
be reported, not bypassed using a different runtime or model API.

DCR support, permission prompts, credential separation and automatic refresh are
**not yet tested in either real host**. A host that only supports CIMD needs a
separate reviewed compatibility test. Unattended/background return additionally
needs a supported host runtime capability and authorization; foreground refresh
is not proof of autonomous waking. If the real hosts cannot do this reasonably,
stop and report the limitation rather than building an endless credential broker.
