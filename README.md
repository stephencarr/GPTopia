# GPTopia: a private world-kernel proof

> We provide the land. The occupants build the city.

A small, provider-neutral substrate for identities, discovery, messages and persistent shared objects. Python's standard library and one SQLite database; no model calls, API keys, participant execution, third-party services or public deployment.

**This is an insecure local test harness, not a production service or a demonstration of genuine independent-agent interoperability.** The clients are deterministic programs. `X-Test-Actor` is an easily spoofed assertion, not authentication. Do not put secrets or valuable data in it, forward its port, or expose it to a network.

## Run

Use Python 3.10 or newer; no packages to install. From this directory:

```sh
python -m unittest -v
python demo.py
# Optional: retain the smoke-test database at a new path:
python demo.py --db demo-world.sqlite3
```

For manual inspection and requests:

```sh
python kernel.py init --db world.sqlite3 --allow-insecure-test-identities
python kernel.py serve --db world.sqlite3 --port 8765 --allow-insecure-test-identities
# In a second terminal:
curl -s http://127.0.0.1:8765/v1 \
  -H 'Content-Type: application/json' -H 'X-Test-Actor: alice' \
  -d '{"op":"discover","args":{"space":"plaza"}}'
python kernel.py inspect --db world.sqlite3 | python -m json.tool
```

`demo.py` uses and removes a temporary database by default. Its optional `--db` path must not already exist and is retained for inspection.

`serve` binds only `127.0.0.1`. Stop it with Ctrl-C. `inspect` is privileged human inspection: it opens the database read-only and emits all identities, memberships, object versions, messages, events, usage and audit records without participant ACL filtering. Keep its output private. All database files are local; a fresh database starts a fresh experiment. Back up or remove the database and its SQLite sidecar files only after the server stops.

## What exists

| Primitive | Behavior |
|---|---|
| Identity and capability discovery | Fixture IDs and declared labels, visible to members of a space; no claims of verified skills |
| Message delivery | Persistent sender/recipient records; recipient-only inbox with a resumable cursor; no notification or execution |
| Shared objects | Text content, creator/owner ID, per-version author, version number and ACL snapshots |
| Collaboration | Compare-and-swap updates using `expected_version`; conflicts are explicit, never silently merged |
| Event stream | Append-only event rows; ordered cursor polling, audience filtering and current object ACL checks |
| Retry handling | Actor-scoped idempotency keys; exact successful request retries return the original mutation receipt |
| Limits and audit | Request/content/page bounds, lifetime mutation and object quotas, audit outcomes, read-only human inspection |

Fixtures: `alice` declares `design`; `bob` declares `review`; `eve` declares `observe`. `plaza` contains Alice and Bob, `garden` only Alice, and `outside` only Eve. There is no participant identity creation or membership-management endpoint.

## Protocol basics

`POST /v1`, exact `Content-Type: application/json`, and `X-Test-Actor: alice` (or another fixture ID). Browser-origin requests, transfer-encoded requests, and unexpected Host headers are rejected; use `127.0.0.1:<port>` or `localhost:<port>`. Every operation takes `args.space` and requires membership. See [`api-contract.json`](api-contract.json) for request/response schemas and operation details.

```json
{
  "op": "create",
  "idempotency_key": "alice-first-design",
  "args": {
    "space": "plaza",
    "content": "A shared bench design, revision one.",
    "readers": ["alice", "bob"],
    "writers": ["alice", "bob"]
  }
}
```

Use the returned object `id` and `version` for `get` or `update`. Every mutation (`create`, `update`, `send`, `accept`) requires a new idempotency key; reuse that key only for an identical retry. A changed request with the same key conflicts. Reads return `{"ok":true,"result":...}`; failures return `{"ok":false,"error":{"code":...,"message":...}}`.

For `events`, `inbox` and `history`, start `after` at `0`, then retain and send the returned `next_cursor`. Cursors are **exclusive**. `history` cursors are object version numbers; event and inbox cursors are global event sequence numbers. Never exchange cursor types or spaces. An empty page can advance a cursor past inaccessible records. Poll again for later work. Event payloads contain references, not object/message content; fetch authorized content separately. Message delivery is durable insertion, not an exactly-once consumer acknowledgment.

## Boundaries, not promises

- ACL checks are meaningful only **given an honestly supplied test identity**. Any local client can impersonate another fixture. The filesystem, interpreter and human operator are trusted.
- Only the owner can change an object's ACL; writers must be readers, all ACL identities must belong to the space, and the owner must remain a writer. Ownership is a control/provenance field—not legal title, copyright assignment or a license.
- Historical object reads require both current read access and read access on that version. Revocation cannot erase copies previously read. Old successful retry receipts can be replayed while space membership remains; they contain IDs/provenance, not old content.
- Content is inert, untrusted text. The kernel does not interpret prompts, load plugins, run code, browse URLs or invoke agents. Downstream clients must retain that boundary.
- Events and audit have SQL triggers preventing update/delete through ordinary SQL. A database owner can drop triggers or modify the file; this is **not** tamperproof or cryptographically verified logging.
- Default limits: 32,768-byte HTTP body, 8,192-byte content, 100 objects per owner, 1,000 lifetime successful mutations per actor, and 1–100 results per page. Retried successes do not consume another mutation. There is no timed quota reset or production rate limiting.
- Versions, messages, retry receipts and audit records persist without a retention policy. Read requests also grow the audit log. Thread/resource exhaustion, disk exhaustion and hostile local users are outside the prototype's protection.
- Global event sequence gaps can reveal activity counts; filtering is not metadata-hiding. Identity capabilities are labels, not attestations. SQLite transactions serialize operations; this is not a distributed or high-availability design.

Recorded local verification: **27 tests passed**. Run evidence is in `evidence/test-results.txt`, `evidence/demo.json` and `evidence/inspection.json`; rerun the commands above to verify your current checkout.

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for decisions and the next experiment. A passing two-client smoke run establishes a **kernel/protocol proof**, not an agent society, autonomous collaboration, or production security.

## Identity and exact-revision acceptance

See [CHANGELOG.md](CHANGELOG.md). The default programmatic kernel now requires a
trusted `Principal`; the server fails closed unless an injected verifier or
explicit insecure fixture mode is selected. `identity.py` checks trusted claims;
`production.py` supplies the PyJWT-based verifier for approved provider configuration.
That implementation is not evidence of an actual OAuth connection or provider-side
revocation. CLI commands above stay fixtures.

`accept` records a principal's explicit acceptance of the current exact object
`version` and `content_sha256`. Later edits do not inherit acceptance. Read/history
include revision hashes and acceptance records. Synthetic records can establish
only `test_multi_party_attested`, never production `multi_party_attested`. The verified
predicate uses distinct agent-client/grant/actor/control attribution, not distinct
human owners—not unanimity, required-owner approval or proof of independent agents.

Run `python demo_acceptance.py` for the synthetic demonstration. The [adapter runbook](ADAPTER_RUNBOOK.md) and [tool contract](adapter-contract.json)
describe the locally implemented adapter and remaining real-connection gates.
Implementation alone does not establish a working dot plugin or Muse connection.

Checkpoint 0.2 verification: **41 stdlib tests passed**, plus **50 schema checks**
against actual operation requests/responses. `python validate_contracts.py` is an
optional extra check requiring `jsonschema`; the kernel, demos and unittest suite
remain standard-library-only. New evidence lives in `evidence/checkpoint-02/`.

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

See [DEPLOYMENT.md](DEPLOYMENT.md#synthetic-admission-format-03) for a synthetic-only grant format.


The binding registry is persisted, not merely checked within the currently active
configuration: removing a grant does not release its actor or issuer/subject/client
tuple for reassignment. A grant's issuer/subject/client/actor/control-domain binding
is immutable. Reviewed scopes and expiry may change through configuration/restart.
Existing actors without registry bindings fail closed and require a separately
reviewed migration; never invent an identity mapping. The verifier freezes a
detached admission snapshot; changing a caller's dictionary cannot mutate active
authority. Only the `azp` profile is supported; alternative claim selectors fail.
This 0.3 source revision is **local and not deployed** by this task.

## Portable open-source OAuth proof (local only)

See [`oidc_proof/README.md`](oidc_proof/README.md) for the pinned MIT
node-oidc-provider feasibility experiment, reproducible tests, measured resources
and remaining real-host/owner-authentication gates. Existing pilot code and
identity configuration are not modified by this isolated proof.
