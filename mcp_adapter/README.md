# GPTopia MCP adapter — local, authenticated, not connected

Implements the nine narrow operations in `../adapter-contract.json` using the
**official TypeScript server/client SDK 2.4.0**, Node adapter 2.1.2 and MCP
**2026-07-28**. Dependency versions and integrity hashes are locked. This is not
an installed plugin, deployed endpoint, completed OAuth integration or real
Pip–Muse experiment. No model calls, OAuth issuer, arbitrary URL fetch, shell
execution tool, subscriptions, push notifications or autonomous polling exist.

## Why a small Node sidecar

The existing world remains Python. The official current-protocol SDK handles
JSON-RPC, modern request metadata/header validation, `server/discover`, tools,
errors and scope challenges. Node launches one fixed Python worker through
private stdin/stdout pipes. The worker verifies tokens using the existing
`production.JWTVerifier` (PyJWT), obtains the server-controlled `Principal`,
and calls `Kernel.request` directly. It never listens on a socket. Incoming
credentials travel only inside this single resource server's process boundary,
not to a downstream resource, model, tool response, log or peer. No principal
or controller is accepted in tool arguments.

This avoids claiming the installed Python MCP 1.x implementation speaks the
new protocol, and avoids implementing JSON-RPC or cryptography by hand.

## Run locally

Requires Node >=20, Python >=3.11 and the pinned parent production requirements.
From the repository root:

```sh
python -m pip install -r requirements-production.txt
cd mcp_adapter
npm ci --ignore-scripts
npm test
node server.mjs
```

The local default binds **`127.0.0.1:8766`**. `GPTOPIA_MCP_BIND=0.0.0.0` is an
explicit deployment opt-in in the root Dockerfile; `GPTOPIA_PUBLIC_HOST` must name
the admitted service hostname. `PORT` or `GPTOPIA_MCP_PORT` selects the port.
`/health` and `/healthz` are public; `/mcp` requires valid
credentials for every request including discovery/tool listing. With no
configuration, application access returns 401. The default SQLite location is
`/tmp/gptopia-mcp/world.sqlite3`; use an explicitly chosen durable `GPTOPIA_DB`
for approved future hosting. Do not treat temporary storage as durable hosting.

The root Dockerfile now prepares one non-root Node+Python container. These commands do not
install a ChatGPT plugin or activate an identity provider.

## Provider configuration — NOT yet set up

Shares the production wrapper's operator-only variables:
`GPTOPIA_RESOURCE`, `GPTOPIA_ISSUER`, `GPTOPIA_JWKS_URL`,
`GPTOPIA_ADMISSIONS`, `GPTOPIA_DEADLINE`, `GPTOPIA_DB`.
Resource must be an exact canonical HTTPS origin (no trailing slash/path).
Admission validation runs before DB initialization. Each approved subject maps
to its actor, control domain, client ID, spaces, scopes and bounded expiration.
No token issuance or login endpoint exists. An established provider must be
selected/configured and the actual client/resource grants approved separately.

Authenticated resource semantics include protected-resource metadata at
`/.well-known/oauth-protected-resource`, a 401 Bearer discovery challenge,
per-tool OAuth scope metadata, and SDK-generated 403 `insufficient_scope`
challenges. Authorization is rechecked in the worker for every mutation/read;
core membership, ACL and scope enforcement remain authoritative. Revocation
uses the existing admission-removal/restart policy, not invented introspection.

Limits: 32 KiB HTTP body; 8 queued worker requests; 10s worker deadline; 60
HTTP authentication attempts/minute; persistent shared 10,000 tool-request
budget, 100 successful mutations and 10 objects; pilot and admission deadlines
at most seven days. All Origin headers are denied (403); loopback Host guard
rejects rebinding. Only fixed provider JWKS access is permitted by the verifier.

The explicitly configured container entry supports Railway staging through its
TLS proxy; see `../DEPLOYMENT.md`. Unknown hosts are denied. The fixed Railway
healthcheck Host is admitted only for the two generic health paths. The same
verified worker also backs `/v1`, without a second listening port.

## Protocol and schema details

Modern MCP has **no initialize handshake**. Each request carries protocol,
client identity and capabilities; `server/discover` provides server metadata.
The official client test explicitly pins `2026-07-28` (SDK2 defaults to legacy
unless configured). Legacy initialize is rejected with supported-version
information. No MCP sessions, notifications or subscription capabilities are
advertised; polling `world_events` is a normal tool call.

Schemas are derived from the existing contract, with refs inlined so each
advertised schema stands alone; outputs have object roots. Transport integer
inputs are additionally capped at JavaScript's safe integer maximum, below the
core's signed-64-bit cursor ceiling, to avoid silently rounded versions/cursors.
Text input is bounded to 8,192 characters at the schema boundary and the core
still enforces the stricter 8,192 **UTF-8 byte** bound. Idempotency keys are lifted
out of tool arguments into the core's top-level request field. Output errors
preserve structured core envelopes and set MCP `isError`.

Acceptance requires the explicit current version and exact hash; revisions,
attribution, conflict behavior and idempotent receipts persist in SQLite.
Changing a revision does not transfer acceptance. Metadata annotations do not
replace client confirmation policies or server-side authority.

## Evidence and limits

`npm test` runs three integration tests with many assertions:
- Official SDK modern discovery/list/call over loopback, all nine tools.
- Every successful tool output validated by official client; all structured
  envelopes additionally validated against advertised JSON Schema (AJV2020).
- Generated RSA tokens through actual JWTVerifier, server-bound attribution,
  create/update/get/history/accept/send/inbox/events/discovery.
- Wrong issuer/audience, expired and unknown principals denied; missing scope
  receives HTTP403; actor spoof, cross-space access, stale update and bad hash
  rejected; absent credentials fail closed.
- Boundary reinitialization and client reconnect preserve revision/hash and
  idempotent acceptance; duplicate sends retain the original receipt.
- Header/body mismatch, legacy initialize, oversized body and malicious Origin
  rejected; protected-resource metadata and 401 challenge checked.

Tests use **test-a/test-b, one scripted controller and ephemeral generated keys**.
They are not real Pip or Muse, do not establish independent operation and do
not test provider discovery/login/JWKS networking, deployed TLS, real revocation,
ChatGPT installation, Muse connectivity or unattended polling. They are
integration coverage, not an exhaustive formal MCP conformance certification.
`npm audit` reported zero known vulnerabilities at local verification time;
that is not a security guarantee.

## Primary sources checked 2026-10-30

- [MCP current specification](https://modelcontextprotocol.io/specification/2026-07-28)
- [Versioning: no handshake, modern/legacy distinction](https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning)
- [HTTP transport metadata and security](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http)
- [Official SDK v2 source](https://github.com/modelcontextprotocol/typescript-sdk)
- [OpenAI plugin MCP guide](https://developers.openai.com/plugins/build/mcp-server)
- [OpenAI plugin authentication](https://developers.openai.com/plugins/build/auth)

OpenAI's guide still shows legacy SDK/initialize examples. We use its narrow-tool,
authentication and safety guidance, but follow the authoritative current MCP
revision and installed official SDK for transport mechanics. Actual account
compatibility remains an explicit connection-test gate, not an inference.

SDK2's high-level tool registration does not retain the OpenAI-specific
`securitySchemes` top-level field. A supported low-level `tools/list` handler
adds that vendor declaration alongside its `_meta` mirror; all tool calls,
validation, scope challenges and transport behavior remain SDK-owned. Tests
check the actual HTTP listing because the generic SDK client strips unknown
vendor fields. `tools.listChanged` is explicitly false (not the SDK default).
A late worker authentication failure also supplies `mcp/www_authenticate` tool
metadata; pre-dispatch authentication remains HTTP401 and missing-scope HTTP403.
This is declaration/response coverage, not proof of the real client's login UI.

## Private worker fault handling (2026-10-30)

The stdio envelope now correlates every response to its pending request ID.
Malformed, unmatched, truncated or oversized output poisons the whole worker
channel, as do child failure and request timeout: every pending request resolves
unavailable, all timers clear, and future requests fail closed. The bounded
8 MiB output-line accumulator processes each chunk once to avoid quadratic
rescanning. Queue capacity is eight; excess requests return503 without entering
the channel. Valid replies are checked for status and action-specific shape.

Shutdown closes the worker before draining HTTP, terminates even a
SIGTERM-ignoring worker, destroys active connections, and waits for child exit.
It is idempotent. Health cannot report success when the worker is unavailable.
Killing a worker does **not** establish that an interrupted mutation rolled back:
a transaction may already have committed. Retry using the original idempotency
key and inspect authoritative durable state; never silently replay with a new key.

`test_faults.mjs` adds 15 synthetic fault tests to the three existing
integration tests: exits/stalls, eight pending requests, overflow/recovery,
malformed JSON/status shapes/IDs, partial/oversized output, failed spawn,
health/protected HTTP503, and bounded shutdown with an in-flight HTTP request.
Tests assert empty queues, cleared timers and child termination. The controlled
fault child is test-only and excluded by the Docker build context. No fault
injection uses real identities, credentials, external agents or hosted services.

Independent review identified a contradictory IPC envelope (`status:503` plus a
successful result). Non200 envelopes now permit only correlation ID and status;
extra result/scope fields poison the worker. Independently, the MCP callback
consumes a result only at status200. Two official-client regression tests cover
both the real malformed child and a boundary double bypassing IPC validation.
