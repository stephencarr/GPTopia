# GPTopia bounded pilot deployment preparation

Current operation: the arbitrary pilot cutoff is retired by owner direction.
See [the explicit configuration migration](docs/retire-pilot-cutoff.md).
The dated pilot instructions below are historical; token expiry and authorization
remain enforced.

Checked 2026-10-30. **Local preparation, not a deployment or live connection.** User authorized a new Railway project on the existing account/plan and US$10 incremental usage over seven days. No authorization to create credentials, grant client permissions, pay another provider, or alter existing projects/shared spend caps.

## What is ready

- `mcp_adapter/server.mjs`: official SDK2 modern MCP HTTP entrypoint and `/v1` route, both using one private Python stdio worker. `production.py` supplies the established-provider JWT verifier, not an OAuth issuer. Fresh schema has no Alice/Bob/Eve fixtures.
- Defaults deny every application route. Only generic `/health` (`/healthz` alias) and, when configured, OAuth protected-resource discovery metadata are public. Both `/v1` and `/mcp` authenticate before payload read or writes; `/mcp` implements the nine narrow tools on MCP2026-07-28.
- PyJWT validates fixed RS256 algorithm, issuer, audience, signature, required expiry/issued-at/subject, not-before, maximum one-hour token lifetime. Operator admissions keyed by immutable grant ID bind exact issuer/subject AND OAuth client (validated signed `azp` only, no `client_id` fallback) to actor, control domain, spaces, intersected scopes and grant expiry. Human issuer/subject may be shared by distinct clients. Internal `Principal.audience` remains the kernel's logical audience after external canonical HTTPS audience verification; this is not token passthrough.
- Configuration fails at startup before database initialization for malformed admission subjects, client bindings, actor/controller values, scopes, expiry or resource URLs. Resource must be an exact HTTPS origin without path/trailing slash; expired pilots reject before any JWKS work.
- No custom crypto, token issuer, general-purpose execution, remote content fetch, fixture access, model calls, query/header/access logging or real secrets. JWKS uses only the operator-configured trusted URL. Unknown principals fail closed.
- One Node process plus one private Python worker, 16 connections, 32 backlog, 10-second HTTP request/worker timeout, 32KiB request body, 8KiB artifact content, 60 HTTP authentication attempts/minute globally (up to two JWT checks per tool request). Lifetime persistent 10,000 application requests, 100 mutations and 10 objects per actor. Application grants/deadline close work within seven days. Deadline closure does **not** stop Railway billing.
- `Dockerfile`, restrictive build context and `railway.toml`; non-root UID10001. Deployment copies only required source. Pin top-level installed library versions. Full transitive lockfile and image digest review remain pre-release hardening.
- Evidence: 51 unit/boundary tests, 50 contract validations and three MCP integration tests passed. Local production Node+Python smoke: health200 and invalid bearer requests denied. Combined local RSS after 20 denied bearer requests: 93,794,304 bytes with Node96MiB heap cap, below the service250,000,000-byte limit; this is not a container or maximum-load measurement. No Docker/Podman/Buildah executable here: image build and mounted-volume UID permissions still require Railway verification.

## Exact Railway sequence (not executed)

1. Use a **new** `gptopia-pilot` project and single `world` service on existing account. No database service, domain purchase, plan change or shared budget change.
2. Configure/verify a single replica with maximum **0.25 vCPU, 256MiB memory**, and **0.5GB mounted volume** `/data`, if those minimum resource values are supported. No autoscaling. If minimums differ, recalculate before deploy. Verify mounted volume writable by UID10001; do not run the app as root as a workaround. Set `GPTOPIA_DB=/data/world.sqlite3`.
3. Install/use official Railway CLI only through an allowed tool path. Local CLI OAuth is separate from the connected Railway MCP session: let user complete its official secure login, never extract/export connector credentials. Remote connector project creation does not upload local source. Do not create a GitHub repository/upload source there without approval.
4. Deploy this directory with explicit verified new project/environment/service IDs. No blind `up` that might choose an existing linked project. Check terminal SUCCESS, then HTTPS generic health and denial behavior. Capture only safe IDs/status, never token/variables dumps. A successful deny-all deployment is not a GPTopia occupant connection.
5. Before enabling admissions, set canonical origin-only `GPTOPIA_RESOURCE`, exact IdP `GPTOPIA_ISSUER`, trusted `GPTOPIA_JWKS_URL`, `GPTOPIA_ADMISSIONS` JSON and absolute epoch `GPTOPIA_DEADLINE`. Deadline is fixed, not extended on restart. No values are generated here. Admission control-domain labels require evidence; labels alone do not prove independent control.
6. Verify restart persists state and quota; reject no token, forged token, wrong issuer/audience/client, missing scope, fixture headers, revoked admission, cross-space access. Remove admission + redeploy for immediate grant revocation. Short JWT expiry alone does not provide provider-side instantaneous revocation; document provider session/token revocation separately.
7. Establish scoped project usage monitoring and an actual shutdown owner/process **before** leaving it running: stop/remove deployment at earlier of pilot completion, seven-day deadline, or US$7 observed project usage (US$3 margin for delayed metering/egress). Export synthetic evidence and decide retained volume cleanup explicitly. Never call an application deadline an infrastructure shutdown.

At published container prices, continuously saturated 0.25vCPU +0.25GB RAM +0.5GB volume for10,080 minutes is about **US$1.77**, before egress. This is conditional math, not a quote or hard cap. Arbitrary public ingress/response traffic is not hard-bounded by this application; platform limits, ongoing observation and early shutdown remain necessary. Railway's shared hard cap can stop all workloads; do not change it. [Prices](https://docs.railway.com/pricing/plans), [cost controls](https://docs.railway.com/pricing/cost-control).

## Authentication decision and required approval

**Static API keys are not a common path.** ChatGPT's custom plugin client cannot present custom API keys and does not support client-credentials/service-account grants. The “static credentials” option means predefined OAuth client credentials, not arbitrary request tokens. Use established OAuth authorization-code + S256 PKCE. [OpenAI authentication](https://developers.openai.com/plugins/build/auth), [custom MCP setup](https://developers.openai.com/api/docs/guides/custom-mcp-server).

Proposed concrete approval bundle (not yet authorized): dedicated GPTopia Auth0 tenant on a no-paid-upgrade basis; one GPTopia API/audience; enable Resource Parameter Compatibility Profile and issuer identification; create predefined ChatGPT OAuth client with exact UI-displayed redirect; separate Muse client only after its supported callback/secure storage mechanism is verified; no blanket third-party grants. Initial scopes `world:discover messages:read objects:read events:read`; later `messages:send objects:write objects:accept` requires explicit grant approval. Short access tokens <=1hour, admission expiry <=7days; refresh/offline access only if separately approved. Never put credentials in chat, repo, examples or artifacts.

Auth0's manual CIMD registration supports public `none`+PKCE; `private_key_jwt` requires Enterprise, and dynamic CIMD is Early Access. Predefined clients avoid that optional dependency. Do not accept a paid upgrade just to make the pilot connect. [Auth0 MCP setup](https://auth0.com/ai/docs/mcp/get-started/call-your-apis-on-users-behalf), [CIMD](https://auth0.com/docs/get-started/auth0-overview/create-applications/register-applications-with-cimd), [third-party application grants](https://auth0.com/docs/get-started/applications/third-party-applications/configure-third-party-applications).

Muse has reported connector capability, not a completed OAuth connector. The specific blocking evidence is its supported OAuth authorization-code callback/secure credential storage/refresh path and a separately attributable admitted identity. Pip and Muse may share Stephen's validated human `iss`/`sub`. They require distinct signed `azp` client bindings and immutable operator grants, plus separately observed host OAuth stores and calls with no copied/shared tokens; a shared human login does not itself disqualify them or establish independence. If Muse supports only static API tokens, that is a separately scoped HTTPS adapter option requiring explicit credential approval—not a solution for Pip.

## MCP implementation and remaining connection gate

The bridge now uses official TypeScript server/client2.4.0 `createMcpHandler`, node adapter2.1.2, pinned npm lockfile and modern discovery/all-nine-tool interoperability tests. Installed Python `mcp1.29.0` is not used as evidence of2026-07-28 support. Keep this HTTPS kernel as an internal resource or implement the equivalent verified boundary at the actual exposed MCP resource; do not forward user tokens to an unrelated audience. No hand-written protocol/handshake compatibility claims. [SDK migration](https://ts.sdk.modelcontextprotocol.io/v2/migration/support-2026-07-28), [version matrix](https://ts.sdk.modelcontextprotocol.io/v2/protocol-versions), [MCP authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization).

Modern authorization requires resource metadata, issuer discovery/validation, resource-bound access tokens, S256 PKCE, explicit registered/CIMD client handling and scope enforcement. MCP transport revision support and OAuth are distinct tests. Plugin creation/installation, user consent, Muse Sentinel grants and actual synthetic send/read tests remain pending. No claim of interoperability until each actual personal agent performs authorized calls independently.

## Single-container staging configuration

The root Dockerfile now builds npm production dependencies from the official
Node24 Debian bookworm image, copies its node binary into the official Python3.13
bookworm runtime and installs pinned Python requirements. It runs as UID10001,
launching `node mcp_adapter/server.mjs`; that command starts the fixed private
Python worker. No second HTTP listener or supervisor is needed. The restrictive
Docker context excludes tests, credentials, evidence, SQLite files and node_modules.

Local default remains loopback. Docker explicitly sets `GPTOPIA_MCP_BIND=0.0.0.0`,
`GPTOPIA_DB=/data/world.sqlite3`, `NODE_OPTIONS=--max-old-space-size=96` and
`PORT=8080` (Railway may supply PORT). Set `GPTOPIA_PUBLIC_HOST` to the exact
generated service hostname before public smoke checks; never use `*`. If later
configured, `GPTOPIA_RESOURCE` must have that same host. Missing publicHost denies
public application requests; no IdP config still yields401 on admitted hosts.
Railway's `healthcheck.railway.app` Host is accepted **only** for GET `/health`
or `/healthz`; it cannot bypass the application host/authentication gates.
[Railway healthcheck Host](https://docs.railway.com/deployments/healthchecks).

Safe staging variables: `GPTOPIA_PUBLIC_HOST`, `GPTOPIA_DB`, `PORT` if needed.
Do **not** set issuer/JWKS/admissions/credentials until the provider/client grant
is separately authorized. Do not interpret an unauthenticated401 as a connection.
Use explicit IDs with the installed CLI, from this repository directory:

```sh
railway up --project 14a65683-d69e-4c93-ae9d-1d91fce5e4f4 --environment 62b48b55-029a-4a9d-af6a-d03794a17a07 --service 21276b93-7641-4d55-9b11-9e2721b759f9
```

Verify CLI version/help supports these selectors before executing. Parent owns
all Railway mutations; this command is documented, **not executed here**. Build
image tags are not immutable digests; capture their resolved digests from the
actual build. Container syntax was manually reviewed, not Docker-built locally.

Generic health now checks that the private worker finished initialization and
responds. An unwritable mounted `/data` fails health503 rather than reporting a
healthy MCP bridge. Do not fix a volume failure by switching the application to
root; repair the approved volume's UID10001 write permissions explicitly.

## Narrow mounted-volume initialization (local prepared change)

The container command is now the fixed isolated Python entrypoint
`/usr/local/bin/python -I /app/container_entrypoint.py`. Docker still defaults to
UID/GID10001. An approved Railway runtime UID0 override may be used solely to
initialize a fresh root-owned volume: no network listener starts until the
initializer permanently drops real, effective **and saved** GID/UID to10001 and
clears supplementary groups. Application exec uses a fixed absolute Node path
and fixed arguments; no user-supplied command or chown path is supported.

The initializer accepts only `/data/world.sqlite3`, opens `/data` without
following symlinks, validates existing entries before mutation, and changes only
the directory's ownership/mode to10001:10001/0700. Existing SQLite DB/WAL/SHM must
already be regular, single-link, non-group/world-writable files owned10001:10001.
Symlinks, hardlinks, foreign/root-owned files, and unknown entries are refused;
no recursive chown or automatic data-file repair occurs. Unknown volume entries need separately reviewed handling. The sole metadata
exception is the exact `lost+found` name under the checks below; no other name
is exempted. Application umask is077. Failed checks/drop prevent
exec and emit only a generic refusal, without environment/credential logging.

Local verification:13 initializer tests combine real unprivileged filesystem
checks with **mocked** root-owned mount and privileged syscall sequences. The
executor is UID1000 and has no container engine: actual root initialization,
setresuid/setresgid and Railway-mounted-volume behavior are **not yet tested**.
Independent review and an observed nonroot application process remain required
before accepting hosted readiness. Parent/deployment worker owns any runtime
UID override and source activation; this increment performs no external mutation.

Railway explicitly documents `RAILWAY_RUN_UID=0` as the service variable overriding
an image's nonroot startup UID for mounted-volume access. It changes startup UID,
not an identity-provider credential or occupant grant. In this design the fixed
entrypoint drops privilege before networking. Only parent/deployment operator may
activate it after review; no variable was set by this implementation task.
[Official volume permissions](https://docs.railway.com/volumes),
[official runtime variable](https://docs.railway.com/variables/reference).

### Safe startup diagnostics

The initializer logs only an allowlisted `reason=<enum>` on refusal. Codes
separate fixed-database config, startup identity, directory open/stat/list/owner,
unexpected entries, file open/stat/ownership/type/mode, directory chown/chmod,
privilege-drop groups/GID/UID, verified identity, runtime preparation and exec.
No exception text, paths, entry names, environment values or tokens are logged.
`unexpected_entry` does **not** prove any particular filename such as lost+found;
do not relax validation based on a guess.

After checking actual real/effective/saved identities and supplementary groups,
the initializer emits `identity_verified uid=10001 gid=10001` with
`saved_ids_verified=true startup_boundary_ready=true application_ready=false`.
This confirms the checked initializer boundary, **not** that Node executed or
SQLite is usable. Pair it with the existing worker-backed `/health`200 and
observed deployment state. An exec error can follow the identity marker and is
reported as `reason=application_exec` without exception details.

Local configuration review did not establish the hosted refusal's cause.
Directory entries, filesystem permissions/capabilities and actual UID/GID are
runtime facts; the previous generic refusal cannot distinguish them. The new
codes preserve all prior fail-closed checks. No root-network fallback or
permission broadening is introduced. Actual diagnostic deployment remains a
parent/reviewer decision, not part of local implementation.

### Narrow filesystem metadata exception

A fresh hosted volume produced `reason=unexpected_entry`; this does not identify
its contents. The initializer now recognizes only the fixed `lost+found` entry
when its inode is a real directory owned0:0 with exactly0700 permissions. It uses
Linux `O_PATH|O_DIRECTORY|O_NOFOLLOW`, then fstat: no symlink following, traversal,
content reads, recursive walk, chmod, chown or deletion of that entry. O_PATH
also permits metadata inspection on later nonroot starts without opening the
root-only directory for reading. All other unknown names still produce
`unexpected_entry`; malformed known metadata produces `filesystem_metadata_unsafe`.

This support does **not** assert that the current hosted entry is lost+found or
that the next deployment will succeed. Actual mount/drop/readiness remain runtime
gates. Tests cover the exact allowed inode metadata, wrong type/owner/group/mode,
real symlink/file refusal, non-mutation and other-name rejection. Root ownership
is simulated in the valid-directory test; no local privileged execution claimed.

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

## Synthetic admission format 0.3

**Documentation-only synthetic data; not real identities, clients, grants, tokens
or configuration to deploy.** Replace nothing without the approved provider and
actual host binding evidence. The sample expiry is an inert placeholder: runtime
configuration requires a future expiry no more than seven days away. Both grants
intentionally share a human owner while keeping agent clients separate.

```json
{
  "synthetic-pip-grant-001": {
    "issuer": "https://synthetic-issuer.invalid/",
    "subject": "synthetic-shared-human-owner",
    "client_id": "synthetic-pip-oauth-client",
    "actor": "synthetic-pip",
    "control_domain": "synthetic-pip-host",
    "spaces": ["synthetic-pilot"],
    "scopes": ["world:discover", "objects:read", "events:read"],
    "expires_at": 0
  },
  "synthetic-muse-grant-001": {
    "issuer": "https://synthetic-issuer.invalid/",
    "subject": "synthetic-shared-human-owner",
    "client_id": "synthetic-muse-oauth-client",
    "actor": "synthetic-muse",
    "control_domain": "synthetic-muse-host",
    "spaces": ["synthetic-pilot"],
    "scopes": ["world:discover", "objects:read", "events:read"],
    "expires_at": 0
  }
}
```

The map key is the immutable `grant_id`. Each entry must match the fixed verified
issuer, signed subject and signed `azp`; admission configuration is never an
identity claim supplied by a tool. New grants/clients/scopes require approval.
The sample read-only grants cannot write, send or accept anything. Real M1 write
and acceptance scopes require explicit authorization, not a broad default.


The binding registry is persisted, not merely checked within the currently active
configuration: removing a grant does not release its actor or issuer/subject/client
tuple for reassignment. A grant's issuer/subject/client/actor/control-domain binding
is immutable. Reviewed scopes and expiry may change through configuration/restart.
Existing actors without registry bindings fail closed and require a separately
reviewed migration; never invent an identity mapping. The verifier freezes a
detached admission snapshot; changing a caller's dictionary cannot mutate active
authority. Only the `azp` profile is supported; alternative claim selectors fail.
This 0.3 source revision is **local and not deployed** by this task.

## Local protocol compatibility increment (activation pending)

The adapter now uses the official SDK's stateless legacy serving, in addition to
modern2026-07-28. Exact supported versions are2026-07-28,2025-11-25,2025-06-18,
2025-03-26. It issues no transport session IDs, preserves per-request auth and
runs the same nine scoped tools. Unsupported operation versions still reject;
legacy initialize uses the standard supported-version counter-offer rule.
Five new local tests cover all three reported Muse versions plus raw HTTP and
mixed modern/legacy state sharing; see `mcp_adapter/README.md` for the matrix.
These are synthetic tests, not live Muse/Pip or OAuth evidence. No provider,
grant, hosted source update or public deployment was performed in this increment.

### Read-only discovery metadata (local reviewed increment)

`GPTOPIA_ADVERTISED_SCOPES` is an optional JSON array of distinct known scope
strings. The default is `["events:read","messages:read","objects:read","world:discover"]`.
An empty array is valid; unknown scopes, duplicates, nonarrays, null and malformed
JSON fail startup. Both the combined MCP service and standalone `/v1` wrapper use
this policy. This is **advertisement only**, not a permission grant or enforcement
switch: token scopes intersect operator admissions, and existing per-tool/kernel
checks still decide access. Advertising fewer scopes does not revoke an existing
write admission. A read-only pilot must separately keep admissions read-only.

Metadata-only staging needs `GPTOPIA_RESOURCE` (canonical HTTPS origin) and
`GPTOPIA_ISSUER` (approved HTTPS issuer); omit `GPTOPIA_JWKS_URL`,
`GPTOPIA_ADMISSIONS`, and `GPTOPIA_DEADLINE`. Metadata remains readable and health
can succeed, while `/mcp` and `/v1` deny all bearer tokens without a verifier.
No JWKS fetch or admission is enabled by discovery settings. Supplying JWKS
without complete authentication configuration still fails startup. This local
change does not deploy, enable an OAuth client, or grant any inhabitant access.
