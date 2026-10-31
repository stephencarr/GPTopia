# WorkOS adoption: smallest local compatibility proof

**Status: local-only resource-boundary harness, not a live integration.** Based
on kernel 0.3 `0e631e6`. The pilot, Auth0 verifier, onboarding and 0.4 branches are
unchanged. No account, key, installation, fork, deployment or external grant was
created. Adoption means using the maintained hosted authorization/registration
service, not building or forking an OAuth issuer.

## Two different supported paths

| Path | Host requirement | Signed identity meaning | Local profile |
|---|---|---|---|
| WorkOS Connect MCP OAuth | Native remote MCP OAuth client | `sub` is human; `client_id` is OAuth software client; `sid` is consent | `connect_user` |
| Hosted Agent Registration | Runtime can follow HTTPS registration instructions and securely keep credentials | `sub` is agent registration; `act.sub` is claimed human owner | `agent_registration` |

These claims are documented separately in [Connect token claims](https://workos.com/docs/authkit/connect/token-claims)
and [hosted Agent Registration](https://workos.com/docs/authkit/agent-registration).
A native MCP host is not assumed to execute the registration flow. An HTTPS-capable
runtime is not assumed to have native MCP installation or background execution.

WorkOS [MCP documentation](https://workos.com/docs/authkit/mcp) describes hosted
OAuth discovery, configurable CIMD/DCR and resource audiences. Current Connect
claim documentation says dynamically registered clients receive OIDC scopes by
default; additional permission defaults require support. Therefore registering a
fresh host is not proof it can obtain GPTopia's scopes. No default-grant expansion
or scope remapping is proposed silently.

## What the prototype implements

`workos_compat.py` uses existing PyJWT, pinned RS256, exact configured HTTPS issuer
and audience, required time/organization/scope claims and maximum one-hour token
lifetime. Its configured profile never comes from the request. Connect requires
signed client/consent fields; Agent Registration requires an agent registration
subject and claimed owner, rejecting anonymous/delegation-chain cases under our
policy. This is strict pilot policy, not a claim that every valid provider token
uses only these permitted profiles. No fallback to Auth0 `azp`, environment client
ID audience, machine identity, or untrusted agent name is allowed.

A normalized `WorkOSIdentity` keeps human owner, organization, OAuth client and
agent registration distinct. An explicit local `ApprovedBinding` test policy
binds those values to actor/grant/runtime-control labels and bounded root/scopes.
`authorize` intersects token scopes and policy on each call. A freshly issued
synthetic token with unchanged identity retains the approved actor; changed
identity does not migrate silently. No token/refresh credential is persisted.

A mandatory injected status boundary must return exactly `True` on each call;
revoked, unavailable, malformed or exception results fail closed. The hosted
Agent Registration guide directs immediate pre-expiry revocation checks to its
credential-validation endpoint. We have **not verified that endpoint's response
schema or implemented a network client**. Connect status/introspection integration
also remains to be verified. Synthetic callbacks do not establish provider-side
revocation semantics or operational availability. The eventual callback must
check current credential/registration status and relevant owner permissions;
a hardcoded `True` is a test double only. The returned authorization is a
point-in-time decision, not an atomic kernel transaction revocation guarantee.
This standalone harness also has no production request/rate budgets; integrating
it must retain the existing bounds and recheck authorization at the mutation
boundary.

The result is intentionally **not** the existing kernel `Principal`.
Agent registration is not an OAuth client ID: stuffing it into `client_id` would
mislabel provenance and could incorrectly satisfy acceptance independence checks.
A small explicitly versioned provider-neutral binding/provenance extension is
needed before wiring that profile to kernel requests. Native Connect could map
human/client fields after explicit new issuer/grant approval, but this candidate
does not do so. Never rewrite or reassign existing pilot actors automatically.

## Adopt rather than rebuild

Use WorkOS-hosted auth/claim screens and generated instructions. The open MIT
`workos/auth.md` repository is a reference provider implementation, **not** the
hosted backend; its flow must not be mixed with hosted API fixtures. There is no
reason to fork that sample into a new issuer for this proof. The official WorkOS
SDK is an API client, not a replacement identity service. Costs/licensing are
being evaluated separately; nothing here authorizes an account, credential,
management API privilege or recurring charge.

For the runtime path, hosted registration documents a user claim, then assertion
exchange and later assertion rotation. Our tests only verify behavior when a
replacement access token arrives; they do not implement or prove those exchanges.
Token acquisition belongs to the real supported host/provider flow, not GPTopia.

## Exact live go/no-go gate

Before any live action, approve provider/environment, cost ceiling, owners,
resource audience, limited scopes, storage and migration/promotion plan.
Then test a fresh actual host through the appropriate path:

1. Native MCP: discover metadata, register with supported CIMD/DCR, owner consent,
   and obtain a token with the exact resource and intended permission scopes.
   Runtime HTTPS: follow the hosted environment's generated `auth.md`, complete
   its claim ceremony, exchange its assertion and store credentials securely.
2. Resolve the human/agent distinction using actual verified claims. Grant only
   explicit approved world access; do not infer access from registration alone.
3. Perform discovery as the intended actor. Record unavoidable operator changes;
   per-agent bespoke issuer/config edits fail the one-prompt setup objective.
4. Return using each actual host's independent stored credentials after token
   expiry, demonstrating supported renewal without copied tokens or fresh manual
   configuration. Background operation requires a real host capability and
   authorization; a foreground return is a separate result.
5. Revoke and demonstrate denial before the prior token expires. Verify wrong
   audience/owner/org/scopes, stopped pilot deadline and failure when the status
   service is unavailable. Confirm original identity/history remain intact.

**Unproved:** fresh-host setup, provider scopes, hosted renewal/revocation,
owner-consent UX, independent runtime behavior, price suitability and production
kernel bridge. The local harness cannot answer these by itself. If WorkOS needs
unreasonable per-host exceptions or the actual hosts cannot execute the flow,
report that as failure of the adoption proof rather than adding another custom
credential broker.
