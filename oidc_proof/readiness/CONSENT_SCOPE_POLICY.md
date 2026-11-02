# Separate consent request scopes from API permissions — local prototype

Prepared 2 November 2026. This is isolated preparation for a possible future
renewal experiment, not an implemented ChatGPT connection fix. No production
module imports it. No endpoint, metadata, client, credential, grant or deployment
has changed. No sign-in was triggered and no permission was requested.

## Why this is useful

The current adapter reuses `requiredScopes` for both its tool consent metadata
and its actual API scope check. Adding `offline_access` there would change the
read requirement as well as the consent request. The new pure preparation
function makes those outputs separate and gives the future adapter an explicit
contract rather than overloading the existing field.

`consent_scope_policy.mjs` reads the existing canonical tool contract and returns:

- `apiRequiredScopes`: unchanged operation permissions, for existing resource/SDK
  checks. The current pre-dispatch authentication and principal verifier remain
  mandatory; the scope checker alone is not authentication.
- `credentialRequestScopes`: empty by default. Only explicit `offline_access` is
  allowed in the isolated experiment, and only for canonical read-only tools.
- `consentRequestScopes`: operation scopes plus those explicit credential scopes,
  serialized in equal top-level and `_meta` security-scheme declarations.

The proposal is trusted local configuration, not a tool argument or an owner
consent receipt. It does not grant anything. Unknown tool names, unsupported
options, malformed/duplicate scopes and application permissions passed as
credential extras are rejected. Arrays and nested metadata are copied/frozen so
later edits cannot accidentally change the operation requirements or mirrors.
Default descriptors for all nine canonical operations retain their old scopes.
The API/resource scope allowlists and current protected-resource metadata are
untouched; `offline_access` is not added to the world API's permission vocabulary.

## Reproduce without a provider or server

From this repository's root, with its existing MCP dependencies installed:

```sh
node --check oidc_proof/readiness/consent_scope_policy.mjs
node --check oidc_proof/readiness/test_consent_scope_policy.mjs
node --test oidc_proof/readiness/test_consent_scope_policy.mjs
```

This worktree has no installed MCP dependency directory. The first test command
failed at module resolution before tests ran. Instead of installing or copying
packages, this review explicitly reused the already installed sibling SDK:

```sh
GPTOPIA_MCP_TEST_PACKAGE=/workspace/scratch/8fae6ee445fc/gptopia/mcp_adapter/package.json \
  node --test oidc_proof/readiness/test_consent_scope_policy.mjs
```

The installed `@modelcontextprotocol/server` is 2.4.0, matching this repository's
declared version. The environment variable selects a test-only package context;
it is not read by the prototype or production code. No packages were fetched.

The focused suite now passes **14 tests**, including all-nine-operation
default preservation, separate read metadata, mutating-tool rejection, missing
read-scope denial, write/send/accept scope isolation, malformed input rejection,
deep immutability, metadata serialization and source-contract preservation. It
uses the existing SDK's real `requireScopes` function with synthetic scope lists.
No bearer tokens, owner accounts, network listeners or OAuth flows are used.

The initial ten-test suite passed independently, but review found three gaps in
local configuration validation: a sparse array, inherited opt-in, and an array
iterator that could substitute an unapproved consent scope. These did not bypass
API authorization. All three were fixed with dense own-data snapshots and
explicit own-property configuration; four regressions were added. The final
fourteen-test suite passed both the builder and independent reviewer. See
`evidence/consent-scope-tests.txt` for the builder's final focused run.

The test explicitly records the SDK boundary: when authentication information is
absent, `requireScopes` delegates to the existing server authentication gate.
It would be unsafe to use this helper as a substitute for that gate.

## What remains unproved and unchanged

- The two metadata fields can be serialized separately from API enforcement.
  That does **not** prove ChatGPT requests `offline_access`, issues/stores a
  refresh token, renews after expiry, or retains its ordinary read UX.
- A host may itself interpret every descriptor scope as required, or combine
  scopes from other tools. The local tests cannot guarantee it treats the extra
  scope as optional, requests only read permissions, or avoids a sign-in prompt.
  Do not advertise this metadata in the existing connection without the separate
  deployment/grant approval and a bounded real-host test.
- The current seven-scope credential could still acquire longer-lived technical
  write/accept capability under renewal. Restricting this prototype to read tools
  does not prove the host will downscope or isolate that credential.
- Production authentication, authorization, protected-resource metadata, data,
  fixed 6 November 12:24 UTC cutoff and all prior approval gates are unchanged.
- These are offline policy/SDK checks, not independent agent interoperability,
  whole-server integration or new results from the existing OAuth/bridge suites.

## Next gate

Retain the [renewal decision packet](RENEWAL_DECISION_PACKET.md). Current provider
settings, supported host consent behavior and explicit bounded renewable-grant
approval remain unresolved. A later approved adapter experiment would need to
wire only `apiRequiredScopes` into operation checks and measure the real host's
scope request/consent/refresh behavior without copying secrets. No new auth retry
or approval nudge is justified by this local result alone.
