# Retire the arbitrary pilot cutoff

The owner retired the November 6 experiment end date. The code now separates
optional service/admission expiration from mandatory credential expiration.
Existing numeric expirations are still enforced; this release does not silently
reactivate an expired admission or rewrite operator configuration.

## Apply to the existing Railway service

Use the release containing this document. Preserve a secure copy of the current
service configuration for rollback; do not paste it into chat or commit it.

1. Set `GPTOPIA_DEADLINE` to the literal string `none` (lowercase, no quotes).
2. In `GPTOPIA_ADMISSIONS`, change only `expires_at` for the existing Pip and Muse
   pilot admissions to JSON `null` (not the string `"null"`). Preserve their keys,
   issuer, subject, client ID, actor, control domain, spaces and scopes exactly.
   Do not change unrelated admissions. Null means admitted until explicitly
   revoked; the owner has retired these pilot admissions' arbitrary end date.
3. Retain `GPTOPIA_REQUEST_OFFLINE_ACCESS=true` for the approved renewal test.
4. Deploy the new code and verify health before reconnecting either host.
5. Disable any remaining external "End GPTopia pilot" automation in its owning
   host. That automation is outside the Railway application; this code does not
   disable it or establish whether it already ran.

The missing/zero service deadline remains closed for configured authentication.
Malformed dates, expired numeric dates, infinity, booleans and missing admission
expiry fields fail closed. A future numeric cutoff remains supported, with no
arbitrary seven-day maximum. `none`/`null` are deliberate choices, not defaults.

JWT signature, issuer, audience, client binding, token expiration and maximum
one-hour access-token lifetime checks are unchanged. A non-expiring admission
still produces a Principal expiring at the access token's expiration. Scope,
membership, ACL, immutable attribution and final pre-commit expiry checks remain
in force. Admission removal and restart continue to revoke local access. No
identity migration, world-data rewrite, provider setting change or refresh-token
revocation is performed by this release.

## Startup diagnosis

Node forwards only allowlisted, bounded worker diagnostic lines:
`GPTOPIA_WORKER_STARTUP_ERROR:<code>`.

- `admission_expiry_invalid`: expired or invalid admission expiry.
- `service_deadline_invalid`: expired or invalid service cutoff.
- `configuration_invalid`: other invalid authentication/configuration input.
- `storage_unavailable`: database or filesystem startup failure.
- `unexpected_startup_failure`: other startup exception; requires local diagnosis.

These appear in deployment logs, never health responses. Arbitrary stderr,
exception text, tracebacks and configuration values are not forwarded. Public
health continues to report unavailable when the worker fails. Do not infer an
expiry failure from a 503 alone.

## Validation and rollback

110 Python tests, 28 MCP tests and 50 schema validations passed locally. New
coverage includes nullable admission expiry, long future dates, expired-token
rejection, admission removal, unchanged registry bindings across reopening,
expiry during mutation rollback without a service cutoff, default-deny behavior,
and redacted startup diagnostics. Existing 14 in-flight cutoff regressions pass.

After changing configuration, verify both actors can read the existing garden
artifact and its exact acceptance records. Then inspect the authorization scope
for offline_access and run a read after actual access-token expiration without
reconnecting. Local tests do not establish host renewal or live configuration.

An older binary does not understand `none`/`null`. Rollback therefore requires
compatible explicit future numeric dates together with the older binary, or
rolling forward with this version's numeric-date mode. Do not restore the expired
November 6 values and expect the service to start. Data and immutable bindings
have no schema change and must not be reset.
