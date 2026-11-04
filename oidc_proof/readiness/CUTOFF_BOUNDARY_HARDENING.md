# In-flight cutoff hardening, local candidate

4 November 2026. Private, reversible local implementation and deterministic tests.
Not deployed. No real provider, host login, credential, grant, external agent,
background job or paid resource was used or changed.

## Finding

The pre-change local implementation at `c9893eb` checked the pilot deadline on
request entry. The HTTP path also checked after verification, but neither path
carried the pilot deadline into the kernel Principal. The worker lacked a second
check after verification; the HTTP path lacked one after body reading or waiting
for the execution lock. With an admission extending beyond the pilot deadline,
a synthetic request crossing the deadline at those points could create an object.
The kernel checked authority after taking its transaction lock, but not again
before returning a successful retry or committing the operation.

These are reproduced local code findings, not observations of the deployed
service. The last recorded live admission expiries match the pilot cutoff;
that avoids the longer-admission case at initial kernel validation, but does not
establish that an already-running transaction cannot cross it. Current service
configuration was not queried or changed in this review.

## Candidate changes

- `mcp_adapter/worker.py` rechecks the cutoff after verification and passes a
  Principal expiry bounded by the earlier of existing expiry and pilot deadline.
- `production.py` applies the same bound and rechecks after body parsing and
  execution-lock waiting, before starting application work.
- `kernel.py` revalidates authority before the successful commit, including
  idempotent replay. Expiry during execution rolls back world changes and returns
  a denial instead of returning content or a successful mutation receipt.

The generic boundary still enforces its configured deadline, not a hard-coded
November date. The fixed pilot configuration remains 6 November 2026 12:24 UTC.
Nothing in this candidate extends that cutoff or authorizes a configuration change.

## Reproduce

From the `gptopia-oidc` repository root, with the already-installed Python
requirements and no package installation:

    python oidc_proof/readiness/test_cutoff_boundary.py
    python -m unittest discover -v
    python validate_contracts.py

The focused harness uses in-process ASGI, temporary SQLite databases, an injected
clock and synthetic Principals, not real tokens or sockets. It covers exact
before/at/after boundaries, verification/body/execution-queue delays, propagated
expiry bounds, simulated database-lock delay, rollback of create/update/accept,
read non-disclosure and expired retry denial. The queue barrier observes actual
attempted lock acquisition after authentication and body parsing. State checks
compare exact world-table rows as well as counts; bookkeeping is checked separately.

Builder results on the final candidate:

- 14 focused cutoff tests passed.
- 89 existing top-level Python tests passed.
- 50 existing contract validations passed.
- 25 existing MCP/transport tests passed, using the already-installed sibling SDK
  packages via a temporary node_modules link. The link was removed afterward.
- 34 related readiness tests passed: grant bridge 13, bridge characterization 5,
  Muse handoff 3 and renewal planner 13.
- `git diff --check` passed.

Evidence is in `evidence/cutoff-boundary-tests.txt`, `cutoff-base-suite.txt`,
`cutoff-contract-validations.txt`, `cutoff-mcp-suite.txt`,
`cutoff-related-suites.txt` and the independent review file when present.
Previous OAuth provider and consent-metadata suites were not rerun for this
candidate; no changes were made to them.

## Limits and release gate

This is a final **pre-commit** check, not a hard real-time deadline. Time can pass
between the last check, SQLite commit and response delivery. It does not interrupt
a running process, latch a permanent shutdown against wall-clock reversal, remove
a service, revoke tokens or eliminate infrastructure/storage cost. Health and
public resource metadata remain available. The harness simulates database-lock
passage; it is not a real database contention or distributed timing test.

Denied in-flight work can still persist a request-budget increment and denial
audit row. Those are explicitly distinguished from world objects, revisions,
messages, acceptances, retry receipts and mutation usage. An early boundary denial
before execution has no such persistence in the tested paths.

This local candidate is not a live security certification, provider-state check,
renewal proof or independent-runtime interoperability result. Deployment still
requires specific approval and exact-source verification. Preserve the existing
pilot cutoff and separately authorized fixed-expiry action; this code is not a
substitute for stopping the service. Do not retry sign-in or change access on the
basis of these results. M1 and the live renewal prerequisites remain open.
