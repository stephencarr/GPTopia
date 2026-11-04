# Verification and continuation

## Verified in this session, 4 November 2026

- Existing checkout was clean at `89910e7e90ce5fb303dd5ff3b5e089f5b97b4c5f`.
  A read-only `git ls-remote origin` returned that same GitHub main/HEAD and no
  other advertised branches. No repository AGENTS.md was found.
- Every archive payload checksum passed. `git bundle verify` confirmed complete
  history without prerequisites. All five branches were imported into the
  existing repository under new `archive/pip-*` names; no original ref was replaced.
- Candidate is `9d3df61159f37f0eb134f49d6032b4c0e9279893`; 27 reachable commits and
  344 reachable objects match the manifest. `git fsck --full` passed.
- Bundled baseline `0e631e6a410a8918919eef66579f943adc3fde4a` and current GitHub
  baseline have identical tree `fb0c9c35b09533860f65f8029e118e15491b97e4`.
  This establishes source equality, not current deployed-service state.
- Candidate versus GitHub baseline changes 46 files, including exactly three
  production Python files (`kernel.py`, `production.py`, `mcp_adapter/worker.py`).
  Other changes are documentation, ignore rules and isolated proof/evidence work.
- The bundle's broad secret-audit report is historical evidence. A fresh focused
  scan of reachable blobs/commit messages found no stored private-key bodies,
  GitHub-token patterns or SQLite database headers. This is not an exhaustive
  guarantee against every credential format. No dependencies/databases are staged.

The original ZIP SHA256 was computed locally; it is not an out-of-band signature.
Exact hashes and branch mapping are in `source-record.json`. The immutable ZIP,
extracted payload and candidate source export are retained under
`/workspace/attachments` and `/workspace/handover` locally. They are not committed.
The candidate export is for local tests and has no deployment remote.

## Current local test results

Python 3.12.14, Node 24.22.1. Python uses `/workspace/gptopia-venv` from onboarding
with pinned production dependencies plus jsonschema 4.26.0 and httpx2 2.16.0.
Candidate MCP tests reuse installed dependencies matching its unchanged lockfile;
OIDC dependencies were installed with `npm ci --ignore-scripts --no-audit --no-fund`.
Tests use synthetic identities, local services and temporary storage.

| Target | Command from candidate root unless stated | Result |
|---|---|---|
| Candidate base suite | `(umask 022; python -m unittest -v)` | 89 passed |
| Contract schemas | `python validate_contracts.py` | 50 validations passed |
| Bridge incompatibility characterization | `python oidc_proof/readiness/test_bridge_contract.py` | 5 passed |
| Isolated grant bridge | `python oidc_proof/readiness/test_grant_bridge.py` | 13 passed |
| In-flight expiry boundaries | `python oidc_proof/readiness/test_cutoff_boundary.py` | 14 passed |
| Recorded handoff checks | `python oidc_proof/readiness/test_demo_handoff.py` | 3 passed |
| Offline renewal guard | `python oidc_proof/readiness/test_renewal_deadline_guard.py` | 13 passed |
| Consent scope policy | `node --test oidc_proof/readiness/test_consent_scope_policy.mjs` | 14 passed |
| MCP transport and faults | `cd mcp_adapter && npm test` | 25 passed |
| OIDC provider/storage proof | `cd oidc_proof && npm test` | 10 passed |
| GitHub baseline Python suite | `(umask 022; python -m unittest -v)` in original checkout | 89 passed |

Candidate total: **186 tests plus 50 schema validations**, no failed or skipped
tests reported. Baseline 89 is a separate run, not added to the candidate count.
Logs and machine-readable candidate command outcomes are retained locally in
`/workspace/handover/current-tests/`. Bundled `verification/fresh-tests` and
`test-evidence/recorded` predate this session and are not these results.
The handoff checks validate recorded expectations, not current host behavior.
Kernel 0.4 and other branch-specific suites were not run; branches are preserved
for reference and are not proposed for implementation. No live host or container
deployment test was performed. `git diff --check` passed for this documentation.

## Historical evidence and unresolved facts

| Claim | Evidence level and remaining gap |
|---|---|
| Muse contributed; Pip independently read and accepted | Reported in candidate `oidc_proof/readiness/MUSE_POC_HANDOFF.md` and `RENEWAL_DECISION_PACKET.md`; not reverified against live state |
| Pip's last recorded error was `oauth_refresh_token_missing` | Historical host observation; not proof of today's provider configuration or a guaranteed fix |
| Production does not request `offline_access` through the isolated helper | Source inspection: helper is outside production and not wired into it |
| Provider can renew synthetic tokens | Current OIDC tests pass; real Pip/Muse issuance, secure storage and renewal remain unverified |
| Durable actor reconnect | Current bridge tests are in-memory/local; production storage, owner approval, recovery and migration remain unbuilt |
| Independent scheduling and credential isolation | Host capabilities unresolved; foreground invocation/refresh cannot establish background wake-up |
| Current deployed commit and shutdown automation | Handover records baseline and cutoff, but live deployment state, external schedules and current admission configuration are unverified |
| Repository privacy and deployment triggers | Private is the user's required policy; current API-level verification is blocked. No visibility changes made |

## Publication blocker and safe continuation

No remote branches have been pushed and no draft PR has been opened.
`gh api repos/stephencarr/GPTopia` returned Forbidden. A direct HTTPS request
confirmed the configured proxy rejects CONNECT to `api.github.com` with HTTP403.
A `GH_TOKEN` variable is present; its value was not inspected. Do not request or
replace a token merely because the network route is denied. Git HTTPS read access
works independently and does not prove GitHub API permissions.

There are no tracked `.github` workflows in the current baseline or candidate.
`railway.toml` configures Docker build, health and restart behavior; it does not
specify the platform's selected source branch, auto-deploy or PR-environment
settings. Their absence from source does not establish pushes are deployment-free.

To finish publication:

1. Permit `api.github.com` through the environment network settings, preserving
   existing domains. Retry repository metadata/API access with existing injected
   authentication; request additional access only if that operation still fails.
   No environment configuration or publication was changed during this task.
2. Inspect current repository hooks/integrations and Railway source branch,
   auto-deploy, preview/PR-environment and scheduled stop settings through an
   authorized read-only route. Obtain explicit approval first if pushing or
   opening a PR would deploy. Do not alter those settings to avoid the gate.
3. Confirm the target remains private, re-read remote refs and compare main with
   the recorded baseline. Preserve remote changes; resolve any naming collision
   with a fresh archive name rather than forcing an existing ref.
4. Publish the five archive refs with their exact recorded commit IDs and the
   documentation branch only when triggers are known safe. Never force-push.
5. Open a draft PR from `docs/architecture-reset` to `main` using
   `PR_BODY.md`. Do not merge. Do not initiate live auth, deploy, spending, external
   agent contact or changes to live stop mechanisms without the required approval.

The archive branches and proposal are local and reviewable even while publication
is blocked. A future developer should use the existing checkout; no new worktree
or replacement repository is necessary. Read this record before attempting a
live test, and keep the original handover evidence immutable.
