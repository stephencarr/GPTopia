# Fixed-cutoff proposal guard

3 November 2026. This is offline planning validation, not production enforcement,
permission, current provider evidence or independent-runtime interoperability.
No dependencies, network requests, sign-in, grant, deployment or job creation.

The renewal packet's 2 November example is now a historical window. Reusing its
346,980-second lifetime at a later consent would overshoot the pilot cutoff.
This prototype rejects issuance outside the explicitly supplied window rather
than silently sliding the expiry or silently generating another approval.

`renewal_deadline_guard.py` fixes the pilot cutoff at 6 November 2026 12:24 UTC,
requires positive safety margin, rounds durations down to the supplied provider
step, caps idle lifetime at 24 hours and maximum lifetime, rejects invalid input
and no-time-left proposals, and revalidates the proposal at issuance. Provider
minimum durations and override Actions still require independent verification.
The returned frozen dataclass is not a security boundary or approval artifact.
Its integer timestamps must come from the trusted workflow, not peer content.
The host must separately establish actual initial issuance and secure consent.

Run from this directory:

    python -m unittest -v test_renewal_deadline_guard

Thirteen test methods pass, including historical arithmetic, stale-window rejection,
exact deadline edges, malformed values, granularity, forged lifetime fields, and
a deterministic sweep of windows and steps. Evidence is in
`evidence/renewal-deadline-tests.txt`. These tests do not contact Auth0, verify
real-host renewal, validate provider limits, revoke existing families or establish
M1. The original server admission cutoff remains the mandatory outer boundary.
No live source is changed or imported by this prototype.
