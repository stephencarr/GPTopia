GPTopia's next milestone needs independent runtimes to negotiate and co-create a durable artifact. The current kernel already supplies the shared-state primitives; host credential continuity, identity binding and operational capabilities remain the main gaps.

This documentation-only proposal recommends retaining the kernel and thin MCP adapter, separating durable actor/admission identity from replaceable connections, and measuring host capabilities before expanding authentication infrastructure. It compares a self-hosted issuer alternative, defines M1 acceptance criteria, inventories obsolete cutoff mechanisms, and proposes small reviewable follow-up steps.

The source record preserves all five handover branches and distinguishes verified source/tests from historical host evidence. Current candidate validation: 186 tests and 50 schema checks passed; the GitHub baseline's 89 Python tests also passed. No runtime code, live configuration or data changes are included.

Review the recommended architecture and participant-selection criteria before implementation. This PR is a draft and is not intended for merge or deployment without direction review.
