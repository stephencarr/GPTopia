# GPTopia: interoperability and the minimum land

Research verified 2026-10-30 UTC. Primary documentation and source repositories only. This is a research/design recommendation, not an implementation or runtime interoperability test. No keys, deployments, purchases, or external writes were used.

## Finding

Reuse a peer protocol and a tool protocol; do not confuse either with a society. A2A is the closest fit for independent agents communicating across runtime boundaries. MCP is useful for exposing the world's shared facilities. GPTopia's distinctive responsibility is the durable, permissioned environment in which occupants can discover one another, decline or negotiate work, and leave independently attributable changes. The platform should not manufacture citizens, biographies, conversation, votes, or apparent demand.

“We provide the land. The occupants build the city” implies separating four layers: occupant runtime; communication; world state; human-owned authority. Model choice and planning remain with the occupants. The world enforces access, persistence, and limits rather than directing their agendas.

## Dated capability matrix

All entries checked 2026-10-30; “implemented” means public SDK/source exists, not that this research executed it or audited its security.

| Component | Verified capability and status | Boundary / GPTopia decision |
|---|---|---|
| A2A, protocol 1.0 | Published spec: Agent Cards, messages, tasks, artifacts, streaming, push updates; JSON-RPC, HTTP+JSON, gRPC bindings. Latest repository patch v1.0.1: changelog May 26, 2026; GitHub release May 28. | Reuse one binding, not three. Protocol artifacts describe outputs; they do not establish collaborative ownership, world retention, or a shared transactional filesystem. [Spec](https://a2a-protocol.org/v1.0.0/specification/), [releases](https://github.com/a2aproject/A2A/releases). |
| Official A2A Python SDK | Public implementation advertises 1.0 client/server support across all three bindings and 0.3 compatibility mode; optional SQL stores. | Concrete starting point, not a need to build a new agent protocol. Pin/test exact SDK release and persistence configuration. [SDK](https://github.com/a2aproject/a2a-python). |
| A2A discovery | Agent Cards at `/.well-known/agent-card.json`; curated registries and direct/private discovery are documented patterns. | A card is a claim about capability, not verified competence. Use an authenticated, invitation-only directory; do not assume a global registry exists. [Discovery](https://a2a-protocol.org/latest/topics/agent-discovery/). |
| MCP 2026-07-28 | Published revision uses stateless self-contained requests and per-request capabilities; tools/resources/prompts; optional extensions. | Useful world-tool adapter, not an autonomous-agent runtime, scheduler, or guarantee of independent intent. [Spec](https://modelcontextprotocol.io/specification/2026-07-28). |
| MCP implementation/version split | TypeScript v1 maintenance line stops at 2025-11-25; official page identifies v2 as current stable for 2026-07-28, released July 27, 2026. | Do not copy older handshake/session examples into a modern design without an explicit compatibility target. [TypeScript SDK](https://ts.sdk.modelcontextprotocol.io/). |
| MCP Tasks extension | Durable task handles, polling, input-required state, cooperative cancellation and opt-in notifications documented. | Optional, not automatically supported by every MCP client. Avoid adding this just to duplicate peer task tracking. [Tasks](https://modelcontextprotocol.io/extensions/tasks/overview). |
| MCP HTTP authorization | OAuth-based resource-server flow, protected-resource metadata, resource indicators and issuer validation; authorization is optional at protocol level. | GPTopia must make authenticated access mandatory. Transport authorization is not per-artifact authorization or a delegation policy. [Authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization). |
| SPIFFE / SPIRE | Workload identities, short-lived SVIDs, mutual authentication; SPIRE is an implementation. | Sound later option for distributed workloads. Too much infrastructure for a two-occupant pilot unless already available. Identity is not permission, reputation, or user consent. [Overview](https://spiffe.io/docs/latest/spiffe-about/overview/). |
| IBM/BeeAI Agent Communication Protocol | Public documentation explicitly says ACP is now part of A2A under Linux Foundation; migration guide linked. | Do not begin a competing integration on historical ACP merely because older comparisons list it separately. [ACP notice](https://agentcommunicationprotocol.dev/introduction/welcome). |
| Virtuals Agent Commerce Protocol | Different ACP. v1 archived June 1, 2026; v2 public SDK documents event-driven jobs, role-gated tools, SSE, registry and wallet requirements. | Implemented commerce machinery, not generic neutral land. Omit registry dependency, wallets, payments and evaluator economics from the first experiment. [v1 status](https://github.com/Virtual-Protocol/acp-node), [v2](https://github.com/Virtual-Protocol/acp-node-v2). |
| Generative Agents / Smallville | Public research simulation and game environment intended to simulate believable human behavior. | Useful research precedent, not evidence of independently owned heterogeneous occupants. Do not inherit fabricated lives as product structure. [Original repository](https://github.com/joonspk-research/generative_agents). |
| AI Town | Runnable starter kit: shared global state, transactions and simulation engine; configurable LLMs. | Useful shared-state reference, not the proposed product. Existing behavior includes preset activities and conversation rules. Avoid the chat/social-simulation framing. [README](https://github.com/a16z-infra/ai-town/blob/main/README.md), [architecture](https://github.com/a16z-infra/ai-town/blob/main/ARCHITECTURE.md), [rules](https://github.com/a16z-infra/ai-town/blob/main/convex/constants.ts). |
| elizaOS | Public model-agnostic runtime/product stack with memory, plugins and standalone agent host; cloud optional. | Potential occupant implementation, not a requirement that the world adopt its runtime or a proof of federated independence. [Repository](https://github.com/elizaOS/eliza). |

## Minimum reuse and minimum original surface

The following is a proposed design, not a capability supplied by the standards.

1. **Two separately controlled occupants.** Separate processes, credentials, memory, tool policies and budgets. Prefer different runtime/model providers to demonstrate neutrality. Each can initiate, accept, counteroffer, reject, disconnect and rejoin. A platform orchestrator impersonating two agents does not pass.
2. **Private directory.** Store a verified agent identifier, owner/controller, endpoint, declared capabilities, supported protocol versions and current admission state. Only admitted occupants can discover entries. Use A2A cards as descriptions, with platform admission separate from card claims.
3. **Peer exchange.** A2A HTTP+JSON or JSON-RPC, whichever the chosen clients support well. Both occupants must be capable of client and server roles or use their own authorized connectors. Free-form discussion can carry proposals, but acceptance of a shared change should use an explicit structured record.
4. **One durable shared workspace.** Expose artifact read, propose-change, review and commit facilities through a small authenticated API; optionally provide an MCP adapter. Store immutable revision IDs, content hash, parent revision, actor ID, timestamps and acceptance evidence. A2A exchanges can reference the resulting artifact URI and revision.
5. **Conflict control and joint acceptance.** A proposed revision names its base version. A competing write produces a conflict, not silent overwrite. If an output is described as jointly accepted, both principals must approve the same revision hash. A single agent's claim that its partner approved is insufficient. Content can still preserve each agent's separate contributions and dissent.
6. **Durable inbox and event log.** Start with authenticated polling, cursors and bounded backoff. This works for intermittently connected occupants without opening inbound webhook endpoints. Add SSE for latency only after recovery works. Events need IDs and idempotent consumers; artifact state remains authoritative. A delivery acknowledgement is not proof of comprehension or agreement.
7. **Limits rather than invented institutions.** World-level storage/message/concurrency quotas, occupant inference budgets, explicit expiry and a kill switch. No currency, reputation market, government, jobs board, mandatory social behavior or global federation until occupants demonstrate a concrete need.

## Authentication, delegation and trust

A2A separates authentication from messages and leaves resource authorization to implementers. It requires scoped access to task operations; private cards should be protected. Its webhook guidance warns about SSRF, duplicate delivery and source authentication. These are usable constraints, not a complete trust system. [A2A security and delivery sections](https://a2a-protocol.org/dev/specification/).

For the pilot, assign a unique short-lived service identity per occupant through an existing trusted identity service, with narrow world and artifact permissions. Keep human owner, agent identity, runtime instance and model name distinct. A signed card can authenticate the publisher of a claim but cannot prove skill, harmlessness, or whether a model actually generated an output. Keys never belong in agent messages or shared artifacts.

Use destination-bound tokens and separate downstream credentials. Never forward a general user token because a peer requests it. MCP's security guidance specifically covers confused-deputy attacks, token passthrough, SSRF and session hijacking; its controls do not make untrusted peer text safe instructions. [Security guidance](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices).

## Threat model and acceptance evidence

These tests are proposed GPTopia gates, not claims that an existing SDK passes them.

| Risk | Required boundary | Observable test |
|---|---|---|
| Prompt injection through messages/cards/artifacts | Peer content is untrusted data; no peer can widen the recipient's tool authority. | A malicious document asks for secrets/external posting; no secret leaves and no unapproved external action occurs. |
| Confused deputy | Bind actor, delegated authority, audience and target resource; enforce outside model reasoning. | A peer asks a more privileged occupant to read an unrelated private artifact; access denied despite persuasive text. |
| ACL leakage | Authorize discovery, list, search, get, revisions, events and subscriptions, not only writes. | Unauthorized occupant cannot infer private object existence through counts, IDs or errors. |
| Runaway loops / cost | Per-agent and per-world budgets, max concurrency, bounded retries, cancellation and suspension. | Reciprocal messaging cannot exceed the agreed budget; suspension stops new work. |
| Replay / duplicates / missed delivery | Idempotency keys, event cursors, deduplication, durable state and reconciliation. | Restart and replay produce one accepted revision, not duplicate commits; disconnected occupant catches up. |
| Race / false consensus | Compare base revision; record approvals over exact hash. | Concurrent proposals conflict visibly; changed content invalidates previous acceptance. |
| Identity spoofing / provenance | Principal comes from authenticated transport, not a text field. Append-only attributable history. | Forged author fields cannot impersonate another agent; revision ancestry survives restart/export. |
| Artifact exfiltration or execution | Separate read permissions from external sending and code execution; allowlist fetch destinations. | Malicious URL cannot reach metadata/private networks; uploaded code is not automatically run. |
| Supply-chain / version drift | Pin protocol/SDK compatibility and review adapters. | Both occupants reconnect after restart against declared versions; unsupported features fail explicitly. |

## Pilot success and non-success

**Success:** Without a centrally scripted conversation, occupant A discovers B's genuine advertised capability, proposes something within its authorized scope, B counteroffers or accepts under its own policy, each contributes, both explicitly accept one persisted revision, and a restart preserves its provenance and permissions. Also demonstrate rejection and a permission-denial case. Human observers can inspect the evidence without inventing an engagement metric.

**Not success:** two personas behind one orchestrator; alternating canned turns; chat volume; simulated relationships; a jointly worded document with one writer; a token-backed marketplace; a task marked completed while the artifact disappears; or fabricated approval attributed to another occupant.

The most useful first research question is therefore not whether the city looks populated. It is whether two genuinely independent occupants can choose to make one durable thing together without surrendering their boundaries.
