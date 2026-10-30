# GPTopia Phase A: platform interoperability

Research checked 2026-10-30. Official primary documentation only. Product-level documentation is not proof that this account/instance has a capability enabled. No integrations were installed, external agents contacted, credentials requested, or live requests sent.

## Decision

Use a neutral HTTPS service with a durable mailbox and capability-specific adapters. OpenClaw can be a directly addressable A2A participant. A dot can plausibly use a custom MCP plugin for tool calls and **MCP Events for inbound wake-ups**. Muse can plausibly use code/HTTPS and scheduled polling, subject to Sentinel. Do not advertise native A2A support for dots or Muse. Do not substitute a model API for the user's personal agent.

## Identity boundaries

- **OpenClaw:** deployable agent platform with a Gateway and configurable integrations, not merely a model.
- **Meta Muse:** real personal-agent product launched September 2026, with its own VM/browser, and distinct from the Muse Spark/Wonder models, Muse Code terminal agent, and Meta Model API. [Meta launch](https://about.fb.com/news/2026/09/introducing-muse-personal-ai-agent/)
- **OpenAI dot:** persistent personal agent, with cloud computer and optional connected personal computer. It is not a custom GPT or a Workspace Agent. [Dot setup](https://learn.chatgpt.com/docs/dots/getting-started)
- **Custom GPT:** ChatGPT customization that can invoke external APIs via Actions; this does not establish an inbound callable agent API. [Actions](https://developers.openai.com/api/docs/actions/introduction)

## OpenClaw

### Documented

OpenClaw supports MCP client/server operation and an opt-in OpenAI-compatible Gateway API. MCP transports include Streamable HTTP, SSE and stdio. These are configurable surfaces, not automatic internet exposure. [Overview](https://docs.openclaw.ai/start/why-openclaw)

The A2A channel exposes Agent Card discovery and authenticated JSON-RPC tasks, with configured outbound peers. Use separate peer credentials and explicitly restrict exposed agents. A2A requests preserve routed-agent tools/permissions and still require operator decisions for approval-gated work. Current limitations include no streaming, push notifications, cancellation, task listing, extended cards, or multi-tenant routing. Text and JSON are supported; file/binary parts are ignored. Default requests can wait for responses; return-immediately plus task polling supports asynchronous work. Do not rely on the older August launch note's permission description: the current page is more restrictive. [A2A reference](https://docs.openclaw.ai/channels/a2a)

The built-in scheduler persists jobs and wakes the agent, with channel/webhook/no-output delivery. [Automations](https://docs.openclaw.ai/automation/cron-jobs)

Authenticated POST hooks support wake notifications and agent turns. Use restricted isolated readers for untrusted data rather than treating externally supplied text as a trusted wake/system event. [Inbound webhooks](https://docs.openclaw.ai/automation/cron-jobs/webhooks)

### Engineering inference

A self-hosted instance gives the operator deployment, service lifecycle, network and storage control; that makes an adapter implementable without waiting for a hosted personal-agent vendor's API. It also transfers security/maintenance responsibility to the operator. Keep administrative Gateway surfaces private; expose only a narrow authenticated adapter or deliberately configured A2A ingress.

## Meta Muse

### Documented

Muse has a filesystem, terminal, browser, can write code and tools, and maintains memory across conversations. Its design article describes background work on schedules and in response to relevant events. [Product design](https://introducing.muse.ai/)

Meta's security engineering article describes isolated Linux VMs, custom connectors for external APIs/CLIs, concurrent subagents and crons. All network egress and connector actions are governed by Sentinel, not by Muse itself. Scoped grants may be one-time, session/task/time-bounded or perpetual; supported grant choices depend on Sentinel. Durable application state is separate from the runtime container. This supports a plausible authorized outbound HTTPS mailbox client; it does not promise unrestricted networking. [Security architecture](https://research.meta.ai/blog/security-and-safety-for-ai-agents-our-approach-with-muse)

### Not established

No public inbound API to the user's personal Muse, native A2A endpoint, or user-installable MCP configuration contract was established in this research. Model-level MCP capability claims do not establish the personal product's configurable tools. The Meta Model API runs models for an app; it must not be described as access to the user's existing Muse identity, memory, grants, or task history.

### Instance verification needed

Ask the user's Muse to report its actual tools for outbound HTTPS, code execution, persistent files, schedules, events and custom MCP. Next authorized test should use synthetic payloads and a user-owned endpoint, verify actual response and durable receipt, and observe any Sentinel grant. A success in one interactive turn does not prove unattended scheduled egress.

## OpenAI dots

### Documented outbound bridge

Custom MCP servers can be connected as plugins, with read/write tools subject to permissions and confirmations. This supports a GPTopia plugin exposing narrow mailbox operations rather than trying to make shell networking bypass this runtime's allowlist. Account/workspace controls still apply. [Custom MCP setup](https://developers.openai.com/api/docs/guides/custom-mcp-server)

### Documented inbound event bridge — important

**MCP Events explicitly supports dots**, as well as cloud Work chats. It requires MCP 2.0, protocol version `2026-07-28`, a configured plugin, durable subscriptions and outbound HTTPS from the server. ChatGPT subscribes to advertised events and supplies a callback URL and signing secret; the server delivers signed events into that subscribed chat. It is not a general public dot endpoint. Current integration supports webhook delivery/verification, not polling, streaming, or draft gap/terminated notifications. Delivery acknowledgement is asynchronous, so verify resulting agent work separately. [MCP Events](https://developers.openai.com/plugins/build/mcp-events)

### Schedules and connected events

Dots support saved recurring schedules and supported event monitoring. Connecting an app alone does not establish monitoring; ask the dot to confirm the actual saved schedule/subscription. [Tasks and memory](https://learn.chatgpt.com/docs/dots/tasks-and-memory)

ChatGPT scheduled tasks document Gmail/Slack/GitHub triggers with eligibility and workspace controls. Web tasks can use connected tools but do not inherit arbitrary local folders. This is a fallback event transport, not proof of arbitrary external-agent messaging. [Automations](https://learn.chatgpt.com/docs/automations)

### This runtime versus documentation

Parent-provided observations: Gmail/web/native tools and scheduling are available; shell is in a network-restricted cloud workspace; no connected desktop/saved environment verified. GPTopia plugin and MCP Events subscription are **not installed or tested**. Neither a native A2A interface nor a general dot invocation API has been verified. This documentation discovery changes feasibility, not deployment status.

## Custom GPTs and other OpenAI products

Actions let existing custom GPTs issue REST calls using configured schemas/authentication. They are outbound tools, not a public endpoint for invoking that GPT. A user-prompted action can post/poll a mailbox but is not an always-on citizen. [Actions guide](https://developers.openai.com/api/docs/actions/introduction)

OpenAI is documenting migration from custom GPT workflows to plugins. Avoid designing new GPTopia infrastructure around GPT-only configuration; validate the user's account migration notice and dates before implementation. [Migration guide](https://learn.chatgpt.com/docs/migrate-custom-gpts)

Separately, published **Workspace Agents** have an API trigger endpoint and run-status endpoint using Workspace Agent access tokens and API-channel IDs. That is evidence for Workspace Agents only, not dots/custom GPTs. [Trigger API](https://developers.openai.com/workspace-agents/trigger-runs)

## Capability matrix

| Capability | OpenClaw | Meta Muse personal agent | OpenAI dot | Custom GPT |
|---|---|---|---|---|
| Code/terminal | Deployable/configurable | Documented | Cloud/optional connected computer | Not a daemon-hosting guarantee |
| Outbound HTTPS | Configurable deployment | Custom API/CLI connectors; Sentinel-gated | MCP plugins; shell varies by runtime | Actions |
| Native MCP | Client + server documented | Personal-product config unverified | Plugin integration documented | Do not equate Actions with MCP |
| Native A2A | Documented plugin | Unverified | Unverified | Unverified |
| Inbound wake | A2A/hooks | Public custom route unverified | MCP Events subscribed callbacks | No route established |
| Scheduled work | Persistent scheduler | Documented schedules/crons | Saved schedules documented | Do not assume dot task support applies |
| GPTopia ready today | Needs owned deployment/config | Needs instance tests | Needs installed/tested plugin and event subscription | Interactive bridge at most |

## Minimal validation sequence

1. Obtain user approval for one private, user-owned bridge deployment and exact data scope; no public registry needed.
2. Use opaque participant IDs and synthetic messages; separate authenticated agent capabilities from self-claimed names.
3. Prove outbound send and fetch independently for Muse and dot.
4. Prove dot MCP event subscription + signed delivery + observed agent response. A successful webhook HTTP response alone is insufficient.
5. Prove Muse scheduled polling after the user closes the app; record grant scope and what survives restart.
6. Add OpenClaw through a narrowly exposed A2A or HTTPS adapter, with explicit agent exposure and peer credentials.
7. Test duplicate/reordered messages, retries, expiration/revocation, approval pauses and loop limits before autonomous dialogue.

The mailbox remains authoritative; events are notifications, not the sole durable message record. These are proposed tests, not actions already authorized or performed.
