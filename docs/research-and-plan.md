# Agent gateway research and implementation plan

Status: proposed plan for review, October 11, 2026.

## Literature synthesis

Three research agents independently examined existing gateway literature, Pi integration, and security invariants. The resulting architectural recommendation is a harness-owned semantic broker with an independent OS network boundary. Existing gateways offer useful routing and authorization patterns, but those features alone do not prevent arbitrary agent code from creating an unrelated connection.

The table separates source claims from the decisions inferred for this project. These are primary project documents and foundational security sources, not a claim of a comprehensive systematic literature review. Moving main-branch documentation must be replaced by pinned references during implementation.

| Primary source | Relevant evidence | Application to this gateway |
| --- | --- | --- |
| [Saltzer and Schroeder, The Protection of Information in Computer Systems](https://web.mit.edu/Saltzer/www/publications/protection/) | Foundational principles include complete mediation, least privilege, fail-safe defaults, and small mechanisms | Derive mandatory mediation, default deny, scoped credentials and a small trusted surface |
| [Anthropic Sandbox Runtime](https://github.com/anthropics/sandbox-runtime) | Native OS isolation plus proxy filtering; Linux and macOS implementations; research-preview status | Reuse mature isolation mechanisms; verify a pinned restrictive profile rather than infer safety from a package name |
| [Anthropic sandbox engineering](https://www.anthropic.com/engineering/claude-code-sandboxing) | Separates filesystem/network confinement and describes credential-holding constrained service access | Put credentials and semantic operations outside untrusted execution |
| [GitHub Agentic Workflow Firewall architecture](https://github.github.com/gh-aw-firewall/reference/security-architecture/) | Network domain filtering has limits for repository identity and approved-destination exfiltration | Do not equate hostname allowlisting with action authorization |
| [Agentgateway](https://github.com/agentgateway/agentgateway) | General agent proxy covering LLM, MCP and A2A connectivity with routing and policy functionality | Consider reuse when broad protocols or fleet operation matter; our inference is that the initial local scope can be smaller |
| [Microsoft MCP Gateway](https://github.com/microsoft/mcp-gateway) | Kubernetes-oriented MCP reverse proxy, authorization and server lifecycle; current README describes independent request routing | A fleet reference, with deployment machinery beyond this local MVP |
| [MCP security best practices](https://modelcontextprotocol.io/docs/draft/tutorials/security/security_best_practices) | Confused-deputy, token passthrough, SSRF and redirect concerns | Future MCP adapters must separate client identity from upstream credentials and mediate their discovery traffic; first release excludes MCP |
| [OWASP SSRF prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) | Destination allowlists, address validation and application/network defenses | Fixed routes and connection-time validated IP dialing; avoid unrestricted URL intake |
| [Bubblewrap security model](https://github.com/containers/bubblewrap) | Low-level unprivileged isolation tool; selected arguments define the protection | Reuse the launcher with an explicit reviewed profile and negative tests |
| [Pi security](https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/security.md) | Runtime restrictions belong to the environment | Isolate the whole process tree |
| [Pi model configuration](https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/models.md) | Compatible endpoint configuration through baseUrl | Use existing provider protocol support through local bridge |
| [Pi CLI](https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/cli.md) | Automated modes and configuration-discovery controls | Pin and minimize fixture configuration; exercise real Pi deterministically |
| [GitHub Spec Kit contract guidance](https://github.github.com/spec-kit/guides/contract-driven-development.html) | Define observable obligations at component boundaries before implementing both sides | Freeze policy/protocol contracts and link requirements to acceptance evidence |
| [Microsoft Research Spec Sharp](https://www.microsoft.com/en-us/research/project/spec/) | Preconditions, postconditions and object invariants are explicit program contracts | Express invariants as enforceable properties rather than descriptive prose alone |

Recent research can supplement the project references. [Scalable LLM Agent Tool Access in the Cloud](https://arxiv.org/abs/2607.15593) examines consolidating tool access and protocols in gateways. [MCP Server Architecture Patterns for LLM-Integrated Applications](https://arxiv.org/abs/2606.30317) discusses gateway and proxy patterns. These recent preprints are architectural context; neither establishes that an application gateway enforces arbitrary process egress. Their findings are not security release evidence for this project.

## Proposed engineering choices

| Decision | Benefit | Cost or alternative |
| --- | --- | --- |
| Linux first | Clear namespace boundary; existing launcher | Mac requires Linux VM; native support is separate work |
| Go, standard-library-oriented | Single deployable gateway binary; mature HTTP/TLS and concurrency | GC and binary size; Rust is viable but increases initial implementation/dependency choices |
| One broker per run | Simple identity, quotas, revocation and transport separation | Higher aggregate process memory than shared service |
| Unix socket plus local bridge | No host TCP listener; normal Pi HTTP provider compatibility | Additional local process/channel to test |
| Exact capability routes | Small parser/authorization surface; credential binding | Less flexible than arbitrary URL access |
| Model protocol passthrough | Preserve existing SDK streaming; avoid protocol conversion | Must freeze and test a specific supported request subset |
| No retries, redirects or pooling | Inspectable one-operation connection behavior | More DNS/TLS overhead; lower compatibility with transient failures |
| Diagnostic bounded audit | Local review without external telemetry or database | Does not provide tamper-proof or power-loss-durable compliance evidence |
| Reuse bubblewrap | Avoid new privileged namespace machinery | Profile, dependencies, kernel features and packaging need review |

These are recommendations, not measurements. Evaluate reuse again if the compatibility milestone shows that a small adapter becomes a large provider implementation. The project's value is the enforced contract and small operation set; avoid reimplementing a broad existing gateway without a reason.

## Spec driven workflow

Keep design, normative spec, invariant/test mapping, and delivery plan versioned together. For each change: state the requirement; define accepted inputs and permitted/forbidden effects; add failing contract/security tests; implement within module boundaries; collect evidence; update traceability. An implementation convenience must not silently become policy.

Distinguish assumptions from verified properties. Examples include supported kernel features, trust in configured upstreams, exact provider semantics, and resource measurement conditions. Security tests run in the actual isolation environment. A skipped sandbox suite is an incomplete gate, not a passing build.

Review changes to destinations, credentials, mount access, transport APIs, retries, streaming success semantics, limits, and dependencies as contract changes. No new capability becomes available merely because a provider SDK or extension supports it.

## Delivery stages

The stages below begin after design review. Each is a concrete checkpoint, not a promise of a fixed calendar estimate before the compatibility and isolation spikes.

### Stage 0 Freeze inputs and contracts

Deliver a pinned Pi release/commit and artifact checksum, supported Node runtime, pinned Go toolchain and bubblewrap, Linux/kernel/profile requirements, IANA range snapshot, exact provider route, one fetch resource, and reference benchmark machine. Freeze the Pi request schema using a local protocol fixture. Replace source main-branch links with commit references where relevant.

Gate: the spec has no unresolved field grammar or safety-critical platform behavior. Review defaults, permissions, and intentional incompatibilities. Produce fixtures and design updates before implementing gateway logic.

### Stage 1 Prove isolation before upstream features

Implement the supervisor lifecycle, reviewed launcher, per-run mounts/socket, bridge readiness, cgroup limits, and cleanup. Use a local deny-only broker fixture. Build test artifacts outside the agent runtime.

Gate: NET-001, NET-002, AUTH-001, LIFE-001, and relevant resource tests pass on Linux. Confirm direct IPv4/IPv6, DNS, subprocess, host-socket, descriptor, namespace-entry and gateway-death attempts cannot bypass. Observe packets outside the namespace. If prerequisites are unavailable, startup fails; do not introduce a weaker silent mode.

### Stage 2 Implement bounded capability admission

Implement strict policy parsing, immutable snapshot/digest, local protocol parser, request schemas, atomic budgets, sanitized errors, and audit admission ordering. Test without Internet access.

Gate: POL-001, POL-002, DST-001, HTTP-001, AUDIT-001, AUTH-002 and admission/resource tests pass. All denied operations show zero target DNS/dial effects. Fuzz policy, paths, JSON and framing; race-test admission and stop paths.

### Stage 3 Add one controlled HTTPS transport

Implement validated DNS answers, literal IP dialing with configured TLS hostname, fresh per-operation connections, scoped credentials, bounded response streaming, deadlines and cancellation. Add fixed resource fetch and model route against deterministic upstream fixtures.

Gate: DST-002, DST-003, SECRET-001, STREAM-001, CANCEL-001 and transport limits pass. Explicitly test private/mixed answers, metadata, wrong certificates, redirects, compressed responses, dropped connections, upstream error redaction, stalled consumer and secret canaries. Confirm one upstream attempt per operation.

### Stage 4 Integrate real Pi

Generate immutable model settings and optional minimal fetch extension. Run the pinned Pi CLI in its sandbox with a deterministic model fixture that emits tool calls. Exercise model streaming, fetch, file work, shell bypass, hostile extension, cancellation, compaction if enabled, outage and cleanup.

Gate: real Pi's observed protocol state and fixture events agree with broker records. No background network path escapes. Preserve tool call/result events, finish reasons and failure semantics. If compatibility needs a new field or route, revise the spec and tests before allowing it.

### Stage 5 Measure and release

Run the complete suite on the supported Linux release profile with no skipped isolation tests. Record exact artifact/profile hashes, resource measurements, fuzz/race results, packet evidence, and all invariant test IDs. Document supported capability examples, operational setup, failure diagnosis, cleanup, and limitations.

Gate: all coding-spec completion criteria hold. An optional live provider smoke test confirms provider compatibility when configured; deterministic CI remains the correctness evidence.

## Lightweight acceptance measurements

| Property | Proposed target | Measurement contract |
| --- | --- | --- |
| Gateway binary | At most 20 MiB | Release build, architecture/toolchain recorded; exclude Pi and bubblewrap, report them separately |
| Idle incremental memory | At most 64 MiB per run | Supervisor, broker and bridge combined RSS after 30 seconds idle; report Pi/VM separately |
| Mediation overhead | At most 10 ms p95 | At least 1000 fixed small requests at concurrency 1 and 4 to local warmed fixture; compare direct fixture vs mediated path; exclude DNS/TLS and also report complete request latency |
| First streamed byte | At most 10 ms added p95 on local fixture | Provider emits scheduled first event; compare equivalent direct and mediated tests |
| Cancellation | Upstream closure within 1 second | Deterministic abort fixture, repeated under concurrency 4 |
| Resource boundedness | Stable under configured limits | Saturation, maximum input, endless output, slow client and run quota tests; record peak combined memory and descriptors |
| External bypass | Zero successful connections or externally routed sandbox packets | Real Linux adversarial tests plus outside observation; broker traffic separately attributed |

Fresh upstream connections make real remote DNS/TLS overhead significant; the benchmark must not hide that in the local mediation figure. Report total latency, not just the favorable microbenchmark. If a target fails, profile and simplify or explicitly revise it without weakening security requirements.

## Subsequent capability expansion

After the first release, evaluate dynamic HTTPS fetch with a strict host/path/query grammar, connection pools that preserve route isolation, additional provider protocols, and narrowly typed Git/MCP operations. Git push, API mutations and remote MCP tools need resource/action authorization and idempotency contracts. A gateway route to a remote tool server does not automatically cover network operations performed by that remote server; those require a separate trusted downstream boundary.

Shared multi-run service, native macOS enforcement, durable audit, OAuth, browser networking, generic tunnels and provider cost accounting are independent design changes. Add them only with clear user needs and corresponding invariants. Maintain the core guarantee: no newly supported feature grants a path around the harness-owned external access boundary.
