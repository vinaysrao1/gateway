# Harness gateway coding specification

Status: accepted implementation contract, October 11, 2026, with reviewed compatibility amendments. MUST, MUST NOT, and SHOULD indicate implementation obligations. Performance targets are not measured results.

## Contract and implementation rules

The system consists of a trusted supervisor and broker, an isolated bridge, and an isolated Pi process tree. Every external network operation caused by the managed run MUST be performed by the broker under a capability in the run policy. Requests denied during route/input/policy admission MUST cause no target DNS query, connection, or upstream request. Address classification necessarily follows approved hostname resolution; a forbidden answer MUST cause no target TCP connection or upstream request. Unsupported protocols MUST fail without fallback.

Implement from this specification, not from examples alone. Every coding task and security-relevant change MUST name its requirement IDs, enforcement mechanism, and verification tests. Change the contract before intentionally changing observable behavior. Tests MUST assert observable effects and forbidden effects, rather than merely reproduce the implementation's branches.

The user authorized implementation against this contract. Passing library tests alone does not prove the Linux boundary; release gates remain mandatory.

## Run state and supervisor contract

The state machine is CREATED → PREPARING → ACTIVE → STOPPING → CLOSED. Preparation failure transitions to STOPPING and CLOSED. CLOSED never becomes ACTIVE. A new run gets a new identity, directory, broker, and policy snapshot.

The trusted supervisor accepts an operator-selected absolute policy path, workspace root, preinstalled Pi runtime, and approved launcher profile. Agent input MUST NOT select these. The supervisor MUST validate the full policy, resource limits, secrets availability, trusted files, workspace mount contents, and platform isolation prerequisites before executing Pi.

During PREPARING, the supervisor creates a private host run directory, starts its broker listener, launches the namespace-local bridge, verifies readiness and namespace isolation, then starts Pi. The externally usable capability channel MUST NOT be active before the isolation check. The sandbox bootstrap process is trusted and limited to readiness checks; it cannot submit agent requests. A handshake enables ACTIVE only after checks pass.

Any preparation error MUST prevent Pi execution. A broker failure during ACTIVE MUST revoke admission and stop the run. Bridge failure MUST terminate Pi and stop the run. A Pi exit MUST stop the bridge and broker. Termination MUST cancel active upstream requests immediately, kill the sandbox process tree within 2 seconds, and remove the host listener after connections close. A forced kill after 2 seconds is allowed and MUST be reported. A process-tree cgroup and PID namespace, rather than only a parent PID, MUST define cleanup membership.

Stale socket connections and stopped run contexts MUST remain invalid. The supervisor MUST NOT silently relaunch a failed run with new credentials or relaxed policy. Termination cannot revoke remote effects already committed.

## Policy format

Use strict UTF-8 JSON, maximum 64 KiB, with schema version 1. All scalar limits are mandatory and may be tightened, but not raised above the reviewed version 1 defaults. Reject unknown keys, duplicate object keys at any depth, unsupported versions, trailing data, invalid values, duplicate IDs/routes, missing required limits, and overlapping local route definitions. Hash the exact validated policy bytes using SHA-256 for audit; preserve those bytes outside the sandbox. No hot reload, includes, environment expansion, executable values, regular expressions, or agent-defined rules.

All strict JSON parsing has a combined limit of 8192 values and object keys per document. Every scalar, container, and object key consumes one item. This bounds allocation amplification from wide schema objects, in addition to the byte and nesting limits.

| Field | Type and contract |
| --- | --- |
| schema_version | Integer, exactly 1 |
| limits | Object containing all run and HTTP limits described below |
| model_routes | Array of zero or one model capability in first release |
| fetch_resources | Finite array of fixed resource capabilities; maximum 64 |
| denied_cidrs | Finite array of operator internal ranges in addition to mandatory special-use exclusions |

A model capability has id, local_path, upstream_url, protocol, allowed_models, credential_ref, max_output_tokens. The request schema is fixed in the protocol implementation rather than supplied by policy. local_path is exactly /v1/chat/completions. protocol is exactly openai-chat-v1, a project identifier for the frozen compatible subset. upstream_url is one exact canonical HTTPS URL without query. allowed_models is a finite nonempty set of literal strings. credential_ref identifies a host-only secret supplied by the trusted supervisor, not a file path visible to Pi. max_output_tokens is an integer from 1 to 8192 by default and applies to every submitted request. The full schema fixture MUST be frozen during the Pi compatibility milestone before model adapter implementation.

A fetch resource has id and url only. id matches [a-z0-9][a-z0-9_-]{0,63}; url is an exact canonical HTTPS URL with no query or fragment. It has no credential, caller headers, body, cookie state, or variable suffix. Configured resources may differ by exact path but not by runtime URL substitution.

Canonical configured URLs MUST use lowercase ASCII DNS labels, no userinfo, trailing dot, wildcard, IP literal, IPv6 zone, control character, backslash, fragment, or query. Use HTTPS port 443 only, represented with no explicit port. Path defaults to / and otherwise uses ASCII unreserved characters and / only; reject percent escapes, dot segments, and repeated slash segments in version 1. This deliberately restricted grammar applies to operator policy, not arbitrary text within model messages. Internationalized domains require preapproved canonical punycode policy entries. No runtime URL input exists in the first release.

## Local transport and protocol

The broker serves HTTP/1.1 over one pathname Unix socket per run. It MUST NOT bind a host TCP listener. No CONNECT, upgrade, WebSocket, descriptor passing, generic RPC execution, or public administration API. The trusted supervisor controls lifecycle through private process control, not a sandbox-visible API.

The bridge listens on namespace-local 127.0.0.1 on a fixed configured port and forwards origin-form HTTP over the mounted Unix socket. It MUST NOT use an Internet dialer, discover upstream URLs, interpret proxy settings, or accept a run ID for routing. It MUST propagate cancellation and MUST respect the same parsing and resource limits. The broker remains authoritative if bridge checks are bypassed.

The bridge and broker accept only the following routes:

| Route | Method and input | Success | Forbidden behavior |
| --- | --- | --- | --- |
| /healthz | GET with no body | 200 and local readiness state, no secrets | No upstream activity; no authority information beyond readiness |
| /v1/chat/completions | POST application/json with frozen compatible subset | Upstream successful status and bounded JSON or SSE bytes | No endpoint discovery, fallback, redirects, request replay, or client auth forwarding |
| /gateway/v1/fetch/{resource_id} | GET with no body or query | Upstream 2xx, bounded response body, approved content type | No URL parameter, query, arbitrary headers, credential, redirect, or cookie persistence |

Model input MUST include model and messages, and stream MUST be boolean if present. Permit only the pinned Pi adapter's explicitly specified fields, including function tool declarations and tool results needed for local agent use. Reject unknown top-level keys, duplicate keys recursively, remote tool descriptors, server-side tools, externally fetched media URLs, and unbounded token requests. Accept ordinary URL text in messages as content; never treat it as a gateway destination. max_tokens or its selected compatible equivalent MUST be normalized to the configured maximum; values above the maximum are rejected, and missing values get that maximum. Do not assume a token limit enforces monetary budget.

The supported schema below was validated against captured Pi 1.1.0 requests. Any required additions are spec changes before adapter implementation. Text-only model input is the first release default. No OAuth, model listing, embedding, image generation, audio, responses protocol, or provider protocol translation.

| Model request field | Proposed accepted subset |
| --- | --- |
| model | Literal string from allowed_models, at most 128 UTF-8 bytes |
| messages | 1 to 1024 messages; roles system, developer, user, assistant, tool; no unknown message keys |
| Message content | UTF-8 string, or 1–64 explicit text blocks per message with exactly type="text" and text=UTF-8 string, or assistant null with tool calls; no media or URL-reference objects; total bytes bounded by request cap. Text blocks are the approved Pi 1.1.0 compatibility amendment. |
| Message keys | role, content, name, tool_calls, tool_call_id only; name at most 64 ASCII letters/digits/underscore/hyphen; role-specific combinations validated |
| tool_calls | Assistant only; at most 64 per message; objects with id, type=function, function={name, arguments}; arguments is a bounded JSON string, never executed by broker |
| tool_call_id | Tool messages only; bounded nonempty string matching a preceding assistant tool call; IDs at most 128 bytes |
| tools | At most 64; type=function only, function fields name, description, parameters, strict; name as above, description at most 4096 bytes, strict boolean |
| parameters | Object with local JSON Schema data, nesting at most 16; reject external $ref/$dynamicRef/$recursiveRef values; local fragment references allowed; broker does not fetch schema resources or validate tool execution |
| stream | Boolean, default false |
| stream_options | Optional object containing include_usage boolean only; legal only with stream=true |
| max_tokens | Integer 1 through route maximum; omitted value filled with route maximum; no second token-limit alias |
| temperature / top_p | Finite numbers in [0,2] / [0,1] respectively |
| tool_choice | auto, none, required, or exact function selection naming one declared tool |
| parallel_tool_calls | Boolean |

All other top-level fields are rejected, including user, metadata, store, remote tools, service-tier controls, response-format extensions, and fallback routing fields. JSON nesting is at most 32 overall. Assistant tool calls require a function declaration with a matching name, IDs must be unique within the submitted conversation, and tool messages require the corresponding call ID. Plain assistant content may be null only when it includes a tool call. Other roles require string content or the bounded explicit text-block array. Model tool calls remain data for Pi; the broker never executes them. Provider-specific reasoning controls and token aliases require an explicit later schema revision if the chosen Pi model needs them. The pinned Pi configuration sets supportsStore=false and maxTokensField=max_tokens to remain within this schema.

The broker MUST generate its own request_id. Client IDs or identity claims MUST NOT change authorization. Reject security-claim headers such as X-Gateway-Run, X-Gateway-Policy, and X-Gateway-Credential. Pi's local dummy Authorization header may be consumed and discarded solely for SDK compatibility. All unlisted client headers are discarded or rejected; none are forwarded by default.

HTTP parsers MUST reject absolute-form targets, queries on all local routes, ambiguous request framing, oversized headers, conflicting Content-Length, any Content-Length with Transfer-Encoding, unsupported transfer encodings, invalid method/path syntax, and non-identity Content-Encoding. Chunked uploads are permitted only if their decoded body stays within the request limit and deadline. A malformed HTTP request may be rejected by the parser before a structured error can be returned.

Construct upstream headers afresh: configured Host, Content-Type, Accept, fixed User-Agent, and route-selected Authorization for model calls only. Never copy client Host, Authorization, Proxy-Authorization, Connection, forwarding headers, cookies, framing headers, or TLS settings. No cookie jar. Accept-Encoding is identity and automatic decompression is disabled. Upstream transport MUST be restricted to HTTP/1.1 in the first release.

For successful responses, forward bounded body bytes unchanged and only explicitly approved response headers: Content-Type and, for SSE, Cache-Control. Upstream auth failures, non-2xx responses, redirects, invalid response framing, compressed responses, or unsupported content types produce sanitized gateway errors; never expose raw upstream error bodies, Set-Cookie, Location, or authentication challenges. For model JSON allow application/json; for streams allow text/event-stream; for fetch allow text/plain, text/html, and application/json with validated optional charset parameters. Fetched content is data and MUST NOT execute in the gateway.

## Error contract

Before response headers are committed, return application/json containing only error.code, a fixed safe error.message, and request_id when assigned. Error details MUST NOT include provider credentials, policy contents, raw DNS answers, arbitrary client body values, response body text, or secret file paths.

| HTTP status | Code | Meaning |
| --- | --- | --- |
| 400 | invalid_request | Unsupported or malformed operation input |
| 403 | capability_denied | Resource/model is outside this run's authority, or destination classification denied it |
| 404 | route_not_found | Local route is not exposed |
| 405 | method_not_allowed | Method is invalid for a known route |
| 413 | request_too_large | Bounded input size exceeded |
| 429 | budget_exceeded | Concurrent or cumulative run limit reached |
| 502 | upstream_failed | DNS, TCP, TLS, auth, unsupported upstream response, or upstream failure |
| 503 | run_unavailable | Run inactive, stopping, or audit sink unavailable |
| 504 | deadline_exceeded | Effective request deadline expired |

After streaming headers have been sent, a failure MUST close the response/connection and record an incomplete result. It MUST NOT append fabricated provider success, fabricate a terminal completion event, silently truncate as a successful response, or retry. The Pi fixture MUST demonstrate that cancellation and truncated streams are surfaced as incomplete/error states. If the pinned SDK cannot do so, the adapter must change before release.

## Outbound connection contract

All production Internet dialing MUST occur in a single outbound transport module. It accepts an internally created AuthorizedOperation value, not an arbitrary URL. Policy evaluation produces this value only after validation and quota reservation. Its fields are immutable, constructors are private to policy admission, and every dial is tied to a live run context.

The resolver MUST receive only the capability's configured hostname. Every A/AAAA answer candidate MUST be normalized, including IPv4-mapped IPv6, and checked. Deny loopback, unspecified, private, link-local, multicast, shared carrier ranges, documentation/test ranges, reserved and special-purpose ranges, IPv6 ULA, transition/translation ranges that could obscure private targets, metadata endpoints, and operator internal ranges. Maintain the range table from pinned IANA registry snapshots and test boundary addresses; do not rely only on IsGlobalUnicast. Empty or mixed allowed/denied results fail. Denial occurs before target TCP connection.

Select one eligible address deterministically, dial that literal address on 443, and use the configured DNS hostname for SNI, Host, and certificate verification. No second resolver invocation from HTTP/TLS connection machinery. A failed dial terminates the operation in version 1; no address fallback or hidden reconnect. No environment proxy, redirect, pooling, TLS validation bypass, cross-route connection reuse, or automatic retry. Each operation has at most one upstream HTTP request attempt. A resolver may perform its normal bounded DNS exchanges; those are broker activity, never a sandbox DNS tunnel.

Credentials MUST be injected only into the exact approved model request after capability and destination validation. They MUST NOT be stored in Pi config/environment/workspace, forwarded to fetch routes, attached to redirects, included in audit/errors, or supplied by the caller. Secure secret loading is host-side; scope keys narrowly and avoid credentials with service-wide write authority. The gateway MUST NOT claim to prevent a malicious approved upstream from echoing the credential within a successful response.

## Limits and streaming

| Limit | Proposed first release value | Required behavior |
| --- | --- | --- |
| Run wall lifetime | 30 minutes | Revoke and cancel when elapsed |
| Concurrent operations | 4 per run | Reject immediately; no waiting queue |
| Cumulative admitted operations | 500 per run | Atomically charge once; do not refund failures |
| Model request body | 2 MiB | Bound before admission; reject oversized input |
| Fetch request body | 0 bytes | Reject nonempty body |
| Header bytes/count | 16 KiB / 64 fields | Reject before operation admission |
| Model response | 32 MiB per operation | Stop before forwarding bytes past the cap |
| Fetch response | 2 MiB per operation | Stop before forwarding bytes past the cap |
| Cumulative outbound request bodies | 64 MiB per run | Charge validated bodies before DNS |
| Cumulative inbound upstream bodies | 128 MiB per run | Reserve chunks atomically before forwarding; count received data up to cap |
| Read request headers/body | 5 / 10 seconds | Abort slow client |
| DNS / connect / TLS | 3 / 5 / 5 seconds | Each bounded by effective overall deadline |
| First response headers | 30 seconds | Abort stalled upstream |
| Overall model / fetch | 180 / 30 seconds | Bound full stream as well as initial response |
| Stream no-progress / stalled client | 30 / 5 seconds | Cancel upstream and release resources |
| Stream copy buffer | At most 32 KiB per direction | No full response accumulation |
| Audit record | 2 KiB | Bound labels and omit bodies |
| Audit file | 8 MiB per run | Revoke admission on exhausted sink |
| Sandbox memory / processes | 1 GiB / 128 tasks | Enforce on full tree with cgroup v2; OOM or supervisor failure ends run |
| Sandbox CPU / descriptors | 2 CPU cores equivalent / 256 FDs per process | cgroup CPU cap and inherited descriptor rlimit |
| Writable workspace / temporary storage | 1 GiB / 256 MiB | Require quota-backed workspace and bounded tmpfs; setup fails if bounds cannot be enforced |

The broker MUST keep run counters concurrency-safe. Cumulative counts never decrement; only in-flight slots release. Do not allocate large buffers until the active/body-size checks pass. Concurrent pre-admission parsing MUST also be bounded: maximum 8 local connections per run, 16 MiB aggregate request buffering, and no unbounded goroutine/connection queue. Bridge limits MUST not multiply this envelope unnoticed.

Client disconnect or explicit cancellation MUST cancel the upstream context promptly and release the in-flight slot exactly once. In deterministic integration tests the upstream sees closure within 1 second. Failed downstream writes are terminal. Overall deadline and run lifetime always override narrower phase timeouts.

These limits constrain transport abuse and resource use. They are not exact billable token limits: the operator should add provider spend ceilings, and retries initiated by Pi count as distinct admitted requests. The gateway itself MUST never replay requests.

## Audit contract

Use a host-only append file per run, permissions 0600. Before DNS or dialing, append a successful admission decision with request ID, run ID, policy digest, capability ID, method, timestamp, and charged budget. A write failure denies admission. This is a diagnostic authorization record, not a power-loss-safe or tamper-proof compliance ledger; no fsync per request is required in version 1.

Every handled operation MUST attempt one terminal event recording outcome, received/sent byte counts, duration, and a fixed reason code. Record denials without client-controlled bodies or URLs. A terminal logging failure MUST revoke subsequent admissions and cancel active work. Process crashes may leave admitted requests with no terminal event; final run summary MUST mark these outcomes unknown when available. Never infer no remote effect from a missing completion event.

Logs MUST NOT contain prompts, tool arguments, response bodies, auth headers, arbitrary URL queries, unbounded labels, or secret values. Parser-level malformed requests may be represented by bounded connection error counters rather than one event per malformed byte sequence.

## Security invariants and executable verification

| ID | Invariant | Enforcement owner | Required executable acceptance case |
| --- | --- | --- | --- |
| NET-001 | Pi and every descendant have no external route or host network deputy | Launcher and supervisor | Real sandbox: Node/curl/TCP/UDP/DNS/IPv6/raw socket attempts fail; host socket and inherited descriptor probes fail; outside packet observer sees no sandbox egress |
| NET-002 | Failure never relaxes network boundary | Supervisor and launcher | Kill broker/bridge during startup and stream; missing bubblewrap/cgroup/seccomp support prevents Pi execution; direct probes still fail |
| AUTH-001 | Authority is fixed by the per-run listener, never a caller claim | Broker and mounts | Spoof identity/policy/credential fields; attempt other run's socket; no cross-run authority |
| AUTH-002 | All untrusted processes in a run share the documented capabilities | Broker | Shell and malicious extension call socket directly; same allow/deny result as Pi |
| POL-001 | Default deny precedes external DNS and TCP | Policy admission | Unknown route/resource/model/field or denied operation results in zero resolver/dial/upstream calls |
| POL-002 | One immutable valid snapshot applies for the whole run | Supervisor and policy parser | Duplicate keys, malformed policy, altered source file, unsupported version fail or leave running snapshot unchanged |
| DST-001 | Only canonical fixed configured destinations can become operations | Policy parser | Userinfo, suffix tricks, ports, escapes, IP literals, Unicode ambiguity and query corpus rejected; no arbitrary runtime destination accepted |
| DST-002 | The authorized resolved address is exactly the address dialed | Outbound transport | Resolver rebinding sequence, mapped IPv6, mixed/private/metadata answers, special-use boundaries, and dial spy prove single checked resolution path; real fixture confirms TLS hostname checking |
| DST-003 | Redirects and replay create no further outbound request | Transport | 301/307 to localhost or another allowed origin produces sanitized failure and no second connection; disconnect after body produces one attempt |
| HTTP-001 | Request authority, authentication and framing are reconstructed | HTTP server and adapter | CL/TE corpus, duplicate auth, forged Host, forwarding/proxy headers and compressed bodies cannot alter observed upstream request |
| SECRET-001 | Gateway does not expose or misroute its secret through its own mechanisms | Supervisor and adapter | Canary scan sandbox env/files, logs, stderr, config and sanitized errors; fetch upstream sees no auth; model sees only its bound credential |
| RES-001 | Input, output, concurrency, lifetime and buffering have finite enforced limits | Broker, bridge and launcher | Slow clients, large chunked bodies, endless SSE, saturated slots, fork/memory abuse, audit cap; bounded peak resources and deterministic rejection |
| STREAM-001 | Successful response bytes preserve protocol; partial failures remain incomplete | Adapter and bridge | SSE checksum/event order, tool calls/results, terminal events, byte cap, stalled consumer and truncated stream are correctly observed by Pi |
| CANCEL-001 | Cancel/revoke closes active upstream work and releases slots once | Context ownership | Client abort, deadline, supervisor stop, concurrent cancellation; upstream closure within 1 second on fixture; race test counters |
| AUDIT-001 | Admission is recorded before egress and failures revoke further admission | Broker audit | Unwritable/full sink denies egress; terminal log failure stops future requests; every normal request correlates with decision/terminal metadata |
| LIFE-001 | Terminated authority cannot be reused and descendants do not survive | Supervisor | Rapid start/stop, stale handle, orphan/grandchild, startup rollback and forced termination tests |

NET-001 requires Linux integration evidence. Mock transport tests cannot prove an OS boundary. DNS spies, destination fixture counters, and outside packet captures must corroborate broker and namespace observations. A denied direct attempt can emit a packet on isolated loopback; the assertion concerns external routing, not the absence of every internal packet.

Production private-address denial MUST remain enabled. Network integration fixtures can run on public routed test addresses or an isolated Linux lab assigning public-address test routes without Internet access. Unit tests inject resolver/dial fixtures. Any internal-IP relaxation belongs to a separately identified test build/configuration that cannot be selected by the production enforced launcher; avoid a general production allow_private flag.

## Pi acceptance scenario

Pin the exact Pi package artifact and runtime. Launch with immutable generated model settings, literal dummy key, fresh home, disabled automatic discovery and network refresh, no persisted session, and only approved explicit extension fixtures. Verify switches against the pin; unknown switches fail setup.

Use a deterministic compatible model fixture to drive real Pi through: model request and SSE completion; a gateway fetch tool invocation and result; a shell/grandchild attempting direct networking; a malicious extension attempting direct DNS/TCP; an explicit provider cancellation; and gateway outage. Require correct Pi observable state, upstream fixture observations, correlated gateway events, and zero bypass packets. A live provider smoke test is optional separately configured evidence; CI correctness must not depend on probabilistic model decisions or paid requests.

## Module boundaries and coding invariants

The repository uses cmd/gateway, internal/supervisor, internal/isolation, internal/policy, internal/protocol, internal/transport, internal/audit, internal/bridge, integration/pi, and tests/security. internal/localhttp implements shared raw framing bounds.

- Only transport may create external clients, use resolver APIs, or dial Internet sockets. Supervisor/isolation may use narrowly enumerated local IPC and process control. Bridge may dial only its fixed Unix socket.
- Adapters select trusted capability IDs and schemas; they cannot instantiate arbitrary outbound requests or read secrets directly.
- Policies are immutable after validation. No package-wide mutable policy, secret, counter, or default outbound HTTP client.
- Every active operation owns a cancellable context and a single cleanup path. Counter changes and audit admission ordering must be reviewable.
- No shell execution in broker, policy parser, or adapters; supervisor launches explicit argv from trusted inputs. Never interpolate agent input into host commands.
- Secret values have no generic formatting/log representation. Error constructors accept fixed codes, not raw upstream/client error text.
- No disabled TLS validation, env proxy inheritance, fallback routes, implicit redirects, background telemetry, dependency auto-update, or uncontrolled retries.
- Dependency pinning, structural import/API checks, fuzz tests, race tests, and real network-isolation tests are required release evidence. Static checks support review; they do not prove absence of all indirect dialing.

## Completion criteria

The first release is complete only when every invariant has a passing mapped test, the pinned real Pi scenario passes, Linux bypass tests run rather than skip, dependency/profile hashes are recorded, cleanup leaves no active process or authority, and measured lightweight budgets are met or explicitly revised in the reviewed spec. A working demo without these properties is a prototype and must be labeled accordingly.

## Reviewed implementation amendments

Pi 1.1.0 requires text-only content arrays; that compatibility amendment is reflected in the model table. Configuration disables store and fixes max_tokens rather than allowing broad provider-specific fields.

The local parser accepts CRLF lines only and one request per connection. This avoids normalizing mixed-line framing into ambiguous HTTP. The bridge validates prohibited input before reverse-proxy normalization.

Encoded request buffering reserves four times (request_bytes + 1024) for each model handler until completion, within request_buffer_bytes. With defaults this deliberately admits only one simultaneous model request; fetches use the remaining operation slots. This reservation bounds encoded copies, not Go object/heap overhead. The JSON item/depth caps bound allocation amplification, and kernel cgroup limits bound the untrusted Pi tree. The trusted broker is outside that cgroup; its heap is bounded structurally by JSON/input/concurrency caps and must be measured separately.

Linux may create default tunnel interfaces in a new network namespace. Only loopback may be up/addressed; any other interface must be down and unaddressed with no external routes. Capabilities and seccomp prevent activating them. This preserves the external-access invariant without incorrectly rejecting Linux kernel defaults.

Successful model SSE must include a nonempty finish_reason and a [DONE] terminal event followed by clean transport completion. The gateway observes events without changing response bytes, bounds each SSE event/line to 64 KiB, and reports clean HTTP EOF without model completion as upstream_incomplete. Supported charset parameters are utf-8 and us-ascii only. Terminal audit records distinguish received upstream bytes from forwarded response bytes; cumulative received budget saturates at its hard cap on an overrun and no over-budget byte is forwarded.

The original final SSE event boundary and a bounded suffix are withheld until clean HTTP body completion. This prevents an SDK that stops at [DONE] from ignoring later framing errors. Success bytes are preserved exactly; terminal timing is deliberately gated. The observer supports LF, CRLF and CR delimiters and only the single choice at index 0 used by the configured model.

Seccomp additionally excludes nonreviewed socket families, x32 syscall ABI and io_uring entry points. Ambient descriptors are sealed close-on-exec before spawn; socket standard streams are rejected, and only trusted bootstrap controls/filter descriptors are reopened and then closed before Pi execution.
