# Gateway implementation evidence

The first Go implementation passed library/race checks and real Linux/Pi acceptance on the recorded profile. This file distinguishes observable evidence from broader guarantees. The broker alone cannot enforce all networking; managed runs require the Linux launcher.

## Core milestone

Implemented fixed immutable capability policy, strict bounded JSON/protocol parsing, private authorized operation values, admission/audit ordering, one checked-IP TLS connection per operation, bounded streaming, cancellation, per-run quotas, local HTTP framing validation, and a Unix-socket bridge. No third-party Go dependency is required.

Core verification: `go test -race ./internal/...` and `go vet ./...`. Security-relevant regression tests include:

| Invariant | Evidence in repository |
| --- | --- |
| POL-001 | broker TestDenyHasNoUpstreamEffect; transport TestInvalidOperationsNoDNS |
| POL-002 | policy TestSnapshotImmutability, TestInvalidPolicies, TestStrictJSON |
| AUTH-001 and AUTH-002 | broker TestAuditBeforeUpstreamAndHeadersRebuilt; Linux cross-run/process tests additionally required |
| DST-001 | policy TestCanonicalDestinations, TestOperationAuthorityAndImmutability |
| DST-002 | transport TestPinnedTLSAndReconstructedRequest, TestAddressCorpus, TestDeniedResolutionNeverDials, TestTLSHostnameAndUntrustedRootFail |
| DST-003 | transport TestDialFailureHasNoAddressFallback, TestRedirectAndCompressedResponsesFailWithoutReplay |
| HTTP-001 | localhttp TestRejectAmbiguousOrMixedLineFraming; bridge TestBridgeRejectsBeforeNormalization |
| SECRET-001 | broker TestFetchNoCredentialAndRedirectSanitized; transport credential reconstruction tests; Linux canary scan additionally required |
| RES-001 | broker TestConcurrencyAndCancellation, TestResponseCapAbortsRatherThanSucceeds, TestParsingReservationIsBounded; localhttp TestBoundConnections |
| STREAM-001 | transport TestStreamBytesAndTruncation; real Pi incomplete-stream behavior additionally required |
| CANCEL-001 | broker TestConcurrencyAndCancellation; transport TestCancellationAndIdleCloseUpstream |
| AUDIT-001 | audit TestFailureLatches, TestBoundedConcurrentRecords; broker TestAuditBeforeUpstreamAndHeadersRebuilt, TestAuditFailureAndRevocation, TestUntrustedAuditLabelsCannotExhaustSink |
| NET-001, NET-002, LIFE-001 | Actual Linux isolation, failure and process cleanup tests required; mock tests do not establish these |

Policy and model request fuzz targets exercise parsers with malformed/random input. Both parsers reject duplicate/case-aliased keys, excess depth, and excess JSON values before full decode. Short fuzz runs passed during development; their duration is not a proof of parser correctness.

## Critical reviews and root cause fixes

The independent reviewers found malformed requests being normalized by the bridge before authorization, mixed-line HTTP framing accepted by the raw guard, arbitrary destination fields in internal operation values, unbounded method labels in audit, incorrect phase-timeout status, an unused buffering budget, and missing supervisor resource limits. The implementation now validates before normalization, requires CRLF per header line, obtains private operations from validated policy, normalizes audit verbs, maps phase deadlines to 504, reserves encoded-buffer capacity, and supplies validated run limits.

Additional review tightened duplicate content encoding checks, streaming downstream write deadlines, immutable secret-safe operation formatting, and bounded JSON item counts. Linux review found user namespace host ownership mismatches, unsafe intermediate export path resolution, and unbounded startup waits; the launcher/supervisor fixes are tested separately in the Linux milestone.

An initial read-deadline hypothesis was withdrawn after inspection of Go's HTTP server showed it clears the background read deadline. Explicit clearing remains for clarity; it is not counted as a confirmed root-cause bug.

## Linux and real Pi acceptance


Final acceptance was independently rerun by the parent agent using Go 1.27.2 and Linux arm64 (LinuxKit 6.12.54). The suite passes actual Pi 1.1.0 model streaming and approved fetch; malicious extension, native curl, shell and grandchild direct-access probes; IPv4/IPv6/DNS/UDP denial; pathname/abstract host deputies; ambient and socket-standard-stream descriptor denial; raw sockets, AF_VSOCK, io_uring, namespace and mount probes; preparation failures; workspace/tmpfs, process and memory quotas; idle lifetime; detached descendants; bridge/supervisor crashes and stale socket revocation.

An outside packet observer counted 11 HTTPS connections matching 11 broker requests, with zero direct/DNS/UDP bypass packets. Normal and truncated request audit records are correlated with fixture observations. Pi reports incomplete streams as errors, including success markers followed by invalid Content-Length or incomplete chunk framing with LF/CR event delimiters. Upstream cancellation measured 77 ms in the final parent run.

[The source and artifact manifest](evidence/linux-arm64-manifest.json) records the exact Go version, release binary SHA-256, kernel, profile source, tests and pinned Pi dependency lock. The runner regenerates a local manifest under artifacts/acceptance on every run. Audit files retain an adjacent host-only byte-exact .policy.json snapshot.

| Measurement | Final local result | Scope |
| --- | --- | --- |
| Linux arm64 release binary | 7,405,728 bytes, 7.06 MiB | Go 1.27.2, stripped, no third-party Go modules |
| Combined idle Go RSS | 27,120 KiB, 26.48 MiB | 30 seconds idle; supervisor/broker plus bootstrap/bridge; Pi/VM excluded |
| Added p95 local latency at concurrency 1 | 0.211 ms | 1,200 samples; direct 0.071 ms, mediated 0.282 ms |
| Added p95 local latency at concurrency 4 | 0.412 ms | 1,200 samples; direct 0.223 ms, mediated 0.635 ms |
| Added p95 first model stream byte | 0.286 ms | 1,200 samples at concurrency 1; direct 0.054 ms, mediated 0.340 ms |
| Cancellation seen upstream | 77 ms | Actual pinned Pi RPC, real HTTPS fixture |

Latency measurements use real TCP/Unix local mediation and an in-memory upstream, excluding upstream DNS/TLS/remote latency. Full HTTPS/Pi tests establish transport compatibility but do not constitute a live-provider Internet latency benchmark. Run-to-run measurements vary; these are results on this workstation, not universal hardware promises. Default encoded-buffer admission permits one model call at a time, with other slots available for fetches.

## Final review fixes and supported limits

Real adversarial testing found an ambient inherited FD99 could escape the network namespace boundary. The launcher now seals all inherited descriptors close-on-exec, reopens only trusted bootstrap/filter descriptors, and rejects socket standard streams. Seccomp denies nonreviewed socket families, x32 ABI and io_uring entry points so alternate socket mechanisms cannot evade the reviewed filter.

Pinned SDK inspection established that [DONE] can end processing before later HTTP framing failures are noticed. The gateway now withholds the completing terminal chunk and a bounded suffix until clean HTTP completion, preserving success bytes. Its bounded observer handles LF, CRLF and CR and the supported single response choice. Regression tests and real Pi framing-failure cases cover this root cause. Independent reviewers reported no remaining blocking issues after these fixes; test success is not a formal proof of kernel confinement.

Supported scope remains Linux arm64/amd64 with trusted privileged preparation, fixed HTTPS capabilities, and one compatible model protocol. The initial evidence here covers arm64; GitHub CI exercises amd64. Approved services may receive readable data, and the host/kernel/upstreams remain trusted. SIGKILL can leave inert metadata requiring trusted reclamation; successful workspace export copies ordinary files and changes without propagating deletions. These limits are documented in [operations](operations.md).
