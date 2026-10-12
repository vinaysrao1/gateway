# Gateway implementation evidence

The Go implementation is being delivered in reviewed milestones. This file distinguishes passing library tests from real Linux/Pi evidence. A gateway library without process isolation cannot enforce all harness networking.

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

## Remaining release evidence

The Linux/Pi milestone must provide namespace/route checks, hostile shell/extension probes, outside packet observation, model streaming and approved fetch, cancellation, gateway outage, cross-run isolation, secret scanning, and complete cleanup. Benchmark targets and maximal resource-limit tests must also be measured rather than inferred. Until this evidence is recorded below, the repository is a tested implementation in progress rather than a completed secure release.
