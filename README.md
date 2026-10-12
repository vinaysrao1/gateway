# Harness external access gateway

The first Go implementation includes a bounded capability broker, Linux process isolation, and real Pi end-to-end acceptance tests. Fixed model and fetch routes are supported; unsupported external networking is blocked.

The gateway gives a sandboxed agent harness one controlled channel for external operations. The first version uses Pi as its integration fixture, Linux process isolation, and a small Go broker that owns upstream connections and credentials.

- [Detailed design](docs/design.md): architecture, trust boundaries, alternatives, limitations, and tradeoffs.
- [Coding specification](docs/coding-spec.md): normative contracts, invariants, interfaces, and acceptance tests.
- [Research and implementation plan](docs/research-and-plan.md): primary sources, staged delivery, and release gates.

Implementation was authorized on October 11, 2026. See [implementation status](docs/implementation-status.md) for concrete verification evidence and remaining gates.


Build and verify with Go 1.27.2:

```sh
go test -race -timeout 60s ./...
go vet ./...
./integration/pi/run.sh
```

The Pi suite uses Docker as a Linux test machine and a deterministic HTTPS fixture. It checks actual kernel isolation, hostile tools/extensions, credentials, quotas, cancellation and failure cleanup. [Running the gateway](docs/operations.md) explains enforced execution and deployment prerequisites. `gateway serve` alone is a broker and does not isolate agents.

Local measured results: 7.06 MiB Linux arm64 binary, 26.48 MiB combined idle Go RSS, and 0.21–0.42 ms added p95 local mediation latency. Pi/VM memory and upstream DNS/TLS/remote latency are excluded; [evidence and limits](docs/implementation-status.md) give the exact scope.


For a simple live demo on your Mac, run `./integration/pi/demo.sh`. Real Pi fetches public `https://example.com/` through the gateway, then attempts a direct curl connection to the same service. The model is a local deterministic fixture, so no model API key is required. Results and gateway audit records are saved under `artifacts/demo/`. The gateway needs Internet access for this demo; Pi remains inside the enforced Linux sandbox.
