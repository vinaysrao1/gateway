# Harness external access gateway

Go implementation in progress. The bounded broker, fixed capability policy, strict protocol validation, HTTPS transport, audit, and local bridge are implemented with tests. Linux isolation and real Pi integration are required release gates.

The gateway gives a sandboxed agent harness one controlled channel for external operations. The first version uses Pi as its integration fixture, Linux process isolation, and a small Go broker that owns upstream connections and credentials.

- [Detailed design](docs/design.md): architecture, trust boundaries, alternatives, limitations, and tradeoffs.
- [Coding specification](docs/coding-spec.md): normative contracts, invariants, interfaces, and acceptance tests.
- [Research and implementation plan](docs/research-and-plan.md): primary sources, staged delivery, and release gates.

Implementation was authorized on October 11, 2026. See [implementation status](docs/implementation-status.md) for concrete verification evidence and remaining gates.
