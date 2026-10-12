# Running the gateway

The enforced launcher supports Linux arm64 and amd64. It requires bubblewrap, cgroup v2 CPU/memory/pids controllers with writable delegation, and mount privileges. The initial launcher runs under a trusted administrator; the agent receives no capabilities. Unsupported platforms or unavailable controls fail before Pi executes. Docker Desktop supplies a Linux test machine on macOS.

## Build and verify

The module requires patched Go 1.27.2. Go's toolchain selection downloads it if the installed launcher is older. The Go gateway has no third-party module dependencies.

```sh
go build -trimpath -ldflags='-s -w' -o bin/gateway ./cmd/gateway
go test -race -timeout 60s ./...
go vet ./...
./integration/pi/run.sh
```

The end-to-end runner needs Docker. Its privileged outer container supplies Linux kernel facilities for the test; it has no Internet network. Pi itself runs inside the actual bubblewrap boundary. The runner uses pinned Pi 1.1.0 and a deterministic HTTPS model fixture with a generated trusted CA; it does not consume a paid model or real credential. Missing isolation facilities fail the suite rather than skip it.

For repeatable measurement, run:

```sh
GATEWAY_MEASURE=1 go test ./internal/broker -run TestLocalMediationMeasurement -count=1 -v
GATEWAY_MEASURE=1 ./integration/pi/run.sh
```

Local mediation measurements exclude DNS/TLS/upstream latency and compare direct fixture access with the real loopback bridge and Unix broker path. The model first-byte measurement uses the bounded streamed protocol. Idle memory measures both Go processes after 30 seconds, excluding Pi and the surrounding VM.

## Enforced execution

Prepare an immutable runtime root using the layout in integration/pi/Dockerfile: the gateway binary, Node/Pi, required shell/loaders/libraries, empty proc/dev/run/workspace/tmp mount points, and generated pi-config/models.json and settings.json. Model settings point to http://127.0.0.1:8787/v1 with a literal dummy client key. No provider secret belongs in that runtime or its workspace.

Adapt examples/policy.json to exact approved HTTPS destinations, model IDs and output limits. A separate private 0600 JSON secret file maps credential references to actual service keys. Launch with an explicit trusted command:

```sh
sudo bin/gateway run \
  --policy /opt/gateway/policy.json \
  --secrets /opt/gateway/secrets.json \
  --audit /var/log/gateway/run-001.jsonl \
  --runtime-root /opt/gateway/runtime \
  --workspace /opt/gateway/workspace \
  --cgroup-root /sys/fs/cgroup \
  -- /usr/local/bin/node /opt/pi/node_modules/@earendil-works/pi-coding-agent/dist/cli.js \
  --offline --provider gateway --model gateway-fixture --thinking off \
  --no-session --no-extensions --no-mcp --no-skills --no-prompt-templates --no-context-files
```

Use a delegated cgroup parent appropriate for the deployment. Audit paths and their adjacent .policy.json snapshots must be fresh; both are host-only. --ca can add an operator-approved CA for a configured upstream and never disables certificate verification. The first version supports one chat completion route and exact fetch resource IDs only.

The `serve` command runs a local broker for trusted integration and diagnostics; it does not isolate arbitrary agents. The `bridge` command is compatibility plumbing and must be inside the managed namespace. `run` is the enforced execution entry point.

## Workspace and lifecycle behavior

The launcher copies ordinary files into a physically bounded tmpfs workspace. Symlinks, sockets, devices and other special files are rejected. On successful exit it exports ordinary files through rooted path operations after all descendants are terminated. Export currently copies files and changes but does not propagate deletions. Failed or cancelled runs do not export their partial workspace.

Graceful exit revokes requests, kills descendants, removes the socket, and removes mounts/control groups. A SIGKILL of the supervisor removes active network authority and kills the sandbox through parent-death/PID-namespace controls, but cannot execute Go cleanup. It can leave inert host tmpfs/cgroup metadata. A trusted administrator must reclaim that metadata before repeated crash workloads; do not delete a populated control group or mounts belonging to another live run. The acceptance lab isolates and reclaims its own stale metadata.

Permissions belong to the whole run. Shell commands and extensions can call the same fixed capabilities as Pi; tool names do not grant additional trust. Approved destinations can receive data readable by the run. This gateway controls channels and credentials, while mounted data and upstream trust remain operator choices.
