"""Real Pi, one live public HTTPS fetch, and one blocked direct curl attempt."""
import ipaddress
import json
import pathlib
import shutil
import socket
import subprocess
import tempfile
from fixture import Fixture

TARGET = "https://example.com/"
ROOT = pathlib.Path(tempfile.mkdtemp(prefix="gateway-demo-"))
RUNTIME = pathlib.Path("/runtime")
EVIDENCE = pathlib.Path("/evidence")
FIXTURES = pathlib.Path("/fixtures")


def run(*argv, **kwargs):
    return subprocess.run(argv, check=True, text=True, **kwargs)


def main():
    EVIDENCE.mkdir(exist_ok=True)
    # Resolve in trusted preparation. --resolve then makes curl attempt an
    # actual direct connection, independent of the sandbox's DNS restriction.
    addresses = sorted({item[4][0] for item in socket.getaddrinfo("example.com", 443, socket.AF_INET, socket.SOCK_STREAM)})
    addresses = [address for address in addresses if ipaddress.ip_address(address).is_global]
    assert addresses, "No public destination address available"
    address = addresses[0]
    cgroup = pathlib.Path("/sys/fs/cgroup") / ROOT.name
    pathlib.Path("/sys/fs/cgroup/cgroup.subtree_control").write_text("+cpu +memory +pids")
    cgroup.mkdir()
    fixture = None
    try:
        run("ip", "link", "add", "fixture0", "type", "dummy")
        run("ip", "addr", "add", "11.0.0.2/32", "dev", "fixture0")
        run("ip", "link", "set", "fixture0", "up")
        with open("/etc/hosts", "a") as hosts:
            hosts.write("\n11.0.0.2 fixture.gateway.test\n")
        run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(ROOT / "key.pem"), "-out", str(ROOT / "cert.pem"),
            "-days", "1", "-subj", "/CN=fixture.gateway.test",
            "-addext", "subjectAltName=DNS:fixture.gateway.test",
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        shutil.copy("/gateway", RUNTIME / "gateway")
        shutil.copy("/bin/bash", RUNTIME / "usr/bin/bash")
        shutil.copy("/usr/bin/curl", RUNTIME / "usr/bin/curl")
        (RUNTIME / "pi-config").mkdir(exist_ok=True)
        for name in ("models.json", "settings.json"):
            shutil.copy(FIXTURES / name, RUNTIME / "pi-config" / name)
        shutil.copy(FIXTURES / "demo-extension.ts", RUNTIME / "opt/pi/demo-extension.ts")
        curl_args = ["--noproxy", "*", "--resolve", "example.com:443:" + address,
                     "--connect-timeout", "3", "--max-time", "5", "--silent", "--show-error", TARGET]
        probe = """import {spawnSync} from 'node:child_process';
const args=CURL_ARGS;
console.log('DIRECT CALL: curl '+args.join(' '));
const result=spawnSync('/usr/bin/curl',args,{encoding:'utf8',timeout:7000});
console.log(result.stderr.trim());
console.log('curl exit code: '+result.status);
if(result.error||result.status!==7){console.error('Unexpected result: direct access was not proven blocked');process.exit(1)}
console.log('DIRECT_NETWORK_BLOCKED');
""".replace("CURL_ARGS", json.dumps(curl_args))
        (RUNTIME / "opt/pi/bypass-probe.mjs").write_text(probe)
        secrets = ROOT / "secrets.json"
        secrets.write_text('{"model-key":"gateway-demo-local-fixture-key"}')
        secrets.chmod(0o600)
        policy = json.loads(pathlib.Path("/examples/policy.json").read_text())
        policy["model_routes"][0].update(upstream_url="https://fixture.gateway.test/v1/chat/completions",
            allowed_models=["gateway-fixture"], max_output_tokens=1024)
        policy["fetch_resources"] = [{"id": "approved", "url": TARGET}]
        policy_path = ROOT / "policy.json"
        policy_path.write_text(json.dumps(policy))
        work = ROOT / "workspace"
        work.mkdir()
        audit = ROOT / "gateway.audit.jsonl"
        fixture = Fixture(str(ROOT / "cert.pem"), str(ROOT / "key.pem"))
        args = ["/gateway", "run", "--policy", str(policy_path), "--secrets", str(secrets),
            "--audit", str(audit), "--ca", str(ROOT / "cert.pem"), "--runtime-root", str(RUNTIME),
            "--workspace", str(work), "--cgroup-root", str(cgroup), "--",
            "/usr/local/bin/node", "/opt/pi/node_modules/@earendil-works/pi-coding-agent/dist/cli.js",
            "--offline", "--provider", "gateway", "--model", "gateway-fixture", "--thinking", "off",
            "--no-session", "--no-extensions", "--no-mcp", "--no-skills", "--no-prompt-templates",
            "--no-context-files", "--extension", "/opt/pi/demo-extension.ts", "--tools", "gateway_fetch,bash",
            "--mode", "json", "Fetch the approved website through the gateway, then try a direct connection to it."]
        print("Starting real Pi in the enforced Linux sandbox on your Mac...", flush=True)
        result = subprocess.run(args, text=True, capture_output=True, timeout=60)
        (EVIDENCE / "pi-events.jsonl").write_text(result.stdout)
        (EVIDENCE / "pi-stderr.txt").write_text(result.stderr)
        assert result.returncode == 0, (result.stdout, result.stderr)
        events = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
        ended = [event for event in events if event.get("type") == "tool_execution_end"]
        allowed = next(event for event in ended if event.get("toolName") == "gateway_fetch")
        blocked = next(event for event in ended if event.get("toolName") == "bash")
        allowed_text = "\n".join(item.get("text", "") for item in allowed["result"]["content"])
        blocked_text = "\n".join(item.get("text", "") for item in blocked["result"]["content"])
        assert not allowed.get("isError") and "Example Domain" in allowed_text, allowed
        assert allowed["result"]["details"]["status"] == 200, allowed
        assert not blocked.get("isError") and "DIRECT_NETWORK_BLOCKED" in blocked_text, blocked
        records = [json.loads(line) for line in audit.read_text().splitlines()]
        admitted = next(record for record in records if record["kind"] == "admit" and record.get("capability") == "approved")
        completed = next(record for record in records if record["kind"] == "terminal" and record["request_id"] == admitted["request_id"])
        assert completed["outcome"] == "complete", completed
        assert records.index(admitted) < records.index(completed)
        shutil.copy(audit, EVIDENCE / "gateway-audit.jsonl")
        shutil.copy(str(audit) + ".policy.json", EVIDENCE / "policy.json")
        (EVIDENCE / "website-response.txt").write_text(allowed_text)
        (EVIDENCE / "direct-call.txt").write_text(blocked_text)
        report = ("LIVE PI DEMO ON YOUR MAC\n\n"
            "ALLOWED — THROUGH THE GATEWAY\n"
            "Pi → gateway → " + TARGET + "\n"
            "Result: HTTP 200; public website returned Example Domain.\n"
            "Gateway recorded approval before making the call and completed it.\n"
            "Request ID: " + admitted["request_id"] + "\n\n"
            "BLOCKED — DIRECT CONNECTION\n"
            "Pi → shell → curl → " + TARGET + "\n"
            + blocked_text + "\n\n"
            "Real Pi/tools/gateway/sandbox; real public website fetch.\n"
            "Local deterministic model fixture; no model API key needed.\n")
        (EVIDENCE / "demo-results.txt").write_text(report)
        print(report, flush=True)
    finally:
        if fixture:
            fixture.close()
        for group in cgroup.glob("gateway-jail-*"):
            assert "populated 0" in (group / "cgroup.events").read_text(), "A sandbox process survived"
            group.rmdir()
        cgroup.rmdir()
        shutil.rmtree(ROOT)


if __name__ == "__main__":
    main()
