#!/bin/sh
set -eu
# Docker provides a Linux test machine, never a production isolation fallback.
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
arch=$(docker info --format '{{.Architecture}}')
case "$arch" in aarch64|arm64) goarch=arm64;; x86_64|amd64) goarch=amd64;; *) echo "unsupported Docker architecture" >&2; exit 1;; esac
build=$(mktemp -d)
trap 'rm -rf "$build"' EXIT
cd "$root"
mkdir -p artifacts/acceptance
CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" go build -trimpath -ldflags='-s -w' -o "$build/gateway" ./cmd/gateway
CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" go test -c -o "$build/isolation.test" ./internal/isolation
docker build -t gateway-pi-lab -f integration/pi/Dockerfile .
python3 - "$build/gateway" "$root" <<'PYMANIFEST'
import hashlib,json,pathlib,subprocess,sys
binary=pathlib.Path(sys.argv[1]);root=pathlib.Path(sys.argv[2])
paths=[root/"go.mod",root/"integration/pi/Dockerfile",root/"integration/pi/package-lock.json"]
for folder in ("cmd","internal","tests/security"):
    paths+=list((root/folder).rglob("*.go"))
paths+=list((root/"tests/security").rglob("*.c"))
for suffix in ("*.py","*.sh","*.ts","*.mjs","*.json"):
    paths+=list((root/"integration/pi").glob(suffix))
manifest={"go_version":subprocess.check_output(["go","version"],text=True).strip(),"binary_bytes":binary.stat().st_size,"binary_sha256":hashlib.sha256(binary.read_bytes()).hexdigest(),"files_sha256":{str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest()for p in sorted(set(paths))},"pi":"1.1.0","bubblewrap":"0.8.0-2+deb12u1","outer_kernel":subprocess.check_output(["docker","run","--rm","--network","none","gateway-pi-lab","uname","-r"],text=True).strip()}
(root/"artifacts/acceptance/manifest.json").write_text(json.dumps(manifest,indent=2)+"\n")
print("Release binary",manifest["binary_bytes"],"bytes SHA256",manifest["binary_sha256"])
PYMANIFEST
docker run --rm --privileged --network none --cgroupns=host \
  -e "GATEWAY_MEASURE=${GATEWAY_MEASURE:-0}" \
  -v "$build/gateway:/gateway:ro" \
  -v "$build/isolation.test:/isolation.test:ro" \
  -v "$root/integration/pi:/fixtures:ro" \
  -v "$root/examples:/examples:ro" \
  -v "$root/tests/security:/security:ro" \
  gateway-pi-lab sh -c '/isolation.test -test.v && python3 /fixtures/run.py'
