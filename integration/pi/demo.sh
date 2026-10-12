#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
arch=$(docker info --format '{{.Architecture}}')
case "$arch" in aarch64|arm64) goarch=arm64;; x86_64|amd64) goarch=amd64;; *) echo "unsupported Docker architecture" >&2; exit 1;; esac
build=$(mktemp -d)
trap 'rm -rf "$build"' EXIT
cd "$root"
mkdir -p artifacts/demo
CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" go build -trimpath -ldflags='-s -w' -o "$build/gateway" ./cmd/gateway
docker build -q -t gateway-pi-lab -f integration/pi/Dockerfile .
# The trusted outer gateway can reach the public website. Pi is confined by
# the real launcher inside this machine, with no external network route.
docker run --rm --privileged --cgroupns=host \
  -v "$build/gateway:/gateway:ro" \
  -v "$root/integration/pi:/fixtures:ro" \
  -v "$root/examples:/examples:ro" \
  -v "$root/artifacts/demo:/evidence" \
  gateway-pi-lab python3 /fixtures/demo.py
