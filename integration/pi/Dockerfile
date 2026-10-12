# This privileged OUTER lab supplies kernel facilities to the real bwrap
# launcher. Pi never runs in this outer network/mount namespace.
FROM node:24.9.0-bookworm-slim@sha256:3e69116c924bfcba6c6979aff60d966c37aef56d488ce091c69d442ebec9f103
RUN apt-get update && apt-get install -y --no-install-recommends bubblewrap=0.8.0-2+deb12u1 curl iproute2 tcpdump openssl python3 gcc libc6-dev ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /pi
COPY integration/pi/package*.json ./
RUN npm ci --ignore-scripts
# Trusted runtime has no host sockets, secrets, policy, audit or package manager.
RUN mkdir -p /runtime/usr/bin /runtime/usr/local/bin /runtime/lib /runtime/lib64 /runtime/etc /runtime/proc /runtime/dev /runtime/tmp /runtime/home/agent /runtime/workspace /runtime/run /runtime/opt \
    && cp /usr/local/bin/node /runtime/usr/local/bin/node \
    && cp /bin/dash /runtime/usr/bin/dash \
    && ln -s dash /runtime/usr/bin/sh \
    && ln -s usr/bin /runtime/bin \
    && cp -a /lib/*-linux-gnu /runtime/lib/ \
    && for p in /lib/ld-linux-*.so.*; do [ ! -e "$p" ] || cp -a "$p" /runtime/lib/; done \
    && for p in /lib64/ld-linux-*.so.*; do [ ! -e "$p" ] || cp -L "$p" /runtime/lib64/; done \
    && cp /etc/ssl/certs/ca-certificates.crt /runtime/etc/ca-certificates.crt \
    && cp -a /pi /runtime/opt/pi
RUN touch /runtime/run/gateway.sock
COPY integration/pi/ /fixtures/
