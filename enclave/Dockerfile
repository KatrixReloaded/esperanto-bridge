# syntax=docker/dockerfile:1.7
# Registry manifest digests resolved 2026-11-06. Always build linux/amd64 on Linux.
FROM rust:1.96.0-bookworm@sha256:5e2214abe154fe26e39f64488952e5c991eeed1d6d6da7cc8381ae83927f0cfc AS rust-build
ARG SOURCE_DATE_EPOCH
RUN rm -f /etc/apt/sources.list.d/debian.sources && printf '%s\n' 'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/20261101T000000Z bookworm main' > /etc/apt/sources.list && apt-get -o Acquire::Check-Valid-Until=false update && apt-get install -y --no-install-recommends libssl-dev pkg-config && rm -rf /var/lib/apt/lists/*
WORKDIR /src/service
COPY service/ ./
ENV CARGO_INCREMENTAL=0 RUSTFLAGS="--remap-path-prefix=/src=/build"
RUN cargo build --locked --release --features zz-watcher/nitro --package zz-watcher

FROM node:24.11.1-bookworm-slim@sha256:48abc13a19400ca3985071e287bd405a1d99306770eb81d61202fb6b65cf0b57 AS sdk-build
WORKDIR /app/sidecar
COPY sidecar/package.json sidecar/package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts
COPY sidecar/src ./src

FROM node:24.11.1-bookworm-slim@sha256:48abc13a19400ca3985071e287bd405a1d99306770eb81d61202fb6b65cf0b57
ARG SOURCE_DATE_EPOCH
RUN rm -f /etc/apt/sources.list.d/debian.sources && printf '%s\n' 'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/20261101T000000Z bookworm main' > /etc/apt/sources.list && apt-get -o Acquire::Check-Valid-Until=false update && apt-get install -y --no-install-recommends libssl3 ca-certificates python3 iproute2 && rm -rf /var/lib/apt/lists/* /var/log/*
COPY --from=rust-build /src/service/target/release/zz-watcher /app/zz-watcher
COPY --from=sdk-build /app/sidecar /app/sidecar
COPY scripts/nitro/forward.py /app/forward.py
COPY enclave/init.py /app/init.py
# Config is public and measured; no keys, IAM credentials or host plaintext state in the image.
COPY enclave/config/runtime.json enclave/config/sidecar.json /etc/cwxmr/
WORKDIR /app
ENTRYPOINT ["/usr/bin/python3", "/app/init.py"]
