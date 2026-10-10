# EpiGraph Explorer: server-rendered web UI + BFF for epigraph-api.
#
# Build context is this directory (`.dockerignore` keeps target/ out):
#   docker build -t epigraph-explorer services/explorer
#
# NETWORKING — read before running. epigraph-api is NOT a container: it runs
# on the host as the systemd unit `epigraph-api.service`, listening on port
# 8080. And this binary binds 127.0.0.1:${EPIGRAPH_EXPLORER_PORT} only (see
# src/main.rs; the reverse proxy is the public edge). Together that means:
#   - Outbound: on a bridge network, 127.0.0.1:8080 inside the container is
#     the container itself, not the host API. A host-gateway
#     (`--add-host=host.docker.internal:host-gateway` plus
#     EPIGRAPH_API_URL=http://host.docker.internal:8080) fixes this side only.
#   - Inbound: a loopback bind inside a bridge network is unreachable from the
#     host, so `-p 8096:8096` does NOT work.
# So run it with host networking, where 127.0.0.1 is the host's loopback on
# both sides and Caddy's `reverse_proxy 127.0.0.1:8096` reaches it:
#   docker run -d --name epigraph-explorer --network host \
#     --env-file /etc/epigraph/explorer.env epigraph-explorer
# Or skip the container and run it under systemd next to the API, as
# `epigraph-explorer.service.example` shows. See README.md "Deploy".
#
# Everything the binary serves is compiled in: askama templates at compile
# time, and every file under static/ via build.rs. The runtime stage needs
# nothing but the binary. Builder and runtime share one Debian release so the
# binary's glibc matches.

FROM rust:1-slim-bookworm AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock build.rs ./
COPY src ./src
COPY templates ./templates
COPY static ./static
# --locked: build exactly the committed dependency graph, as CI does.
RUN cargo build --release --locked --bin epigraph-explorer

FROM debian:bookworm-slim
# reqwest's `rustls-tls` feature bundles the Mozilla roots (webpki-roots), so
# TLS to an https EPIGRAPH_API_URL / EPIGRAPH_OAUTH_BASE_URL works without the
# system store; ca-certificates is installed anyway so a switch to native
# roots, or an operator's debugging tools, do not silently lose trust anchors.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
# Fixed, unprivileged uid/gid with no home and no login shell. The process
# writes nothing to disk: sessions live in memory (a restart signs everyone out).
RUN groupadd --system --gid 10001 explorer \
    && useradd --system --uid 10001 --gid 10001 --no-create-home \
       --home-dir /nonexistent --shell /usr/sbin/nologin explorer
COPY --from=builder /build/target/release/epigraph-explorer /usr/local/bin/epigraph-explorer
USER 10001:10001
ENV EPIGRAPH_EXPLORER_PORT=8096 \
    RUST_LOG=info
# Documentation only under --network host, which ignores port publishing.
EXPOSE 8096
# SIGTERM (Docker's default stop signal) drains in-flight requests and exits 0.
# Exit code 2 means a configuration error: fix the env, do not restart-loop.
CMD ["/usr/local/bin/epigraph-explorer"]
