# syntax=docker/dockerfile:1.7
#
# Ctxward — privacy gateway for LLM traffic
#
# Multi-stage build:
#   - builder: rust:bookworm with cargo cache mounts
#   - runtime: debian:bookworm-slim, non-root, read-only-rootfs friendly,
#              with HEALTHCHECK against /healthz and tini for signal handling.
#
# rustls-tls is used (no system CA dependency); we only need wget+tini at runtime.

ARG RUST_VERSION=1.95
ARG DEBIAN_VERSION=bookworm

# ============================================================================
# Builder
# ============================================================================
FROM rust:${RUST_VERSION}-${DEBIAN_VERSION} AS builder
WORKDIR /app

ENV CARGO_TERM_COLOR=always \
    CARGO_INCREMENTAL=0 \
    RUSTFLAGS="-C link-arg=-s"

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY config ./config

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    cargo build --release --locked && \
    cp /app/target/release/context-gurd /tmp/ctxward

# ============================================================================
# Runtime
# ============================================================================
FROM debian:${DEBIAN_VERSION}-slim AS runtime

ARG VCS_REF=unknown
ARG BUILD_DATE=unknown
ARG VERSION=0.0.0-dev

LABEL org.opencontainers.image.title="Ctxward" \
      org.opencontainers.image.description="Privacy gateway for LLM traffic — detection, redaction, tokenization, review." \
      org.opencontainers.image.source="https://github.com/OWNER/ctxward" \
      org.opencontainers.image.url="https://github.com/OWNER/ctxward" \
      org.opencontainers.image.documentation="https://github.com/OWNER/ctxward#readme" \
      org.opencontainers.image.vendor="Ctxward Contributors" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.version="${VERSION}"

RUN apt-get update && \
    apt-get install -y --no-install-recommends wget tini ca-certificates && \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/* && \
    groupadd -r -g 10001 ctxward && \
    useradd -r -u 10001 -g ctxward -s /usr/sbin/nologin -M ctxward && \
    mkdir -p /app && chown ctxward:ctxward /app

COPY --from=builder --chown=ctxward:ctxward /tmp/ctxward /usr/local/bin/ctxward
COPY --chown=ctxward:ctxward config/example.yaml /app/config.yaml

# Backwards-compat symlink so existing operators / docs still work.
RUN ln -s /usr/local/bin/ctxward /usr/local/bin/context-gurd

USER 10001:10001
WORKDIR /app

ENV CONTEXT_GURD_CONFIG=/app/config.yaml \
    RUST_LOG=info \
    RUST_BACKTRACE=1

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -qO- --tries=1 --timeout=2 http://127.0.0.1:8080/healthz || exit 1

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/ctxward"]
