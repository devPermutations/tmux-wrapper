# Stage 1: Build
FROM rust:1.93-bookworm AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
RUN cargo build --release

# Stage 2: Runtime
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    tmux sudo ca-certificates libssl3 curl && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/wraptmux/static /data
COPY --from=builder /build/target/release/wraptmux /opt/wraptmux/wraptmux
COPY static/ /opt/wraptmux/static/
COPY entrypoint.sh /opt/wraptmux/entrypoint.sh
RUN chmod +x /opt/wraptmux/entrypoint.sh

EXPOSE 7681
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:7681/ || exit 1

ENTRYPOINT ["/opt/wraptmux/entrypoint.sh"]
