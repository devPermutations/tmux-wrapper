FROM rust:latest AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 ca-certificates tmux && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/tmuxwrapper /opt/tmuxwrapper/tmuxwrapper
COPY config.toml /opt/tmuxwrapper/config.toml
COPY static/ /opt/tmuxwrapper/static/
WORKDIR /opt/tmuxwrapper
ENTRYPOINT ["/opt/tmuxwrapper/tmuxwrapper"]
