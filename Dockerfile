FROM rust:latest AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 ca-certificates tmux sudo && \
    rm -rf /var/lib/apt/lists/*
# Add Unix users matching config.toml entries (setuid requires them to exist)
# Example: RUN useradd -m -s /bin/bash ktulu
COPY --from=builder /build/target/release/tmuxwrapper /opt/tmuxwrapper/tmuxwrapper
COPY config.toml /opt/tmuxwrapper/config.toml
COPY static/ /opt/tmuxwrapper/static/
WORKDIR /opt/tmuxwrapper
ENTRYPOINT ["/opt/tmuxwrapper/tmuxwrapper"]
