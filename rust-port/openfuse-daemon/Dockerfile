# Build context must be rust-port/ (workspace root), not openfuse-daemon/
# docker build -f openfuse-daemon/Dockerfile .
FROM rust:slim AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY openfuse-core/ openfuse-core/
COPY openfuse-cli/ openfuse-cli/
COPY openfuse-daemon/ openfuse-daemon/
# Only build the daemon (skip CLI)
RUN cargo build --release -p openfused-daemon && \
    strip target/release/openfused

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/openfused /usr/local/bin/openfused
EXPOSE 2053
ENTRYPOINT ["openfused"]
CMD ["serve", "--store", "/store", "--port", "2053"]
