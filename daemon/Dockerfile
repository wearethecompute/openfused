FROM rust:1.84-slim AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
RUN apt-get update && apt-get install -y pkg-config libfuse3-dev && \
    cargo build --release && \
    strip target/release/openfused

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends libfuse3-3 ca-certificates && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/openfused /usr/local/bin/openfused
EXPOSE 9781
ENTRYPOINT ["openfused"]
CMD ["serve", "--store", "/store", "--port", "9781"]
