# sentinel scanner - rust build
# c1q_ (M-Society team)

FROM rust:1.76-slim AS builder
WORKDIR /app
COPY Cargo.toml .
COPY src/ src/
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/port-scanner /usr/local/bin/
COPY --from=builder /app/target/release/banner-grabber /usr/local/bin/
COPY --from=builder /app/target/release/tls-fingerprint /usr/local/bin/
COPY --from=builder /app/target/release/mass-resolver /usr/local/bin/
