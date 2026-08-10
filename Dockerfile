# Build.
#
# Pinned to the MSRV floor rather than `latest`: 1.85 is a hard requirement (the crypto
# tree needs edition2024) and CI checks it, so building the image on the same version is
# what keeps "it works in Docker" and "CI is green" the same statement.
FROM rust:1.85-bookworm AS build

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

# --locked so the image cannot silently resolve different dependency versions than the
# ones `cargo audit` ran against in CI.
RUN cargo build --release --locked -p cairn-server

# Run.
#
# Debian slim rather than distroless or scratch: the binary links against system OpenSSL-free
# rustls, but glibc and CA certificates are still wanted, and a shell makes a failing
# deployment diagnosable by whoever is self-hosting. This is a project people are meant to
# run themselves.
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Unprivileged. The server needs nothing but its own data directory.
RUN useradd --system --create-home --uid 10001 cairn
USER cairn

COPY --from=build /src/target/release/cairn-server /usr/local/bin/cairn-server

# Bind to all interfaces *inside the container*. That is not the same as exposing it: the
# compose file publishes only the reverse proxy, and this port stays on the internal
# network. See docs/11-self-hosting.md — the server terminates no TLS of its own.
ENV CAIRN_BIND=0.0.0.0:8080 \
    CAIRN_DATA_DIR=/data \
    RUST_LOG=info

VOLUME ["/data"]
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/cairn-server"]
