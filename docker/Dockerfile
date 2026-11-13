# syntax=docker/dockerfile:1

# ---- build -----------------------------------------------------------------
FROM rust:1.99-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml rustfmt.toml ./
COPY crates ./crates
RUN cargo build --release --locked -p browserx \
 && strip target/release/browserx

# ---- runtime ---------------------------------------------------------------
FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends chromium ca-certificates curl fonts-liberation tini \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 10001 browserx \
 && useradd --system --uid 10001 --gid browserx --home-dir /var/lib/browserx --create-home --shell /usr/sbin/nologin browserx

COPY --from=build /src/target/release/browserx /usr/local/bin/browserx
COPY docker/browserx.docker.toml /etc/browserx/browserx.toml

ENV BROWSERX_CHROMIUM_PATH=/usr/bin/chromium
USER browserx
WORKDIR /var/lib/browserx
VOLUME ["/var/lib/browserx"]
EXPOSE 7690 7691

# Readiness covers the lease store, the browser executable and drain state.
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=3 \
  CMD curl --fail --silent http://127.0.0.1:7691/readyz || exit 1

# tini reaps the browser processes the server spawns.
ENTRYPOINT ["/usr/bin/tini", "--", "browserx"]
CMD ["serve", "--config", "/etc/browserx/browserx.toml"]
