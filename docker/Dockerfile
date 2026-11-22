# syntax=docker/dockerfile:1

# ---- build -----------------------------------------------------------------
# rust:1.99-bookworm
FROM docker.io/library/rust:1.99-bookworm@sha256:e6f2cff35d0f309acf8433b4f05878ed77092602c5065cc81801177da0bb3a9c AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml rustfmt.toml ./
COPY crates ./crates
COPY vendor ./vendor
# The MCP server embeds these at build time (include_str!).
COPY docs ./docs
COPY examples ./examples
RUN cargo build --release --locked -p browserx \
 && strip target/release/browserx

# ---- runtime ---------------------------------------------------------------
# debian:bookworm-slim
FROM docker.io/library/debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
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
