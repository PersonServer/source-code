# syntax=docker/dockerfile:1
# Multi-arch (linux/amd64, linux/arm64) build of psd, the AAuth Person Server.
#
# Build with buildx (each target platform builds natively under emulation):
#   docker buildx build --platform linux/amd64,linux/arm64 \
#     -t ghcr.io/personserver/psd:dev .
#
# The runtime image is distroless/cc (glibc, no shell, non-root). psd needs
# no OpenSSL (TLS is rustls) and no system SQLite: rusqlite's bundled build
# compiles SQLite into the binary, so glibc + libgcc from cc-debian12 are all
# it links against at run time. Verified by running `psd version` and a
# `serve` against the built image.
#
# Adapted from apd (MIT OR Apache-2.0), github.com/AgentProvider/source-code.

FROM rust:1-bookworm AS builder
ARG TARGETARCH
WORKDIR /src

# BuildKit caches the cargo registry, the git checkouts and the target dir
# across builds — all three keyed per arch. A multi-platform build runs the
# amd64 and arm64 stages concurrently, and two cargos unpacking crates into
# one shared registry cache race ("failed to unpack package … File exists").
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN --mount=type=cache,target=/usr/local/cargo/registry,id=psd-cargo-registry-${TARGETARCH} \
    --mount=type=cache,target=/usr/local/cargo/git,id=psd-cargo-git-${TARGETARCH} \
    --mount=type=cache,target=/src/target,id=psd-target-${TARGETARCH} \
    cargo build --release --locked --bin psd \
    && strip target/release/psd \
    && cp target/release/psd /usr/local/bin/psd \
    && mkdir -p /out/var/lib/psd

FROM gcr.io/distroless/cc-debian12:nonroot AS runtime
COPY --from=builder /usr/local/bin/psd /usr/local/bin/psd

# psd reads its config under /etc/psd and keeps its state (keys file, SQLite
# database, audit log) under /var/lib/psd — mount a volume there; the
# database is the record of who allowed what and must survive restarts.
# The directory is created in the builder and copied in owned by uid 65532
# (nonroot) so that psd can write there even with NO volume mounted — a
# first `docker run` must not fail with "unable to open database file".
# There is no shell in distroless to chown it afterwards, and relying on
# WORKDIR to create it as the right user depends on the base image's USER
# and the builder in use. WORKDIR is the state dir so relative paths in the
# config resolve there.
COPY --from=builder --chown=65532:65532 /out/var/lib/psd /var/lib/psd
WORKDIR /var/lib/psd
EXPOSE 8430
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/psd"]
CMD ["serve", "--config", "/etc/psd/psd.json"]

# OCI labels (repo/version/revision are also injected in CI via annotations).
LABEL org.opencontainers.image.title="psd" \
      org.opencontainers.image.description="Self-hostable AAuth Person Server" \
      org.opencontainers.image.source="https://github.com/PersonServer/source-code" \
      org.opencontainers.image.licenses="MIT"
