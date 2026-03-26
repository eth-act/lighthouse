FROM rust:1.91.0-bullseye AS builder
RUN apt-get update && apt-get -y upgrade && apt-get install -y cmake libclang-dev
ARG FEATURES
ARG PROFILE=release
ARG CARGO_USE_GIT_CLI=true
ENV FEATURES=$FEATURES
ENV PROFILE=$PROFILE
ENV CARGO_NET_GIT_FETCH_WITH_CLI=$CARGO_USE_GIT_CLI
ENV CARGO_INCREMENTAL=1

WORKDIR /lighthouse
COPY . .
# Persist the registry and target file across builds. See: https://docs.docker.com/build/cache/optimize/#use-cache-mounts
# Clear stale leveldb-sys cmake cache before building to avoid failures on cached runners.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/lighthouse/target \
    rm -rf /lighthouse/target/release/build/leveldb-sys-*/out/build 2>/dev/null || true && \
    make

FROM ubuntu:22.04
RUN apt-get update && apt-get -y upgrade && apt-get install -y --no-install-recommends \
  libssl-dev \
  ca-certificates \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/cargo/bin/lighthouse /usr/local/bin/lighthouse
