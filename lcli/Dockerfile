# `lcli` requires the full project to be in scope, so this should be built either:
#  - from the `lighthouse` dir with the command: `docker build -f ./lcli/Dockerflie .`
#  - from the current directory with the command: `docker build -f ./Dockerfile ../`
FROM rust:1.88.0-bullseye AS builder
RUN apt-get update && apt-get install -y --no-install-recommends cmake libclang-dev clang \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
ENV CC=clang
ENV CXX=clang++
COPY . lighthouse
ARG FEATURES
ENV FEATURES=$FEATURES
RUN cd lighthouse && make install-lcli

FROM ubuntu:22.04
COPY --from=builder /usr/local/cargo/bin/lcli /usr/local/bin/lcli
