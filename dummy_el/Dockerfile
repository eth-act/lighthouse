# Multi-stage build for dummy_el
FROM rust:1.88.0-bullseye AS builder

WORKDIR /build

# Copy the entire workspace (needed for workspace structure)
COPY . .

# Build only dummy_el in release mode
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release -p dummy_el && \
    cp target/release/dummy_el /dummy_el

# Runtime stage with minimal Ubuntu image
FROM ubuntu:22.04

RUN apt-get update && apt-get -y upgrade && apt-get install -y --no-install-recommends \
  ca-certificates \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

# Copy the binary from builder
COPY --from=builder /dummy_el /usr/local/bin/dummy_el

# Create a fake 'geth' binary that runs dummy_el instead
# Kurtosis will call "geth init ..." and "geth --..." but we'll run dummy_el
COPY --from=builder /build/dummy_el/geth-wrapper.sh /usr/local/bin/geth
RUN chmod +x /usr/local/bin/geth

# Expose default Engine API port
EXPOSE 8551
