#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
ROOT_DIR="$( cd -- "$SCRIPT_DIR/../.." &> /dev/null && pwd )"

ENCLAVE_NAME="${ENCLAVE_NAME:-local-testnet}"
CL_SERVICE="${CL_SERVICE:-cl-1-lighthouse-geth}"
BEACON_NODE_URL="${BEACON_NODE_URL:-}"
SOURCE_BEACON_NODE_URL="${SOURCE_BEACON_NODE_URL:-}"
PROOFS_PER_BLOCK="${PROOFS_PER_BLOCK:-1}"
PROOF_DELAY_MS="${PROOF_DELAY_MS:-1000}"
BACKFILL_THRESHOLD_SLOTS="${BACKFILL_THRESHOLD_SLOTS:-32}"
BACKFILL_INTERVAL_SECS="${BACKFILL_INTERVAL_SECS:-10}"

while getopts "e:s:b:S:p:d:t:i:h" flag; do
  case "${flag}" in
    e) ENCLAVE_NAME=${OPTARG};;
    s) CL_SERVICE=${OPTARG};;
    b) BEACON_NODE_URL=${OPTARG};;
    S) SOURCE_BEACON_NODE_URL=${OPTARG};;
    p) PROOFS_PER_BLOCK=${OPTARG};;
    d) PROOF_DELAY_MS=${OPTARG};;
    t) BACKFILL_THRESHOLD_SLOTS=${OPTARG};;
    i) BACKFILL_INTERVAL_SECS=${OPTARG};;
    h)
      echo "Start the dummy prover against a local testnet."
      echo "Note: Run this after the testnet is up so the beacon node endpoint exists."
      echo
      echo "Usage: $0 [options]"
      echo
      echo "Options:"
      echo "  -e ENCLAVE_NAME           Kurtosis enclave name (default: $ENCLAVE_NAME)"
      echo "  -s CL_SERVICE             Kurtosis CL service name (default: $CL_SERVICE)"
      echo "  -b BEACON_NODE_URL        Target beacon node URL (default: from kurtosis)"
      echo "  -S SOURCE_BEACON_NODE_URL Source beacon node URL (default: target URL)"
      echo "  -p PROOFS_PER_BLOCK       Proof IDs to submit per block (default: $PROOFS_PER_BLOCK)"
      echo "  -d PROOF_DELAY_MS         Proof generation delay in ms (default: $PROOF_DELAY_MS)"
      echo "  -t BACKFILL_THRESHOLD     Backfill threshold in slots (default: $BACKFILL_THRESHOLD_SLOTS)"
      echo "  -i BACKFILL_INTERVAL      Backfill interval in seconds (default: $BACKFILL_INTERVAL_SECS)"
      echo "  -h                        Show this help"
      echo
      echo "Example:"
      echo "  $0 -e local-testnet -s cl-1-lighthouse-geth -p 2 -d 1000 -t 64 -i 5"
      exit
      ;;
  esac
done

if [ -z "$BEACON_NODE_URL" ]; then
  if command -v kurtosis &> /dev/null; then
    if BEACON_NODE_URL=$(kurtosis port print "$ENCLAVE_NAME" "$CL_SERVICE" http 2>/dev/null); then
      echo "Using beacon node from kurtosis: $BEACON_NODE_URL"
    else
      echo "Failed to detect beacon node URL via kurtosis. Set -b or BEACON_NODE_URL." >&2
      exit 1
    fi
  else
    BEACON_NODE_URL="http://localhost:5052"
    echo "kurtosis not found, defaulting to $BEACON_NODE_URL"
  fi
fi

if [ -z "$SOURCE_BEACON_NODE_URL" ]; then
  SOURCE_BEACON_NODE_URL="$BEACON_NODE_URL"
fi

echo "Starting dummy prover..."
echo "  target:  $BEACON_NODE_URL"
echo "  source:  $SOURCE_BEACON_NODE_URL"
echo "  proofs:  $PROOFS_PER_BLOCK"
echo "  delay:   ${PROOF_DELAY_MS}ms"
echo "  backfill threshold: ${BACKFILL_THRESHOLD_SLOTS} slots"
echo "  backfill interval:  ${BACKFILL_INTERVAL_SECS}s"

exec cargo run --manifest-path "$ROOT_DIR/Cargo.toml" -p zkvm_execution_layer --bin dummy-prover -- \
  --beacon-node "$BEACON_NODE_URL" \
  --source-beacon-node "$SOURCE_BEACON_NODE_URL" \
  --proofs-per-block "$PROOFS_PER_BLOCK" \
  --proof-delay-ms "$PROOF_DELAY_MS" \
  --backfill-threshold-slots "$BACKFILL_THRESHOLD_SLOTS" \
  --backfill-interval-secs "$BACKFILL_INTERVAL_SECS"
