#!/usr/bin/env bash

# Start a local EIP-8025 testnet using Kurtosis.
#
# Requires: docker, kurtosis
#
# This script builds Lighthouse (optional) and launches a Kurtosis enclave via
# the ethereum-package. The network params file selects the topology:
#   network_params_eip8025.yaml              — mock proof engines (no zkboost)
#   network_params_eip8025_zkboost.yaml      — zkboost backends (mock zkVM)
#   network_params_eip8025_zkboost_gpu.yaml  — zkboost backends (GPU provers)

set -Eeuo pipefail

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
ROOT_DIR="$SCRIPT_DIR/../.."
ENCLAVE_NAME=eip8025-testnet
NETWORK_PARAMS_FILE=$SCRIPT_DIR/network_params_eip8025.yaml
ETHEREUM_PKG=github.com/ethpandaops/ethereum-package
# Must match the `cl_image` in the network params yaml so a local build is
# picked up by Kurtosis instead of pulling the remote image.
LH_IMAGE_NAME=ethpandaops/lighthouse:eth-act-optional-proofs

BUILD_IMAGE=true
KEEP_ENCLAVE=false

# Get options
while getopts "e:n:p:bkh" flag; do
  case "${flag}" in
    e) ENCLAVE_NAME=${OPTARG};;
    n) NETWORK_PARAMS_FILE=${OPTARG};;
    p) ETHEREUM_PKG=${OPTARG};;
    b) BUILD_IMAGE=false;;
    k) KEEP_ENCLAVE=true;;
    h)
        echo "Start a local EIP-8025 testnet with Kurtosis."
        echo
        echo "usage: $0 <Options>"
        echo
        echo "Options:"
        echo "   -e: enclave name                                default: $ENCLAVE_NAME"
        echo "   -n: kurtosis network params file path           default: $NETWORK_PARAMS_FILE"
        echo "   -p: ethereum-package path or GitHub ref         default: $ETHEREUM_PKG"
        echo "   -b: skip building Lighthouse docker image"
        echo "   -k: keep existing enclave (don't destroy first)"
        echo "   -h: this help"
        exit
        ;;
  esac
done

for cmd in docker kurtosis; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "$cmd is not installed. Please install $cmd and try again."
        exit 1
    fi
done

if [ "$KEEP_ENCLAVE" = false ]; then
    kurtosis enclave rm -f "$ENCLAVE_NAME" 2>/dev/null || true
fi

if [ "$BUILD_IMAGE" = true ]; then
    echo "Building Lighthouse Docker image ($LH_IMAGE_NAME)."
    docker build \
        --build-arg FEATURES=portable,spec-minimal \
        -f "$ROOT_DIR/Dockerfile" \
        -t "$LH_IMAGE_NAME" \
        "$ROOT_DIR"
else
    echo "Skipping Lighthouse Docker image build."
fi

echo "Starting EIP-8025 testnet enclave: $ENCLAVE_NAME"
echo "  network params:   $NETWORK_PARAMS_FILE"
echo "  ethereum-package: $ETHEREUM_PKG"
kurtosis run --enclave "$ENCLAVE_NAME" \
    "$ETHEREUM_PKG" \
    --args-file "$NETWORK_PARAMS_FILE"

echo
echo "EIP-8025 testnet started!"
echo
echo "Useful commands:"
echo "  kurtosis enclave inspect $ENCLAVE_NAME"
echo "  kurtosis service logs $ENCLAVE_NAME <service-name>"
echo "  kurtosis enclave rm -f $ENCLAVE_NAME"
