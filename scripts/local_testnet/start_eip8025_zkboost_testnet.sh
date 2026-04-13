#!/usr/bin/env bash

# Start a local EIP-8025 testnet with zkboost backends using Kurtosis.
#
# Builds a Lighthouse Docker image then launches a Kurtosis enclave via the
# ethereum-package with native zkboost support.
#
# For the mock-only path (no zkboost), use start_eip8025_testnet.sh instead.
#
# Requires: docker, kurtosis, yq

set -Eeuo pipefail

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
ROOT_DIR="$SCRIPT_DIR/../.."
ENCLAVE_NAME=eip8025-zkboost
NETWORK_PARAMS_FILE=$SCRIPT_DIR/network_params_eip8025_zkboost.yaml
ETHEREUM_PKG=github.com/frisitano/ethereum-package@feat/integrate-zkboost

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
        echo "Start a local EIP-8025 testnet with zkboost backends."
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

LH_IMAGE_NAME=$(yq eval ".participants[0].cl_image" "$NETWORK_PARAMS_FILE")

for cmd in docker kurtosis yq; do
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

echo "Starting EIP-8025 zkboost testnet enclave: $ENCLAVE_NAME"
echo "  ethereum-package: $ETHEREUM_PKG"
kurtosis run --enclave "$ENCLAVE_NAME" \
    "$ETHEREUM_PKG" \
    --args-file "$NETWORK_PARAMS_FILE"

echo ""
echo "EIP-8025 zkboost testnet started!"
echo ""
echo "Useful commands:"
echo "  kurtosis enclave inspect $ENCLAVE_NAME"
echo "  kurtosis service logs $ENCLAVE_NAME cl-1-lighthouse-reth"
echo "  kurtosis service logs $ENCLAVE_NAME zkboost-1"
echo "  kurtosis service logs $ENCLAVE_NAME zkboost-2"
echo "  kurtosis enclave rm -f $ENCLAVE_NAME"
