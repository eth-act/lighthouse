#!/usr/bin/env bash

# Start a local EIP-8025 testnet with mock proof engines using Kurtosis.
#
# Requires: docker, kurtosis, yq
#
# This script builds Lighthouse and launches a Kurtosis enclave using
# network_params_eip8025.yaml. Mock proof engines are enabled via the
# http://mock/0/ URL pattern (no special build feature required).

set -Eeuo pipefail

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
ROOT_DIR="$SCRIPT_DIR/../.."
ENCLAVE_NAME=eip8025-testnet
NETWORK_PARAMS_FILE=$SCRIPT_DIR/network_params_eip8025.yaml
ETHEREUM_PKG_VERSION=main

BUILD_IMAGE=true
KEEP_ENCLAVE=false

# Get options
while getopts "e:n:bkh" flag; do
  case "${flag}" in
    e) ENCLAVE_NAME=${OPTARG};;
    n) NETWORK_PARAMS_FILE=${OPTARG};;
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
    echo "Building Lighthouse Docker image."
    docker build \
        --build-arg FEATURES=portable,spec-minimal \
        -f "$ROOT_DIR/Dockerfile" \
        -t "$LH_IMAGE_NAME" \
        "$ROOT_DIR"
else
    echo "Skipping Lighthouse Docker image build."
fi

echo "Starting EIP-8025 testnet enclave: $ENCLAVE_NAME"
kurtosis run --enclave "$ENCLAVE_NAME" \
    "github.com/ethpandaops/ethereum-package@$ETHEREUM_PKG_VERSION" \
    --args-file "$NETWORK_PARAMS_FILE"

echo "EIP-8025 testnet started!"
echo
echo "Useful commands:"
echo "  kurtosis enclave inspect $ENCLAVE_NAME"
echo "  kurtosis service logs $ENCLAVE_NAME cl-1-lighthouse-geth"
echo "  kurtosis enclave rm -f $ENCLAVE_NAME"
