#!/bin/sh
set -e

# This is a wrapper that pretends to be geth but actually runs dummy_el
# Kurtosis may call various geth commands - we handle them all appropriately

echo "[dummy_el geth-wrapper] Called with: $@"

# Check if this is the "geth init" command - ignore it
if echo "$@" | grep -q "init"; then
    echo "[dummy_el geth-wrapper] Ignoring 'geth init' command"
    exit 0
fi

# Check for version/help commands
if echo "$@" | grep -qE "^(version|--version|-v|help|--help|-h)$"; then
    echo "Dummy-EL/v0.1.0 (geth-compatible wrapper)"
    exit 0
fi

# Filter out flags that we don't need for dummy_el
# These are geth-specific flags that kurtosis may pass
FILTERED_ARGS=""
for arg in "$@"; do
    case "$arg" in
        --override.*|--override*|-override.*|-override*)
            echo "[dummy_el geth-wrapper] Ignoring geth flag: $arg"
            ;;
        --datadir=*|--datadir)
            echo "[dummy_el geth-wrapper] Ignoring geth flag: $arg"
            ;;
        --syncmode=*|--syncmode)
            echo "[dummy_el geth-wrapper] Ignoring geth flag: $arg"
            ;;
        --gcmode=*|--gcmode)
            echo "[dummy_el geth-wrapper] Ignoring geth flag: $arg"
            ;;
        --networkid=*|--networkid)
            echo "[dummy_el geth-wrapper] Ignoring geth flag: $arg"
            ;;
        *)
            FILTERED_ARGS="$FILTERED_ARGS $arg"
            ;;
    esac
done

# For any other command, we start dummy_el
# Parse geth arguments to extract what we need

JWT_PATH=""
ENGINE_PORT="8551"
RPC_PORT="8545"
WS_PORT="8546"
METRICS_PORT="9001"
P2P_PORT="30303"
HOST="0.0.0.0"

# Parse arguments to find JWT secret and ports
for arg in "$@"; do
    case "$arg" in
        --authrpc.jwtsecret=*)
            JWT_PATH="${arg#*=}"
            ;;
        --authrpc.port=*)
            ENGINE_PORT="${arg#*=}"
            ;;
        --http.port=*)
            RPC_PORT="${arg#*=}"
            ;;
        --ws.port=*)
            WS_PORT="${arg#*=}"
            ;;
        --metrics.port=*)
            METRICS_PORT="${arg#*=}"
            ;;
        --port=*)
            P2P_PORT="${arg#*=}"
            ;;
        --discovery.port=*)
            # Use discovery port for P2P if specified
            P2P_PORT="${arg#*=}"
            ;;
    esac
done

# Fallback to default JWT location if not parsed
if [ -z "$JWT_PATH" ] && [ -f "/jwt/jwtsecret" ]; then
    JWT_PATH="/jwt/jwtsecret"
fi

echo "[dummy_el geth-wrapper] Starting dummy_el instead of geth"
echo "[dummy_el geth-wrapper] Engine port: $ENGINE_PORT, RPC port: $RPC_PORT, WS port: $WS_PORT"
echo "[dummy_el geth-wrapper] Metrics port: $METRICS_PORT, P2P port: $P2P_PORT"

# Build dummy_el command
DUMMY_EL_CMD="/usr/local/bin/dummy_el --host $HOST --port $ENGINE_PORT --rpc-port $RPC_PORT --ws-port $WS_PORT --metrics-port $METRICS_PORT --p2p-port $P2P_PORT"

# Add JWT if available
if [ -n "$JWT_PATH" ] && [ -f "$JWT_PATH" ]; then
    echo "[dummy_el geth-wrapper] Using JWT from $JWT_PATH"
    DUMMY_EL_CMD="$DUMMY_EL_CMD --jwt-secret $JWT_PATH"
else
    echo "[dummy_el geth-wrapper] WARNING: No JWT file found"
fi

echo "[dummy_el geth-wrapper] Executing: $DUMMY_EL_CMD"
exec $DUMMY_EL_CMD
