#!/bin/sh
set -e

# This is a wrapper that pretends to be geth but actually runs dummy_el
# Kurtosis calls: geth init ... && geth --authrpc.port=8551 ...
# We ignore the init, and when we see the actual geth command with authrpc.port, we start dummy_el

echo "[dummy_el geth-wrapper] Called with: $@"

# Check if this is the "geth init" command and ignore it
if echo "$@" | grep -q "init"; then
    echo "[dummy_el geth-wrapper] Ignoring 'geth init' command"
    exit 0
fi

# If we're here, it's the actual geth run command
# Kurtosis mounts JWT secret at /jwt/jwtsecret
JWT_PATH="/jwt/jwtsecret"

echo "[dummy_el geth-wrapper] Starting dummy_el instead of geth"

# Run dummy_el with JWT if available, otherwise without
if [ -f "$JWT_PATH" ]; then
    echo "[dummy_el geth-wrapper] Using JWT from $JWT_PATH"
    exec /usr/local/bin/dummy_el --host 0.0.0.0 --port 8551 --jwt-secret "$JWT_PATH"
else
    echo "[dummy_el geth-wrapper] WARNING: No JWT file found at $JWT_PATH"
    exec /usr/local/bin/dummy_el --host 0.0.0.0 --port 8551
fi
