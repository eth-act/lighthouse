# Simple Local Testnet

These scripts allow for running a small local testnet with a default of 4 beacon nodes, 4 validator clients and 4 Geth execution clients using Kurtosis.
This setup can be useful for testing and development.

## Installation

1. Install [Docker](https://docs.docker.com/get-docker/). Verify that Docker has been successfully installed by running `sudo docker run hello-world`. 

1. Install [Kurtosis](https://docs.kurtosis.com/install/). Verify that Kurtosis has been successfully installed by running `kurtosis version` which should display the version.

1. Install [`yq`](https://github.com/mikefarah/yq). If you are on Ubuntu, you can install `yq` by running `snap install yq`.

## Starting the testnet

To start a testnet, from the Lighthouse root repository:

```bash
cd ./scripts/local_testnet
./start_local_testnet.sh
```

It will build a Lighthouse docker image from the root of the directory and will take an approximately 12 minutes to complete. Once built, the testing will be started automatically. You will see a list of services running and "Started!" at the end. 
You can also select your own Lighthouse docker image to use by specifying it in `network_params.yaml` under the `cl_image` key.
Full configuration reference for Kurtosis is specified [here](https://github.com/ethpandaops/ethereum-package?tab=readme-ov-file#configuration).

To view all running services:

```bash
kurtosis enclave inspect local-testnet
```

To view the logs:

```bash
kurtosis service logs local-testnet $SERVICE_NAME
```

where `$SERVICE_NAME` is obtained by inspecting the running services above. For example, to view the logs of the first beacon node, validator client and Geth:

```bash
kurtosis service logs local-testnet -f cl-1-lighthouse-geth 
kurtosis service logs local-testnet -f vc-1-geth-lighthouse
kurtosis service logs local-testnet -f el-1-geth-lighthouse
```

If you would like to save the logs, use the command:

```bash
kurtosis dump $OUTPUT_DIRECTORY
```

This will create a folder named `$OUTPUT_DIRECTORY` in the present working directory that contains all logs and other information. If you want the logs for a particular service and saved to a file named `logs.txt`:

```bash
kurtosis service logs local-testnet $SERVICE_NAME -a > logs.txt
```
where `$SERVICE_NAME` can be viewed by running `kurtosis enclave inspect local-testnet`.

Kurtosis comes with a Dora explorer which can be opened with:

```bash
open $(kurtosis port print local-testnet dora http)
```

Some testnet parameters can be varied by modifying the `network_params.yaml` file. Kurtosis also comes with a web UI which can be open with `kurtosis web`.

## Stopping the testnet

To stop the testnet, from the Lighthouse root repository:

```bash
cd ./scripts/local_testnet
./stop_local_testnet.sh
```

You will see "Local testnet stopped." at the end. 

## CLI options

The script comes with some CLI options, which can be viewed with `./start_local_testnet.sh --help`. One of the CLI options is to avoid rebuilding Lighthouse each time the testnet starts, which can be configured with the command:

```bash
./start_local_testnet.sh -b false
```

## EIP-8025 Testnets

EIP-8025 introduces execution proofs into the Ethereum consensus layer. Three Kurtosis configurations are provided, ranging from a fully mocked setup to a GPU-backed production-like environment.

### Configuration overview

| File | Proof backend | EL client | Use case |
|---|---|---|---|
| `network_params_eip8025.yaml` | Mock (`http://mock/0/`) | Geth | Fast local dev/CI |
| `network_params_eip8025_zkboost.yaml` | zkboost-server (mock zkVM) | Reth | Integration testing |
| `network_params_eip8025_zkboost_gpu.yaml` | zkboost-server (GPU ZisK) | Reth | Full proving validation |

All three configurations run 4 participants: 2 supernodes (with proof generation enabled) and 2 non-supernodes.

### Mock proof engine testnet

Starts a 4-node network where each node points to a `MockProofNodeClient` via the `http://mock/0/` URL. No real proving is done; this is the fastest way to exercise the EIP-8025 code paths locally.

```bash
cd ./scripts/local_testnet
./start_eip8025_testnet.sh
```

CLI options:

```
-e: enclave name               (default: eip8025-testnet)
-n: network params file path   (default: network_params_eip8025.yaml)
-b: skip building Docker image
-k: keep existing enclave (don't destroy first)
```

To skip rebuilding Lighthouse on subsequent runs:

```bash
./start_eip8025_testnet.sh -b
```

### zkboost testnet (mock provers)

Starts a 4-node network backed by two `zkboost-server` instances, each connected to its own Reth execution client. Proving is handled by a mock zkVM (`reth-zisk` kind), so no GPU hardware is required. Uses a fork of the ethereum-package with native zkboost support.

```bash
cd ./scripts/local_testnet
./start_eip8025_zkboost_testnet.sh
```

CLI options:

```
-e: enclave name               (default: eip8025-zkboost)
-n: network params file path   (default: network_params_eip8025_zkboost.yaml)
-p: ethereum-package ref       (default: github.com/frisitano/ethereum-package@feat/integrate-zkboost)
-b: skip building Docker image
-k: keep existing enclave (don't destroy first)
```

To inspect running services and follow logs:

```bash
kurtosis enclave inspect eip8025-zkboost
kurtosis service logs eip8025-zkboost -f cl-1-lighthouse-reth
kurtosis service logs eip8025-zkboost -f zkboost-1
kurtosis service logs eip8025-zkboost -f zkboost-2
```

### zkboost testnet (GPU ZisK provers)

Starts the same 4-node topology but replaces the mock zkVM with real GPU-backed `ere-server-zisk` containers. Two prover types are configured: `reth-zisk` (GPUs 0–3) and `ethrex-zisk` (GPUs 4–7).

**Prerequisites:**
- NVIDIA GPUs with drivers installed (8 GPUs recommended: 4 per prover type)
- NVIDIA Container Toolkit configured for Docker
- Allow 5–10 minutes for ZisK setup on first run

```bash
cd ./scripts/local_testnet
./start_eip8025_zkboost_testnet.sh -n network_params_eip8025_zkboost_gpu.yaml -e eip8025-zkboost-gpu
```

### Stopping an EIP-8025 enclave

```bash
kurtosis enclave rm -f eip8025-testnet       # mock testnet
kurtosis enclave rm -f eip8025-zkboost       # zkboost testnet
kurtosis enclave rm -f eip8025-zkboost-gpu   # GPU testnet
```

## Further reading about Kurtosis

You may refer to [this article](https://ethpandaops.io/posts/kurtosis-deep-dive/) for information about Kurtosis.