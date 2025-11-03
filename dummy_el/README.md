# Using Dummy EL

This is a dummy EL that can be used with proof verification nodes. These nodes do not require an EL to function since they just take in proofs. 

## Quick Start

### 1. Build the Docker Image

From the lighthouse repository root:

```bash
docker build -f dummy_el/Dockerfile -t dummy_el:local .
```

### 2. Adding to Kurtosis

In Kurtosis, you can add the following:

```yaml
  - el_type: geth
    el_image: dummy_el:local
```

Note that we need to use el_type `geth` as kurtosis will be looking for a binary named geth. We wrap calls to the Geth binary so that they are processed by our dummy_el.