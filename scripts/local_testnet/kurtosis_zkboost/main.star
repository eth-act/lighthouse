# Kurtosis package that runs the ethereum-package and then adds zkboost-server
# sidecar services for real proof generation.
#
# Usage:
#   kurtosis run --enclave eip8025-zkboost ./kurtosis_zkboost \
#       --args-file network_params_eip8025_zkboost.yaml
#
# The args file must include a top-level `zkboost` key alongside standard
# ethereum-package configuration.  Example:
#
#   zkboost:
#     image: ghcr.io/eth-act/zkboost/zkboost-server:1715344
#     instances:
#       - name: zkboost-1
#         el_service: el-1-geth-lighthouse
#       - name: zkboost-2
#         el_service: el-2-geth-lighthouse
#     mock_proving_time_ms: 5000
#     mock_proof_size: 1024

ethereum_package = import_module("github.com/ethpandaops/ethereum-package/main.star")

ZKBOOST_PORT_ID = "http"
ZKBOOST_PORT_NUMBER = 3000
ZKBOOST_METRICS_PATH = "/metrics"

# Default mock zkVM config — real proving backends can be configured via
# external ere-server instances if needed.
ZKBOOST_CONFIG_TEMPLATE = """\
port = {port}
el_endpoint = "http://{el_service}:{el_rpc_port}"

[[zkvm]]
kind = "mock"
mock_proving_time_ms = {mock_proving_time_ms}
mock_proof_size = {mock_proof_size}
proof_type = "reth-zisk"
"""


def run(plan, args):
    """Start ethereum-package then add zkboost-server sidecars."""

    # Split out zkboost config from ethereum-package args.
    zkboost_args = args.pop("zkboost", None)
    if zkboost_args == None:
        fail("Missing required 'zkboost' key in args file.")

    # Run the standard ethereum-package with the remaining args.
    # Grafana dashboards are provisioned via grafana_params.additional_dashboards
    # in the args file — static JSON files in ./dashboards/ that already have
    # the correct datasource UID (PBFA97CFB590B2093) hardcoded in every panel.
    ethereum_package.run(plan, args)

    # Extract zkboost settings with defaults.
    zkboost_image = zkboost_args.get("image", "ghcr.io/eth-act/zkboost/zkboost-server:1715344")
    instances = zkboost_args.get("instances", [])
    mock_proving_time_ms = zkboost_args.get("mock_proving_time_ms", 5000)
    mock_proof_size = zkboost_args.get("mock_proof_size", 1024)
    el_rpc_port = zkboost_args.get("el_rpc_port", 8545)

    if len(instances) == 0:
        fail("zkboost.instances must contain at least one entry.")

    for instance in instances:
        name = instance["name"]
        el_service = instance["el_service"]

        config_content = ZKBOOST_CONFIG_TEMPLATE.format(
            port = ZKBOOST_PORT_NUMBER,
            el_service = el_service,
            el_rpc_port = el_rpc_port,
            mock_proving_time_ms = mock_proving_time_ms,
            mock_proof_size = mock_proof_size,
        )

        config_artifact = plan.render_templates(
            name = name + "-config",
            config = {
                "config.toml": struct(
                    template = config_content,
                    data = {},
                ),
            },
        )

        plan.add_service(
            name = name,
            config = ServiceConfig(
                image = zkboost_image,
                cmd = ["--config", "/app/config.toml"],
                ports = {
                    ZKBOOST_PORT_ID: PortSpec(
                        number = ZKBOOST_PORT_NUMBER,
                        transport_protocol = "TCP",
                        application_protocol = "http",
                    ),
                },
                files = {
                    "/app": config_artifact,
                },
                env_vars = {
                    "RUST_LOG": "info,zkboost=debug",
                },
            ),
        )

        plan.print("Started zkboost service '{0}' -> EL '{1}'".format(name, el_service))

        # Register this zkboost instance as a Prometheus scrape target.
        # The ethereum-package deploys Prometheus with --web.enable-lifecycle, so
        # we append a new job to its config and trigger a hot reload via the API.
        # We use a heredoc (with quoted delimiter 'EOF' to suppress variable
        # expansion) so that names containing hyphens or other special chars are
        # written literally without any shell-quoting problems.
        plan.exec(
            service_name = "prometheus",
            recipe = ExecRecipe(
                command = [
                    "/bin/sh", "-c",
                    """cat >> /config/prometheus-config.yml << 'EOF'
- job_name: {name}
  metrics_path: {metrics_path}
  scrape_interval: 15s
  static_configs:
    - targets:
        - {name}:{port}
      labels:
        service: {name}
        el_service: {el_service}
EOF
wget -q -O /dev/null --post-data '' http://localhost:9090/-/reload""".format(
                        name = name,
                        port = ZKBOOST_PORT_NUMBER,
                        el_service = el_service,
                        metrics_path = ZKBOOST_METRICS_PATH,
                    ),
                ],
            ),
        )
