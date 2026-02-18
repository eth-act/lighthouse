use super::*;
use task_executor::TaskExecutor;

pub struct TestEnvironment<E: EthSpec> {
    pub executor: TaskExecutor,
    pub signal_rx: Option<Receiver<ShutdownReason>>,
    pub signal: Option<async_channel::Sender<()>>,
    pub sse_logging_components: Option<SSELoggingComponents>,
    pub eth_spec_instance: E,
    pub eth2_config: Eth2Config,
    pub eth2_network_config: Option<Arc<Eth2NetworkConfig>>,
}

impl<E: EthSpec> TestEnvironment<E> {
    pub fn core_context(&self) -> RuntimeContext<E> {
        RuntimeContext {
            executor: self.executor.clone(),
            eth_spec_instance: self.eth_spec_instance.clone(),
            eth2_config: self.eth2_config.clone(),
            eth2_network_config: self.eth2_network_config.clone(),
            sse_logging_components: self.sse_logging_components.clone(),
        }
    }
}
