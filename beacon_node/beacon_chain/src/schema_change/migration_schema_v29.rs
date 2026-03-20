use store::{DBColumn, Error, KeyValueStoreOp};
use tracing::info;
use types::Hash256;

pub const PROOF_ENGINE_DB_KEY: Hash256 = Hash256::ZERO;

/// Upgrade to v29: no-op. The new `ProofEngine` column is populated lazily at runtime.
pub fn upgrade_to_v29() -> Result<Vec<KeyValueStoreOp>, Error> {
    info!("Upgrading to v29 (ProofEngine column — no data migration needed)");
    Ok(vec![])
}

/// Downgrade from v29: delete any persisted ProofEngine state.
pub fn downgrade_from_v29() -> Result<Vec<KeyValueStoreOp>, Error> {
    info!("Downgrading from v29 (deleting ProofEngine state)");
    Ok(vec![KeyValueStoreOp::DeleteKey(
        DBColumn::ProofEngine,
        PROOF_ENGINE_DB_KEY.as_slice().to_vec(),
    )])
}
