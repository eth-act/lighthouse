use execution_layer::eip8025::PersistedProofEngineState;
use ssz::{Decode, Encode};
use store::{DBColumn, Error, KeyValueStoreOp, StoreConfig};
use types::Hash256;

/// Database key for persisted ProofEngine state (same pattern as FORK_CHOICE_DB_KEY).
pub const PROOF_ENGINE_DB_KEY: Hash256 = Hash256::ZERO;

/// Decompress and decode a `PersistedProofEngineState` from raw DB bytes.
pub fn decode_proof_engine_state(
    bytes: &[u8],
    store_config: &StoreConfig,
) -> Result<PersistedProofEngineState, Error> {
    let decompressed = store_config
        .decompress_bytes(bytes)
        .map_err(Error::Compression)?;
    PersistedProofEngineState::from_ssz_bytes(&decompressed).map_err(Into::into)
}

/// Encode and compress a `PersistedProofEngineState` into a DB write operation.
pub fn encode_proof_engine_state(
    state: &PersistedProofEngineState,
    store_config: &StoreConfig,
) -> Result<KeyValueStoreOp, Error> {
    let ssz_bytes = state.as_ssz_bytes();
    let compressed = store_config
        .compress_bytes(&ssz_bytes)
        .map_err(Error::Compression)?;
    Ok(KeyValueStoreOp::PutKeyValue(
        DBColumn::ProofEngine,
        PROOF_ENGINE_DB_KEY.as_slice().to_vec(),
        compressed,
    ))
}
