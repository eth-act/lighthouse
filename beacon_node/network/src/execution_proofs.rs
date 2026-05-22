use execution_layer::eip8025::types::ProofTypes;
use ssz_types::VariableList;
use types::execution::eip8025::{MaxExecutionProofsPerPayload, ProofType as ExecutionProofType};

pub(crate) struct ExecutionProofStatusProofTypes<'a>(pub &'a ProofTypes);

impl From<ExecutionProofStatusProofTypes<'_>>
    for VariableList<ExecutionProofType, MaxExecutionProofsPerPayload>
{
    fn from(proof_types: ExecutionProofStatusProofTypes<'_>) -> Self {
        proof_types
            .0
            .iter()
            .map(|proof_type| proof_type.to_u8())
            .collect::<Vec<_>>()
            .try_into()
            .expect("proof type count is validated during configuration")
    }
}
