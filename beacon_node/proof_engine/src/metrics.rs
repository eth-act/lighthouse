pub use metrics::*;
use std::sync::LazyLock;

pub static EXECUTION_PROOF_ENGINE_VERIFICATION_SECONDS: LazyLock<Result<HistogramVec>> =
    LazyLock::new(|| {
        try_create_histogram_vec_with_buckets(
            "beacon_execution_proof_engine_verification_seconds",
            "Time spent verifying execution proofs in the proof engine by proof type, outcome, and error type.",
            decimal_buckets(-3, 1),
            &["proof_type", "outcome", "error_type"],
        )
    });
