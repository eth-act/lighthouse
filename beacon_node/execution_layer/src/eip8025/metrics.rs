pub use metrics::*;
use std::sync::LazyLock;

// ── Label constants ───────────────────────────────────────────────────────────

pub const VALID: &str = "valid";
pub const INVALID: &str = "invalid";
pub const BUFFERED: &str = "buffered";
pub const ERROR: &str = "error";
pub const SUCCESS: &str = "success";

// ── Proof engine counters ─────────────────────────────────────────────────────

/// Total proof generation requests sent to the proof node, labelled by proof type.
pub static PROOF_ENGINE_REQUESTS_TOTAL: LazyLock<Result<IntCounterVec>> = LazyLock::new(|| {
    try_create_int_counter_vec(
        "proof_engine_requests_total",
        "Total proof generation requests sent to the proof node",
        &["proof_type"],
    )
});

/// Total proof verification attempts, labelled by proof type and outcome
/// (`valid`, `invalid`, `buffered`, `error`).
pub static PROOF_ENGINE_VERIFICATIONS_TOTAL: LazyLock<Result<IntCounterVec>> =
    LazyLock::new(|| {
        try_create_int_counter_vec(
            "proof_engine_verifications_total",
            "Total proof verification attempts by outcome",
            &["proof_type", "status"],
        )
    });

/// Total `forkchoice_updated` calls, labelled by outcome (`success`, `error`).
pub static PROOF_ENGINE_FORKCHOICE_UPDATES_TOTAL: LazyLock<Result<IntCounterVec>> =
    LazyLock::new(|| {
        try_create_int_counter_vec(
            "proof_engine_forkchoice_updates_total",
            "Total forkchoice_updated calls by outcome",
            &["status"],
        )
    });

/// Total `new_payload` calls processed by the proof engine.
pub static PROOF_ENGINE_NEW_PAYLOADS_TOTAL: LazyLock<Result<IntCounter>> = LazyLock::new(|| {
    try_create_int_counter(
        "proof_engine_new_payloads_total",
        "Total new_payload calls processed by the proof engine",
    )
});

// ── Proof engine gauges ───────────────────────────────────────────────────────

/// Current number of proofs held in the pre-request buffer (request root not yet seen).
pub static PROOF_ENGINE_BUFFERED_PROOF_COUNT: LazyLock<Result<IntGauge>> = LazyLock::new(|| {
    try_create_int_gauge(
        "proof_engine_buffered_proof_count",
        "Proofs buffered awaiting their new_payload request root",
    )
});

/// Current number of requests tracked in the proof engine state tree.
pub static PROOF_ENGINE_TREE_SIZE: LazyLock<Result<IntGauge>> = LazyLock::new(|| {
    try_create_int_gauge(
        "proof_engine_tree_size",
        "Number of payload requests currently tracked in the proof engine state tree",
    )
});

/// Current number of payload requests in the proof engine buffer awaiting promotion.
pub static PROOF_ENGINE_BUFFER_SIZE: LazyLock<Result<IntGauge>> = LazyLock::new(|| {
    try_create_int_gauge(
        "proof_engine_buffer_size",
        "Number of payload requests in the proof engine buffer awaiting promotion",
    )
});

/// Current number of payload requests with insufficient proofs for promotion.
pub static PROOF_ENGINE_MISSING_PROOF_COUNT: LazyLock<Result<IntGauge>> = LazyLock::new(|| {
    try_create_int_gauge(
        "proof_engine_missing_proof_count",
        "Number of payload requests currently missing sufficient proofs",
    )
});

// ── Proof engine histograms ───────────────────────────────────────────────────

/// Duration of `verify_execution_proof` calls, labelled by proof type.
pub static PROOF_ENGINE_VERIFICATION_DURATION: LazyLock<Result<HistogramVec>> =
    LazyLock::new(|| {
        try_create_histogram_vec_with_buckets(
            "proof_engine_verification_duration_seconds",
            "Duration of proof verification calls",
            decimal_buckets(-3, 1),
            &["proof_type"],
        )
    });
