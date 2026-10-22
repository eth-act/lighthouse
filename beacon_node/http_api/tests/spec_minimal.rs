#![cfg(not(debug_assertions))] // Tests are too slow in debug.

pub mod execution_proof_tests;
pub mod fork_tests;
pub mod gloas_reorg_tests;
pub mod interactive_tests_minimal;
pub mod status_tests;
