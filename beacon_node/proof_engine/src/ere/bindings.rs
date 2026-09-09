//! Safe ownership wrapper around the minimal ERE verifier C API.

use crate::ZkvmKind;
use std::{ptr::NonNull, slice};

const ERE_OK: i32 = 0;

/// Status returned by the pinned ERE C ABI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Status {
    NullPointer,
    BadZkvmKind,
    DecodeProgramVk,
    DecodeProof,
    Verify,
    Internal,
    Unknown(i32),
}

impl Status {
    fn from_code(code: i32) -> Self {
        match code {
            1 => Self::NullPointer,
            2 => Self::BadZkvmKind,
            3 => Self::DecodeProgramVk,
            4 => Self::DecodeProof,
            5 => Self::Verify,
            6 => Self::Internal,
            code => Self::Unknown(code),
        }
    }

    pub(super) fn code(self) -> i32 {
        match self {
            Self::NullPointer => 1,
            Self::BadZkvmKind => 2,
            Self::DecodeProgramVk => 3,
            Self::DecodeProof => 4,
            Self::Verify => 5,
            Self::Internal => 6,
            Self::Unknown(code) => code,
        }
    }
}

#[repr(C)]
struct EreVerifier {
    _private: [u8; 0],
}

unsafe extern "C" {
    fn ere_verifier_new(
        zkvm_kind: u32,
        encoded_program_vk_ptr: *const u8,
        encoded_program_vk_len: usize,
        output: *mut *mut EreVerifier,
    ) -> i32;
    fn ere_verifier_verify(
        handle: *const EreVerifier,
        encoded_proof_ptr: *const u8,
        encoded_proof_len: usize,
        public_values_ptr: *mut *mut u8,
        public_values_len: *mut usize,
    ) -> i32;
    fn ere_verifier_free(handle: *mut EreVerifier);
    fn ere_bytes_free(ptr: *mut u8, len: usize);
}

pub(super) struct Verifier(NonNull<EreVerifier>);

// ERE's Rust verifier trait requires Send + Sync, and the C handle only exposes shared
// verification plus exclusive destruction after the last Arc is dropped.
unsafe impl Send for Verifier {}
unsafe impl Sync for Verifier {}

impl Verifier {
    pub(super) fn new(zkvm_kind: ZkvmKind, encoded_program_vk: &[u8]) -> Result<Self, Status> {
        let mut output = std::ptr::null_mut();
        // SAFETY: the input slice is readable for its length and `output` is writable.
        let status = unsafe {
            ere_verifier_new(
                match zkvm_kind {
                    ZkvmKind::Openvm => 0,
                    ZkvmKind::Sp1 => 1,
                    ZkvmKind::Zisk => 2,
                },
                encoded_program_vk.as_ptr(),
                encoded_program_vk.len(),
                &mut output,
            )
        };
        if status != ERE_OK {
            return Err(Status::from_code(status));
        }
        NonNull::new(output).map(Self).ok_or(Status::Internal)
    }

    pub(super) fn verify(&self, encoded_proof: &[u8]) -> Result<Vec<u8>, Status> {
        let mut output = std::ptr::null_mut();
        let mut output_len = 0;
        // SAFETY: the handle is live, the proof slice is readable for its length, and both
        // output pointers are writable.
        let status = unsafe {
            ere_verifier_verify(
                self.0.as_ptr(),
                encoded_proof.as_ptr(),
                encoded_proof.len(),
                &mut output,
                &mut output_len,
            )
        };
        if status != ERE_OK {
            if !output.is_null() {
                // SAFETY: ERE initialized this output allocation and reports its length.
                unsafe { ere_bytes_free(output, output_len) };
            }
            return Err(Status::from_code(status));
        }
        if output.is_null() {
            return (output_len == 0).then(Vec::new).ok_or(Status::Internal);
        }

        // SAFETY: ERE returned a readable allocation of exactly `output_len` bytes.
        let public_values = unsafe { slice::from_raw_parts(output, output_len) }.to_vec();
        // SAFETY: this is the exact pointer/length pair returned above and is freed once.
        unsafe { ere_bytes_free(output, output_len) };
        Ok(public_values)
    }
}

impl Drop for Verifier {
    fn drop(&mut self) {
        // SAFETY: the handle is live, uniquely owned by this value, and dropped once.
        unsafe { ere_verifier_free(self.0.as_ptr()) };
    }
}

#[cfg(test)]
mod tests {
    use super::Status;

    #[test]
    fn decodes_ere_status_codes() {
        let statuses = [
            (1, Status::NullPointer),
            (2, Status::BadZkvmKind),
            (3, Status::DecodeProgramVk),
            (4, Status::DecodeProof),
            (5, Status::Verify),
            (6, Status::Internal),
            (99, Status::Unknown(99)),
        ];

        for (code, expected) in statuses {
            let status = Status::from_code(code);
            assert_eq!(status, expected);
            assert_eq!(status.code(), code);
        }
    }
}
