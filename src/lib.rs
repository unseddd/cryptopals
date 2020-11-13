#![no_std]

extern crate alloc;

/// Utilities for encoding/decoding
pub mod encoding;

/// Gauss-Jordan matrix reduction
pub mod gauss;

/// Good-Turing distribution smoothing
pub mod good_turing;

/// Various tools using Hamming distance
pub mod hamming;

/// Tools for analyzing language statistics in ciphertexts and plaintext
pub mod language;

/// Encryption oracle and detection of which AES mode the oracle used for encryption
pub mod oracle;

/// User profile functions
pub mod user;

#[cfg(test)]
mod tests {}
