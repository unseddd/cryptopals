#![no_std]

extern crate alloc;

/// Tools for AES-128-CTR related challenges
pub mod ctr;

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

/// Mersenne Twister (32- and 64-bit) based on Wikipedia pseudocode,
/// and the original algorithm from Matsumoto and Nishimura
pub mod mersenne;

/// Encryption oracle and detection of which AES mode the oracle used for encryption
pub mod oracle;

/// User profile functions
pub mod user;

#[cfg(test)]
mod tests {}
