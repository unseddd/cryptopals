#![macro_use]
use alloc::vec;
use alloc::vec::Vec;

use rand::{Rng, RngCore};
use rand::rngs::ThreadRng;

use craes::aes;

use crate::encoding;

mod ecb;
mod cbc;

pub use ecb::*;
pub use cbc::*;

// Upper limit for random ECB oracle padding (chal. 12)
const RAND_LIMIT_HI: usize = 10;
// Lower limit for random ECB oracle padding (chal. 12)
const RAND_LIMIT_LO: usize = 5;

// Upper limit for random ECB oracle prefix (chal. 14)
const RAND_PREFIX_HI: usize = 32;
// Lower limit for random ECB oracle prefix (chal. 14)
const RAND_PREFIX_LO: usize = 5;

// Length of unknown target text (chal. 12 + 14)
const UNKNOWN_LEN: usize = 138;
// Length of Base64-encoded unknown target text (chal. 12 + 14)
const UNKNOWN_B64_LEN: usize = 184;

// ASCII byte value for "="
const EQUAL: u8 = 0x3d;
// ASCII byte value for ";"
const SEMICOLON: u8 = 0x3b;

/// Mode of AES used to encrypt a message
#[derive(Debug, PartialEq)]
pub enum AesMode {
    Ecb,
    Cbc,
}

/// Errors for Oracle and Oracle Detection
#[derive(Debug)]
pub enum Error {
    Base64(encoding::Error),
    InvalidLength,
    InvalidPosition,
    InvalidRange,
    Ecb(craes::ecb::Error),
    Cbc(craes::cbc::Error),
    NoDecryptionFound,
}

/// Generate a random AES-128 key
pub fn gen_rand_key(rng: &mut ThreadRng) -> [u8; aes::KEY_LEN_128] {
    let mut key = [0_u8; aes::KEY_LEN_128];
    rng.fill_bytes(&mut key);
    key
}

/// Generate a random AES-128-CBC IV
pub fn gen_rand_iv(rng: &mut ThreadRng) -> [u8; craes::cbc::IV_LEN] {
    let mut iv = [0_u8; craes::cbc::IV_LEN];
    rng.fill_bytes(&mut iv);
    iv
}

/// Generate random bytes in the provided range
pub fn gen_rand_bytes(rng: &mut ThreadRng, lo: usize, hi: usize) -> Result<Vec<u8>, Error> {
    if lo == 0 || hi == 0 || lo >= hi {
        return Err(Error::InvalidRange);
    }

    let len = rng.gen_range::<usize, usize, usize>(lo, hi);
    let mut bytes = vec![0_u8; len];

    rng.fill(bytes.as_mut_slice());

    Ok(bytes)
}

// Add random bytes before and after the provided message
fn add_random_bytes(msg: &[u8], rng: &mut ThreadRng) -> Vec<u8> {
    let front_cnt = rng.gen_range::<usize, usize, usize>(RAND_LIMIT_LO, RAND_LIMIT_HI);
    let back_cnt = rng.gen_range::<usize, usize, usize>(RAND_LIMIT_LO, RAND_LIMIT_HI);

    let mut front_bytes = vec![0_u8; front_cnt];
    let mut back_bytes = vec![0_u8; back_cnt];

    rng.fill(front_bytes.as_mut_slice());
    rng.fill(back_bytes.as_mut_slice());

    front_bytes.extend_from_slice(&msg);
    front_bytes.extend_from_slice(&back_bytes);

    front_bytes
}
