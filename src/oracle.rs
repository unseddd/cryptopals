#![macro_use]
use alloc::vec;
use alloc::vec::Vec;

use rand::{Rng, RngCore, thread_rng};
use rand::rngs::ThreadRng;

use craes::{aes, ecb, cbc, pkcs7};
use crate::encoding;

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

// Unknown target text (Base64-encoded)
const UNKNOWN_TARGET: &[u8; UNKNOWN_B64_LEN] = b"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

/// Errors for Oracle and Oracle Detection
#[derive(Debug)]
pub enum Error {
    Base64(encoding::Error),
    InvalidLength,
    InvalidRange,
    Ecb(ecb::Error),
    Cbc(cbc::Error),
}

/// Generate a random AES-128 key
pub fn gen_rand_key(rng: &mut ThreadRng) -> [u8; aes::KEY_LEN_128] {
    let mut key = [0_u8; aes::KEY_LEN_128];
    rng.fill_bytes(&mut key);
    key 
}

/// Generate a random AES-128-CBC IV
pub fn gen_rand_iv(rng: &mut ThreadRng) -> [u8; cbc::IV_LEN] {
    let mut iv = [0_u8; cbc::IV_LEN];
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

/// Mode of AES used to encrypt a message
#[derive(Debug, PartialEq)]
pub enum AesMode {
    Ecb,
    Cbc,
}

/// Encrypt a message under ECB or CBC with a 50% chance
///
/// 5-10 random bytes prepended to the message
/// 5-10 random bytes appended to the message
///
/// The counts of prepended and appended bytes are independent
///
/// The key and IV (for CBC) are randomly generated
///
/// Returns the ciphertext and mode used (for testing/debugging)
pub fn oracle(msg: &[u8]) -> Result<(Vec<u8>, AesMode), Error> {
    let mut rng = thread_rng();

    let key = gen_rand_key(&mut rng);
    let iv = gen_rand_iv(&mut rng);

    let new_msg = pkcs7::pad(&add_random_bytes(&msg, &mut rng));

    // encrypt under ECB or CBC with a 50% chance
    if rng.gen_bool(0.50_f64) {
        Ok((ecb::encrypt(&new_msg, &key).map_err(|e| Error::Ecb(e))?, AesMode::Ecb))
    } else {
        Ok((cbc::encrypt(&new_msg, &key, &iv).map_err(|e| Error::Cbc(e))?, AesMode::Cbc))
    }
}

/// Detect whether ECB or CBC mode is being used to encrypt
///
/// Caller should supply the oracle with a uniform message of at least three AES blocks
pub fn detect_oracle(cipher: &[u8]) -> Result<AesMode, Error> {
    if cipher.len() < aes::BLOCK_LEN * 3 {
        return Err(Error::InvalidLength)
    }

    // if the second and third ciphertext block are the same, it's ECB, otherwise CBC
    if cipher[aes::BLOCK_LEN..aes::BLOCK_LEN*2] == cipher[aes::BLOCK_LEN*2..aes::BLOCK_LEN*3] {
        Ok(AesMode::Ecb)
    } else {
        Ok(AesMode::Cbc)
    }
}

/// Encrypt a message using AES-128-ECB
pub fn ecb_oracle(msg: &[u8], key: &[u8; aes::KEY_LEN_128]) -> Result<Vec<u8>, Error> {
    let unk = encoding::from_base64(UNKNOWN_TARGET.as_ref()).map_err(|e| Error::Base64(e))?;

    ecb::encrypt(&pkcs7::pad([msg, unk.as_ref()].concat().as_ref()), &key).map_err(|e| Error::Ecb(e))
}

/// Detect the block size of the ECB oracle
///
/// Already known, but our cryptopals want us to do this for reasons(tm)
pub fn detect_block_size() -> Result<usize, Error> {
    let key = gen_rand_key(&mut thread_rng());

    let mut last_attempt: Vec<u8> = Vec::new();

    // search in arbitrary range (no block ciphers use 128-byte blocks)
    for size in 1..=128 {
        let a = vec![0x41_u8; size];

        // encrypt our test string using the ECB oracle
        let out = ecb_oracle(&a, &key)?;

        if last_attempt.len() == 0 {
            // this is our first attempt, assign the ciphertext and continue
            last_attempt = out;
        } else if last_attempt[..size - 1] == out[..size - 1] {
            // our last attempt was the cipher's block length
            return Ok(size - 1);
        } else {
            // we haven't found the block length, assign the ciphertext and continue
            last_attempt = out;
        }
    }

    Err(Error::InvalidLength)
}

/// Decrypt ECB oracle one byte at a time (simple)
pub fn decrypt_ecb_oracle_simple(key: &[u8; aes::BLOCK_LEN]) -> Result<Vec<u8>, Error> {
    use hashbrown::HashMap;

    let mut res = Vec::with_capacity(UNKNOWN_LEN);

    // Build a dictionary of all possible ciphertexts, up to the unknown message length
    let mut dictionary: HashMap<Vec<u8>, u8> = HashMap::new();

    for ciph_idx in 1..UNKNOWN_LEN {
        // the current block number
        let block = ciph_idx / aes::BLOCK_LEN;
        let attempt_len = aes::BLOCK_LEN * (block + 1);

        // decrypt next byte
        for b in 0x00..=0xff {
            let mut attempt = vec![0x41; attempt_len - ciph_idx];

            // append known bytes
            attempt.extend_from_slice(res.as_ref());

            // append next guess
            attempt.push(b);

            // get next ciphertext from the ECB oracle
            let ciph = ecb_oracle(&attempt, &key).unwrap()[..attempt_len].to_vec();

            // add the guess entry to the dictionary
            dictionary.insert(ciph, b);
        }

        // supply next attempt that is ciph_idx bytes short
        // places the next byte of the unknown plaintext at the end of our string
        let attempt = vec![0x41; attempt_len - ciph_idx];
        let ciph = ecb_oracle(&attempt, &key).unwrap()[..attempt_len].to_vec();

        // add the entry in our dictionary as the next decrypted byte
        res.push(dictionary[&ciph]);
    }

    Ok(res)
}

/// Random ECB oracle that encrypts a message and target text, prepended by a random string
///
/// AES-128-ECB(rand_prefix | message | target text, rand_key)
pub struct RandEcbOracle {
    key: [u8; aes::KEY_LEN_128],
    prefix: Vec<u8>,
    target: Vec<u8>,
}

impl RandEcbOracle {
    /// Create a new oracle, generating a random prefix and key
    pub fn new() -> Self {
        let mut rng = thread_rng();

        let key = gen_rand_key(&mut rng);

        // range is valid, cannot panic
        let prefix = gen_rand_bytes(&mut rng, RAND_PREFIX_LO, RAND_PREFIX_HI).unwrap();

        // unknown target is valid Base64. If panic occurs, some serious shit went wrong
        let target = encoding::from_base64(UNKNOWN_TARGET.as_ref()).unwrap();

        Self { key: key, prefix: prefix, target: target }
    }

    /// Random oracle, encrypts the message with the oracle's key
    ///
    /// The oracle's random prefix (fixed after creation) is prepended to the plaintext.
    ///
    /// The target message is appended to the end of the message.
    pub fn encrypt(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        let plaintext = [&self.prefix, msg, &self.target].concat();

        ecb::encrypt(&pkcs7::pad(&plaintext), &self.key).map_err(|e| Error::Ecb(e))
    }

    // convenience function for testing
    fn prefix_len(&self) -> usize {
        self.prefix.len()
    }
}

/// Guess the length of the ECB oracle
pub fn guess_prefix_len(oracle: &RandEcbOracle) -> Result<usize, Error> {
    let mut ident_block = 0_usize;
    let mut ident_len = 0_usize;

    // add a byte to attempt message, until two identical blocks are found
    // no more than three blocks is needed
    // up to one block to fill the last prefix block, then two block for ident
    for len in 1..aes::BLOCK_LEN*3 {
        let attempt = vec![0x41; len];
        let ciph = oracle.encrypt(&attempt)?;

        // ciphertext guaranteed to be a multiple of AES block length
        let num_blocks = ciph.len() / aes::BLOCK_LEN;

        // look for the first two identical blocks
        for i in 0..num_blocks-1 {
            let block = &ciph[aes::BLOCK_LEN*i..aes::BLOCK_LEN*(i+1)];
            let next_block = &ciph[aes::BLOCK_LEN*(i+1)..aes::BLOCK_LEN*(i+2)];
            if block == next_block {
                ident_block = i;
                ident_len = len;
                break;
            }
        }

        if ident_len != 0 {
            break;
        }
    }

    // the length needed to pad the last block of prefix
    let extra = ident_len - aes::BLOCK_LEN*2;

    Ok(aes::BLOCK_LEN*ident_block - extra)
}

/// Decrypt ECB oracle one byte at a time (hard)
pub fn decrypt_ecb_oracle_hard(oracle: &RandEcbOracle) -> Result<Vec<u8>, Error> {
    use hashbrown::HashMap;

    let mut res = Vec::with_capacity(UNKNOWN_LEN);

    // Build a dictionary of all possible ciphertexts, up to the unknown message length
    let mut dictionary: HashMap<Vec<u8>, u8> = HashMap::new();

    // guess the prefix length to start solving at the next block
    let prefix_len = guess_prefix_len(&oracle)?;
    let extra_len = aes::BLOCK_LEN - (prefix_len % aes::BLOCK_LEN);
    let full_prefix = prefix_len + extra_len;

    for ciph_idx in 1..UNKNOWN_LEN {
        // the current block number
        let block = ciph_idx / aes::BLOCK_LEN;
        // add extra padding to account for the prefix
        let attempt_len = aes::BLOCK_LEN * (block + 1) + extra_len;

        // decrypt next byte
        for b in 0x00..=0xff {
            let mut attempt = vec![0x41; attempt_len - ciph_idx];

            // append known bytes
            attempt.extend_from_slice(res.as_ref());

            // append next guess
            attempt.push(b);

            // get next ciphertext from the ECB oracle, ignore prefix block(s)
            let ciph = oracle.encrypt(&attempt).unwrap()[full_prefix..prefix_len+attempt_len].to_vec();

            // add the guess entry to the dictionary
            dictionary.insert(ciph, b);
        }

        // supply next attempt that is ciph_idx bytes short
        // places the next byte of the unknown plaintext at the end of our string
        let attempt = vec![0x41; attempt_len - ciph_idx];
        let ciph = oracle.encrypt(&attempt).unwrap()[full_prefix..prefix_len+attempt_len].to_vec();

        // add the entry in our dictionary as the next decrypted byte
        res.push(dictionary[&ciph]);
    }

    Ok(res)
}

/// Ciphertext and key material output by the CBC oracle
pub struct CbcOracleOutput {
    pub ciphertext: Vec<u8>,
    pub key: [u8; aes::KEY_LEN_128],
    pub iv: [u8; cbc::IV_LEN],
}

/// CBC oracle to encrypt user data under a random key and IV
///
/// Prepends a fixed key-value data string
/// Appends another fixed key-value data string
///
/// Quotes out ";" and "=" metacharacters from user-input
pub fn cbc_oracle(user_data: &[u8]) -> Result<CbcOracleOutput, Error> {
    let mut plaintext = b"comment1=cooking%20MCs;userdata=".to_vec();

    let msg: Vec<u8> = user_data.iter()
        .filter(|&&b| b != SEMICOLON && b != EQUAL)
        .map(|&b| b)
        .collect();

    let suffix = b";comment2=%20like%20a%20pound%20of%20bacon";

    plaintext.extend_from_slice(&msg);
    plaintext.extend_from_slice(&suffix[..]);

    let mut rng = thread_rng();

    let key = gen_rand_key(&mut rng);
    let iv = gen_rand_iv(&mut rng);

    let cipher = cbc::encrypt(&pkcs7::pad(&plaintext), &key, &iv)
        .map_err(|e| Error::Cbc(e))?;

    Ok(CbcOracleOutput { ciphertext: cipher, key: key, iv: iv })
}

pub fn cbc_oracle_found_admin(output: &CbcOracleOutput) -> Result<bool, Error> {
    let plaintext = cbc::decrypt(&output.ciphertext, &output.key, &output.iv)
        .map_err(|e| Error::Cbc(e))?;

    let target = b";admin=true;";

    for chunk in plaintext.chunks_exact(target.len()) {
        if &chunk == &target {
            return Ok(true);
        }
    }

    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_guess_prefix_len() {
        for _i in 0..10 {
            let oracle = RandEcbOracle::new();
            assert_eq!(guess_prefix_len(&oracle).unwrap(), oracle.prefix_len());
        }
    }
}
