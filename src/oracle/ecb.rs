#![macro_use]
use alloc::vec;
use alloc::vec::Vec;

use rand::{thread_rng, Rng};

use craes::{aes, cbc, ecb, pkcs7};

use crate::encoding;

use super::{add_random_bytes, gen_rand_bytes, gen_rand_iv, gen_rand_key, AesMode, Error};
use super::{RAND_PREFIX_HI, RAND_PREFIX_LO, UNKNOWN_B64_LEN, UNKNOWN_LEN};

// Unknown target text (Base64-encoded)
const UNKNOWN_TARGET: &[u8; UNKNOWN_B64_LEN] = b"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

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
        Ok((
            ecb::encrypt(&new_msg, &key).map_err(|e| Error::Ecb(e))?,
            AesMode::Ecb,
        ))
    } else {
        Ok((
            cbc::encrypt(&new_msg, &key, &iv).map_err(|e| Error::Cbc(e))?,
            AesMode::Cbc,
        ))
    }
}

/// Detect whether ECB or CBC mode is being used to encrypt
///
/// Caller should supply the oracle with a uniform message of at least three AES blocks
pub fn detect_oracle(cipher: &[u8]) -> Result<AesMode, Error> {
    if cipher.len() < aes::BLOCK_LEN * 3 {
        return Err(Error::InvalidLength);
    }

    // if the second and third ciphertext block are the same, it's ECB, otherwise CBC
    if cipher[aes::BLOCK_LEN..aes::BLOCK_LEN * 2] == cipher[aes::BLOCK_LEN * 2..aes::BLOCK_LEN * 3]
    {
        Ok(AesMode::Ecb)
    } else {
        Ok(AesMode::Cbc)
    }
}

/// Encrypt a message using AES-128-ECB
pub fn ecb_oracle(msg: &[u8], key: &[u8; aes::KEY_LEN_128]) -> Result<Vec<u8>, Error> {
    let unk = encoding::from_base64(UNKNOWN_TARGET.as_ref()).map_err(|e| Error::Base64(e))?;

    ecb::encrypt(&pkcs7::pad([msg, unk.as_ref()].concat().as_ref()), &key)
        .map_err(|e| Error::Ecb(e))
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
    let mut res = Vec::with_capacity(UNKNOWN_LEN);

    for ciph_idx in 1..UNKNOWN_LEN {
        // the current block number
        let block = ciph_idx / aes::BLOCK_LEN;
        let attempt_len = aes::BLOCK_LEN * (block + 1);

        // supply next attempt that is ciph_idx bytes short
        // places the next byte of the unknown plaintext at the end of our string
        let short_attempt = vec![0x41; attempt_len - ciph_idx];
        let short_ciph = ecb_oracle(&short_attempt, &key).unwrap()[..attempt_len].to_vec();

        // decrypt next byte
        for b in 0x00..=0xff {
            let mut attempt = vec![0x41; attempt_len - ciph_idx];

            // append known bytes
            attempt.extend_from_slice(res.as_ref());

            // append next guess
            attempt.push(b);

            // get next ciphertext from the ECB oracle
            let ciph = ecb_oracle(&attempt, &key).unwrap()[..attempt_len].to_vec();

            // found the byte that matches the next byte of the target text
            if ciph == short_ciph {
                res.push(b);
                break;
            }
        }
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

        Self {
            key: key,
            prefix: prefix,
            target: target,
        }
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
    #[allow(dead_code)]
    pub fn prefix_len(&self) -> usize {
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
    for len in 1..aes::BLOCK_LEN * 3 {
        let attempt = vec![0x41; len];
        let ciph = oracle.encrypt(&attempt)?;

        // ciphertext guaranteed to be a multiple of AES block length
        let num_blocks = ciph.len() / aes::BLOCK_LEN;

        // look for the first two identical blocks
        for i in 0..num_blocks - 1 {
            let block = &ciph[aes::BLOCK_LEN * i..aes::BLOCK_LEN * (i + 1)];
            let next_block = &ciph[aes::BLOCK_LEN * (i + 1)..aes::BLOCK_LEN * (i + 2)];
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
    let extra = ident_len - aes::BLOCK_LEN * 2;

    Ok(aes::BLOCK_LEN * ident_block - extra)
}

/// Decrypt ECB oracle one byte at a time (hard)
pub fn decrypt_ecb_oracle_hard(oracle: &RandEcbOracle) -> Result<Vec<u8>, Error> {
    let mut res = Vec::with_capacity(UNKNOWN_LEN);

    // guess the prefix length to start solving at the next block
    let prefix_len = guess_prefix_len(&oracle)?;
    let extra_len = aes::BLOCK_LEN - (prefix_len % aes::BLOCK_LEN);
    let full_prefix = prefix_len + extra_len;

    for ciph_idx in 1..UNKNOWN_LEN {
        // the current block number
        let block = ciph_idx / aes::BLOCK_LEN;
        // add extra padding to account for the prefix
        let attempt_len = aes::BLOCK_LEN * (block + 1) + extra_len;

        // supply next attempt that is ciph_idx bytes short
        // places the next byte of the unknown plaintext at the end of our string
        let short_attempt = vec![0x41; attempt_len - ciph_idx];
        let short_ciph =
            oracle.encrypt(&short_attempt).unwrap()[full_prefix..prefix_len + attempt_len].to_vec();

        // decrypt next byte
        for b in 0x00..=0xff {
            let mut attempt = vec![0x41; attempt_len - ciph_idx];

            // append known bytes
            attempt.extend_from_slice(res.as_ref());

            // append next guess
            attempt.push(b);

            // get next ciphertext from the ECB oracle, ignore prefix block(s)
            let ciph =
                oracle.encrypt(&attempt).unwrap()[full_prefix..prefix_len + attempt_len].to_vec();

            // found the byte that matches the next byte of the target text
            if ciph == short_ciph {
                res.push(b);
                break;
            }
        }
    }

    Ok(res)
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
