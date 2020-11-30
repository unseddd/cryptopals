use alloc::vec::Vec;

use rand::{thread_rng, Rng, RngCore};

#[derive(Debug)]
pub enum Error {
    InvalidIndex,
}

/// Provides an API to edit an AES-128-CTR encrypted ciphertext
pub struct EditCtr {
    key: [u8; craes::aes::KEY_LEN_128],
    nonce: u64,
}

impl EditCtr {
    /// Create a new EditCtr cipher
    ///
    /// Generates a random key and nonce for ultra security(tm)
    pub fn new() -> Self {
        let mut rng = thread_rng();
        let mut key = [0_u8; craes::aes::KEY_LEN_128];

        rng.fill(&mut key);

        let nonce = rng.next_u64();

        Self {
            key: key,
            nonce: nonce,
        }
    }

    /// Encrypt a given message using AES-128-CTR
    pub fn encrypt(&self, msg: &[u8]) -> Vec<u8> {
        // could  make count random, but no real point
        let mut count = 0;
        craes::ctr::encrypt(
            &msg,
            &self.key,
            self.nonce,
            &mut count,
            &craes::ctr::Endian::Little,
        )
    }

    /// Edit the provided ciphertext
    ///
    /// Performs the single-byte edit, re-encrypts, and returns edited the ciphertext
    ///
    /// Index must be within valid range of the ciphertext
    ///
    /// NOTE: notice the intentional (insecure) lack of validation of the edit byte
    pub fn edit(&self, ciphertext: &[u8], index: usize, edit: u8) -> Result<Vec<u8>, Error> {
        if index >= ciphertext.len() {
            return Err(Error::InvalidIndex);
        }

        let count = (index / craes::aes::BLOCK_LEN) as u64;
        let mut input = [0_u8; craes::aes::BLOCK_LEN];

        input[..craes::ctr::NONCE_LEN].copy_from_slice(self.nonce.to_le_bytes().as_ref());

        let keystream =
            craes::ctr::ctr_inner_cipher(&mut input, &self.key, count, &craes::ctr::Endian::Little);
        let key_byte = keystream[index % craes::aes::BLOCK_LEN];

        let mut out = ciphertext.to_vec();

        out[index] = key_byte ^ edit;

        Ok(out)
    }
}
