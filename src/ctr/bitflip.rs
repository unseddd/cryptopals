use alloc::vec::Vec;

use rand::{thread_rng, Rng, RngCore};

// ASCII code for semicolon character
const SEMICOLON: u8 = 0x3b;

// ASCII code for equal sign character
const EQUAL: u8 = 0x3d;

// offset into BitFlipper plaintext/ciphertext where user data begins
const USER_OFFSET: usize = 32;

pub struct BitFlipper {
    key: [u8; craes::aes::KEY_LEN_128],
    nonce: u64,
}

impl BitFlipper {
    /// Create a new BitFlipper with a random key and nonce
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

    /// Encrypt given user data using AES-128-CTR
    ///
    /// Strip metacharacters (";", "=") from the input
    ///
    /// Surround the plaintext with application data before encryption
    ///
    /// Returns the ciphertext
    pub fn encrypt(&self, user_data: &[u8]) -> Vec<u8> {
        let mut plaintext = b"comment1=cooking%20MCs;userdata=".to_vec();

        let msg: Vec<u8> = user_data
            .iter()
            .filter(|&&b| b != SEMICOLON && b != EQUAL)
            .map(|&b| b)
            .collect();

        let suffix = b";comment2=%20like%20a%20pound%20of%20bacon";

        plaintext.extend_from_slice(&msg);
        plaintext.extend_from_slice(&suffix[..]);

        let mut count = 0;
        let mode = craes::ctr::Endian::Little;

        craes::ctr::encrypt(&plaintext, &self.key, self.nonce, &mut count, &mode)
    }

    /// Return true if the target string ";admin=true;" is found in the decrypted ciphertext
    ///
    /// Return false otherwise
    pub fn found_admin(&self, ciphertext: &[u8]) -> bool {
        let mut count = 0;
        let mode = craes::ctr::Endian::Little;

        let plaintext = craes::ctr::decrypt(&ciphertext, &self.key, self.nonce, &mut count, &mode);

        let target = b";admin=true;";

        // need to offset to the beginning of user data, since we're using a stream cipher now
        for chunk in plaintext[USER_OFFSET..].chunks_exact(target.len()) {
            if chunk == target.as_ref() {
                return true;
            }
        }

        false
    }
}
