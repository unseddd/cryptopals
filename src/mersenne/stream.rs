use alloc::vec::Vec;

use crate::bytes::xor_assign;

use super::mt19937::*;

// Size of MT19937 output in bytes
const BLOCK_LEN: usize = 4;

pub struct Cipher {
    key: u16,
}

impl Cipher {
    /// Create a new stream cipher from a 16-bit "key"
    pub fn new(key: u16) -> Self {
        Self { key: key }
    }

    /// Encrypt a given message using MT19937 as a keystream generator
    ///
    /// Count is an offset from the initial state
    ///
    /// A zero count starts from a fresh PRNG, while 32 generates the first 32 outputs
    ///
    /// The next output after count is used as the first keystream bytes
    pub fn encrypt(&self, msg: &[u8], count: u32) -> Vec<u8> {
        self.cipher_inner(msg, count)
    }

    /// Decrypt a given ciphertext using MT19937 as a keystream generator
    ///
    /// Count is an offset from the initial state
    ///
    /// A zero count starts from a fresh PRNG, while 32 generates the first 32 outputs
    ///
    /// The next output after count is used as the first keystream bytes
    pub fn decrypt(&self, cipher: &[u8], count: u32) -> Vec<u8> {
        self.cipher_inner(cipher, count)
    }

    fn cipher_inner(&self, text: &[u8], count: u32) -> Vec<u8> {
        let mut res = Vec::with_capacity(text.len());

        // create a fresh PRNG for deterministic outputs
        let mut rng = Mt19937::new(self.key as u32);

        // generate the first `count` outputs for keystream offset
        for _i in 0..count {
            let _ = rng.extract_number();
        }

        for block in text.chunks(BLOCK_LEN) {
            let mut keystream = rng.extract_number().to_le_bytes();
            xor_assign(&mut keystream[..block.len()], block);
            res.extend_from_slice(&keystream[..block.len()]);
        }

        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_cipher() {
        let key = 1337;
        let count = 42;
        let msg = b"kill me quick, in the nightshade, with the candlestick";

        let cipher = Cipher::new(key);
        let ciphertext = cipher.encrypt(msg.as_ref(), count);
        let plaintext = cipher.decrypt(ciphertext.as_slice(), count);

        assert_eq!(plaintext.as_slice(), msg.as_ref());
    }
}
