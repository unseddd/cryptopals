use alloc::vec::Vec;
use rand::{Rng, thread_rng};

/// Secret-prefix MAC implementation using SHA-1
pub struct Sha1SecretMac {
    // use a rediculously short key for test purposes
    key: u8,
}

impl Sha1SecretMac {
    /// Create a new secret-prefix MAC producer
    pub fn new() -> Self {
        Self { key: thread_rng().gen_range::<u8, u8, u8>(0, 255) }
    }

    /// Convenience function to create a MAC producer from a given key
    pub fn from_key(key: u8) -> Self {
        Self { key: key }
    }

   
    /// Calculate a secret-prefix MAC over the given message
    ///
    /// Prepends the message with the secret key, before calculating the SHA-1 digest
    pub fn mac(&self, msg: &[u8]) -> Result<[u8; isha1::DIGEST_LEN], isha1::Error> {
        let mut input: Vec<u8> = Vec::with_capacity(msg.len() + 1);
        input.push(self.key);
        input.extend_from_slice(&msg);

        isha1::Sha1::digest(&input)
    }
}
