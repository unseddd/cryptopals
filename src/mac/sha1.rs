use alloc::vec::Vec;
use rand::{thread_rng, Rng};

/// Secret-prefix MAC implementation using SHA-1
pub struct Sha1SecretMac {
    key: u128,
}

impl Sha1SecretMac {
    /// Create a new secret-prefix MAC producer
    pub fn new() -> Self {
        Self {
            key: thread_rng().gen_range::<u128, u128, u128>(1, core::u128::MAX),
        }
    }

    /// Convenience function to create a MAC producer from a given key
    pub fn from_key(key: u128) -> Self {
        Self { key: key }
    }

    /// Calculate a secret-prefix MAC over the given message
    ///
    /// Prepends the message with the secret key, before calculating the SHA-1 digest
    pub fn mac(&self, msg: &[u8]) -> Result<[u8; isha1::DIGEST_LEN], isha1::Error> {
        let mut input: Vec<u8> = Vec::with_capacity(msg.len() + core::mem::size_of_val(&self.key));

        input.extend_from_slice(self.key.to_le_bytes().as_ref());
        input.extend_from_slice(&msg);

        isha1::Sha1::digest(&input)
    }

    /// Calculates a secret-prefix MAC over the given message
    ///
    /// Initializes the SHA-1 state from the given MAC
    /// For Cryptopals challenge 29, NEVER do this in practice
    ///
    /// Simulates manipulating SHA-1 state with "glue padding" in a real attack
    pub fn mac_from_mac(
        &self,
        msg: &[u8],
        mac: &[u8; isha1::DIGEST_LEN],
        total_len: u64,
    ) -> Result<[u8; isha1::DIGEST_LEN], isha1::Error> {
        let mut sha = isha1::Sha1::from_digest(mac);

        sha.input(&msg)?;

        sha.finalize_insecure(total_len)
    }
}
