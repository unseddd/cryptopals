use alloc::vec::Vec;
use rand::{thread_rng, Rng};

/// Secret-prefix MAC implementation using MD4
pub struct Md4SecretMac {
    key: u128,
}

impl Md4SecretMac {
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
    /// Prepends the message with the secret key, before calculating the MD4 digest
    pub fn mac(&self, msg: &[u8]) -> Result<[u8; bmd4::DIGEST_LEN], bmd4::Error> {
        let mut input: Vec<u8> = Vec::with_capacity(msg.len() + core::mem::size_of_val(&self.key));

        input.extend_from_slice(self.key.to_le_bytes().as_ref());
        input.extend_from_slice(&msg);

        let mut md4 = bmd4::Md4::new();
        md4.update(&input)?;
        md4.finalize() 
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
        mac: &[u8; bmd4::DIGEST_LEN],
        total_len: u64,
    ) -> Result<[u8; bmd4::DIGEST_LEN], bmd4::Error> {
        let mut md4 = bmd4::Md4::from_digest(mac);

        md4.update(&msg)?;

        md4.finalize_insecure(total_len)
    }
}

