use alloc::vec::Vec;
use core::ops::Mul;
use num::bigint::BigUint;
use num::Zero;
use rand::{thread_rng, Rng};

use isha2::Sha2;

use crate::dh;
use crate::mac::hmac_sha256;

use super::{Error, SecureRemotePassword};
use super::{FAILED_LOGIN, SUCCESSFUL_LOGIN};

/// A small "cheat" just to get the point across in Challenge 38
///
/// Pretend our user only chooses passwords from a small dictionary of words
///
/// Use these entries to crack the password
///
/// Obviously, in real-world attacks you would need a rainbow table
/// of "hashed" values (much larger than this toy example).
///
/// The idea is the same though:
///    force parameters to be weak
///    build "hashes" out of dictionary values + MitMed client parameters
///    construct forged parameters from the cracked password
///    login using forged challenge parameters
///
/// NOTE: all these passwords are shit
pub const DICTIONARY: [&'static [u8; 10]; 10] = [
    b"leb35tP4$$",
    b"1337P4$$wd",
    b"sumbadpa55",
    b"sheizaP45$",
    b"s3cureP45$",
    b"s3cureP4$$",
    b"OKyoudidnt",
    b"eV3ntryRnd",
    b"no74one5ec",
    b"ntr0pyrulz",
];

/// Simplified implementation of Secure Remote Password (SRP) server
pub struct SimpleSrpServer {
    nonce: u128,
    salt: u128,
    password_exponent: BigUint,
    private_exponent: BigUint,
    email: Vec<u8>,
}

impl SecureRemotePassword for SimpleSrpServer {
    /// Create a new Secure Remote Password server with random salt
    fn new() -> Self {
        let mut rng = thread_rng();
        Self {
            nonce: rng.gen_range::<u128, u128, u128>(0, u128::MAX),
            salt: rng.gen_range::<u128, u128, u128>(0, u128::MAX),
            password_exponent: BigUint::default(),
            private_exponent: dh::generate_secret_exp(),
            email: Vec::new(),
        }
    }

    /// Generate server "public key" sent to the client
    fn generate_public_key(&self) -> Result<BigUint, Error> {
        dh::public_key(&self.private_exponent).map_err(|e| Error::DiffieHellman(e))
    }

    /// Get the email for the Secure Remote Password
    fn email(&self) -> &[u8] {
        &self.email
    }

    /// Set the email for the Secure Remote Password
    fn set_email(&mut self, email: &[u8]) -> Result<(), Error> {
        // if this were a real implementation, do more input validation
        // here, since this is a toy, just make sure the email isn't empty
        if email.len() == 0 {
            return Err(Error::InvalidEmail);
        }

        self.email = email.to_vec();

        Ok(())
    }
}

impl SimpleSrpServer {
    /// Register a user with the SRP server
    pub fn register(&mut self, email: &[u8], password: &[u8]) -> Result<(), Error> {
        // mimic a server already having a registered user
        //
        // basically a database/server with one user entry
        if self.email.len() != 0 {
            return Err(Error::AlreadyRegistered);
        }

        self.set_email(&email)?;
        self.generate_password_exponent(&password)
    }

    /// Login to the SRP server
    pub fn login(
        &self,
        email: &[u8],
        client_public_key: &BigUint,
        challenge: &[u8; isha2::sha256::DIGEST_LEN],
    ) -> Result<&'static str, Error> {
        if email != self.email {
            return Err(Error::InvalidEmail);
        }

        if self.validate_challenge(&client_public_key, &challenge)? {
            Ok(SUCCESSFUL_LOGIN)
        } else {
            Err(Error::FailedLogin(FAILED_LOGIN))
        }
    }

    // Generate the `v` exponent from the provided password
    //
    // v = G**SHA-256(salt||password) % P
    fn generate_password_exponent(&mut self, password: &[u8]) -> Result<(), Error> {
        let mut input = self.salt.to_be_bytes().to_vec();
        input.extend_from_slice(&password);

        // xH = SHA-256(salt || password)
        let xh = isha2::sha256::Sha256::digest(&input).map_err(|e| Error::Sha256(e))?;
        // x = BigUint(xH)
        let x = BigUint::from_bytes_be(&xh);

        // v = G**x % P
        self.password_exponent = dh::public_key(&x).map_err(|e| Error::DiffieHellman(e))?;

        Ok(())
    }

    /// Get the randomly generated nonce ("u")
    pub fn nonce(&self) -> u128 {
        self.nonce
    }

    /// Get the randomly generated salt
    pub fn salt(&self) -> u128 {
        self.salt
    }

    /// Generate a new random salt
    ///
    /// Only called server-side
    pub fn generate_salt(&mut self) -> u128 {
        self.salt = thread_rng().gen_range::<u128, u128, u128>(0, u128::MAX);
        self.salt
    }

    /// Validate the challenge supplied by the client
    pub fn validate_challenge(
        &self,
        client_public_key: &BigUint,
        challenge: &[u8; isha2::sha256::DIGEST_LEN],
    ) -> Result<bool, Error> {
        // check that the client has registered, and `generate_password_exponent` was called
        if self.password_exponent.is_zero() {
            return Err(Error::InvalidPassword);
        }

        let p = dh::p();
        let u = BigUint::from_bytes_be(&self.nonce.to_be_bytes());

        // S = ((A * v**u) ** b) % N
        let big_s = client_public_key
            .mul(&self.password_exponent.modpow(&u, &p))
            .modpow(&self.private_exponent, &p);

        // K = SHA-256(S)
        let big_k = isha2::sha256::Sha256::digest(&big_s.to_bytes_be()).map_err(|e| Error::Sha256(e))?;

        let gen_challenge =
            hmac_sha256(big_k.as_ref(), &self.salt.to_be_bytes()).map_err(|e| Error::Sha256(e))?;

        // constant-time comparison if the generated challenge matches the supplied challenge
        let sum: u16 = gen_challenge
            .iter()
            .zip(challenge.iter())
            .map(|(a, b)| (a ^ b) as u16)
            .sum();

        Ok(sum == 0)
    }

    /// Set the MitM parameters to make password cracking as fast as possible
    pub fn set_crack_parameters(&mut self) {
        self.private_exponent = BigUint::from_bytes_be(&[1]);
        self.salt = 0;
        self.nonce = 1;
    }

    /// Crack the password using an offline dictionary
    ///
    /// See notes for the dictionary on the contrived construction
    ///
    /// Basically, we are conceding the user picks a single word from the dictionary
    ///
    /// Not true to real life, but close enough for this toy example
    pub fn crack_password(
        &self,
        client_public_key: &BigUint,
        challenge: &[u8; isha2::sha256::DIGEST_LEN],
    ) -> Result<Vec<u8>, Error> {
        // set a maximum to not try past
        let salt_bytes = self.salt.to_be_bytes();
        let u = BigUint::from_bytes_be(self.nonce.to_be_bytes().as_ref());
        let p = dh::p();

        // naive password cracker
        for word in DICTIONARY.iter() {
            let mut input = salt_bytes.to_vec();
            input.extend_from_slice(word.as_ref());

            // xH = SHA-256(salt || password)
            let xh = isha2::sha256::Sha256::digest(&input).map_err(|e| Error::Sha256(e))?;
            // x = BigUint(xH)
            let x = BigUint::from_bytes_be(xh.as_ref());
            // v = G**x % P
            let v = dh::g().modpow(&x, &p);

            // S = ((A * v**u)**b) % P
            let big_s = client_public_key
                .mul(v)
                .modpow(&u, &p)
                .modpow(&self.private_exponent, &p)
                .to_bytes_be();

            // K = SHA-256(S)
            let big_k = isha2::sha256::Sha256::digest(&big_s).map_err(|e| Error::Sha256(e))?;

            let dig =
                hmac_sha256(big_k.as_ref(), salt_bytes.as_ref()).map_err(|e| Error::Sha256(e))?;

            // constant-time evaluate if the digests match
            let sum: u16 = dig
                .iter()
                .zip(challenge.iter())
                .map(|(a, b)| (a ^ b) as u16)
                .sum();

            if sum == 0 {
                return Ok(word.to_vec());
            }
        }

        Err(Error::InvalidPassword)
    }
}

/// Simplified implementation of Secure Remote Password (SRP) client
pub struct SimpleSrpClient {
    private_exponent: BigUint,
    email: Vec<u8>,
    password: Vec<u8>,
}

impl SecureRemotePassword for SimpleSrpClient {
    /// Create a new Secure Remote Password generator with random salt
    fn new() -> Self {
        Self {
            private_exponent: dh::generate_secret_exp(),
            email: Vec::new(),
            password: Vec::new(),
        }
    }

    /// Generate client "public key" sent to the server
    fn generate_public_key(&self) -> Result<BigUint, Error> {
        dh::public_key(&self.private_exponent).map_err(|e| Error::DiffieHellman(e))
    }

    /// Get the email for the Secure Remote Password
    fn email(&self) -> &[u8] {
        &self.email
    }

    /// Set the email for the Secure Remote Password
    fn set_email(&mut self, email: &[u8]) -> Result<(), Error> {
        // if this were a real implementation, do more input validation
        // here, since this is a toy, just make sure the email isn't empty
        if email.len() == 0 {
            return Err(Error::InvalidEmail);
        }

        self.email = email.to_vec();

        Ok(())
    }
}

impl SimpleSrpClient {
    /// Get the password for the Secure Remote Password client
    pub fn password(&self) -> &[u8] {
        &self.password
    }

    /// Set the password
    pub fn set_password(&mut self, password: &[u8]) -> Result<(), Error> {
        // if this were a real implementation, do more input validation
        // here, since this is a toy, just make sure the password isn't empty
        if password.len() == 0 {
            return Err(Error::InvalidPassword);
        }

        self.password = password.to_vec();

        Ok(())
    }

    /// Generate the client challenge
    ///
    /// No need to keep the salt client-side, since a new one should be generated each session
    pub fn generate_challenge(
        &mut self,
        server_public_key: &BigUint,
        salt: u128,
        u: u128,
    ) -> Result<[u8; isha2::sha256::DIGEST_LEN], Error> {
        let mut input = salt.to_be_bytes().to_vec();
        input.extend_from_slice(&self.password);

        // xH = SHA-256(salt || password)
        let xh = isha2::sha256::Sha256::digest(&input).map_err(|e| Error::Sha256(e))?;
        let x = BigUint::from_bytes_be(xh.as_ref());

        // a + u * x
        let mut a_plus_ux = self.private_exponent.clone();
        let u = BigUint::from_bytes_be(&u.to_be_bytes());
        a_plus_ux += &u.mul(&x);
        // S = ((B ** (a + u * x)) % P
        let big_s = server_public_key.modpow(&a_plus_ux, &dh::p());
        // K = SHA-256(S)
        let big_k = isha2::sha256::Sha256::digest(&big_s.to_bytes_be()).map_err(|e| Error::Sha256(e))?;

        // HMAC-SHA256(K, salt)
        hmac_sha256(big_k.as_ref(), salt.to_be_bytes().as_ref()).map_err(|e| Error::Sha256(e))
    }
}
