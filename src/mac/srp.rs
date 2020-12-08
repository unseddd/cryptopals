use alloc::vec::Vec;
use core::ops::{Add, Mul, Sub};
use num::bigint::BigUint;
use num::{Integer, Zero};
use rand::{thread_rng, Rng};

use crate::dh;
use crate::mac::hmac_sha256;

// Shared constant used to generate/validate client challenges
const K: u8 = 3;

/// Successful login message
pub const SUCCESSFUL_LOGIN: &'static str = "Welcome to the System!";

/// Failed login message
pub const FAILED_LOGIN: &'static str = "You hackin' muh shit, bruh?";

/// Secure Remote Password errors
#[derive(Debug)]
pub enum Error {
    Sha256(isha256::Error),
    DiffieHellman(dh::Error),
    AlreadyRegistered,
    FailedLogin(&'static str),
    InvalidEmail,
    InvalidPassword,
}

/// Implementation of Secure Remote Password (SRP) server
pub struct SrpServer {
    salt: u128,
    password_exponent: BigUint,
    private_exponent: BigUint,
    email: Vec<u8>,
}

/// Common functionality between Secure Remote Password client and server
pub trait SecureRemotePassword {
    /// Create a new Secure Remote Password implementation
    fn new() -> Self;

    /// Generate the public key for constructing/validating the client challenge
    fn generate_public_key(&self) -> Result<BigUint, Error>;

    /// Get the email for the Secure Remote Password
    fn email(&self) -> &[u8];

    /// Set the email for the Secure Remote Password
    fn set_email(&mut self, email: &[u8]) -> Result<(), Error>;
}

impl SecureRemotePassword for SrpServer {
    /// Create a new Secure Remote Password server with random salt
    fn new() -> Self {
        Self {
            salt: thread_rng().gen_range::<u128, u128, u128>(0, u128::MAX),
            password_exponent: BigUint::default(),
            private_exponent: dh::generate_secret_exp(),
            email: Vec::new(),
        }
    }

    /// Generate server "public key" sent to the client
    fn generate_public_key(&self) -> Result<BigUint, Error> {
        let pub_b = dh::public_key(&self.private_exponent).map_err(|e| Error::DiffieHellman(e))?;

        Ok(BigUint::from_bytes_be(&[K])
            .mul(&self.password_exponent)
            .add(&pub_b))
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

impl SrpServer {
    /// Generate the `v` exponent from the provided password
    ///
    /// v = G**SHA-256(salt||password) % P
    fn generate_password_exponent(&mut self, password: &[u8]) -> Result<(), Error> {
        let mut input = self.salt.to_be_bytes().to_vec();
        input.extend_from_slice(&password);

        let xh = isha256::Sha256::digest(&input).map_err(|e| Error::Sha256(e))?;
        let x = BigUint::from_bytes_be(&xh);

        self.password_exponent = dh::public_key(&x).map_err(|e| Error::DiffieHellman(e))?;

        Ok(())
    }

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
        challenge: &[u8; isha256::DIGEST_LEN],
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
        challenge: &[u8; isha256::DIGEST_LEN],
    ) -> Result<bool, Error> {
        // check that the client has been register and/or `generate_password_exponent` was called
        if self.password_exponent.is_zero() {
            return Err(Error::InvalidPassword);
        }

        let big_b = self.generate_public_key()?;

        let mut big_a_b = client_public_key.to_bytes_be();
        big_a_b.extend_from_slice(&big_b.to_bytes_be());

        // uH = SHA-256(A||B)
        let uh = isha256::Sha256::digest(&big_a_b).map_err(|e| Error::Sha256(e))?;
        let u = BigUint::from_bytes_be(uh.as_ref());

        // S = ((A * v**u) ** b) % N
        let p = dh::p();

        let big_s = client_public_key
            .mul(&self.password_exponent.modpow(&u, &p))
            .modpow(&self.private_exponent, &p);
        let big_k = isha256::Sha256::digest(&big_s.to_bytes_be()).map_err(|e| Error::Sha256(e))?;

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
}

impl SecureRemotePassword for SrpClient {
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

/// Implementation of Secure Remote Password (SRP) client
pub struct SrpClient {
    private_exponent: BigUint,
    email: Vec<u8>,
    password: Vec<u8>,
}

impl SrpClient {
    /// Get the password for the Secure Remote Password
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
    ) -> Result<[u8; isha256::DIGEST_LEN], Error> {
        let mut a_b = dh::public_key(&self.private_exponent)
            .map_err(|e| Error::DiffieHellman(e))?
            .to_bytes_be();

        a_b.extend_from_slice(&server_public_key.to_bytes_be());

        let uh = isha256::Sha256::digest(&a_b).map_err(|e| Error::Sha256(e))?;
        let u = BigUint::from_bytes_be(&uh);

        let mut input = salt.to_be_bytes().to_vec();
        input.extend_from_slice(&self.password);

        let xh = isha256::Sha256::digest(&input).map_err(|e| Error::Sha256(e))?;
        let x = BigUint::from_bytes_be(xh.as_ref());
        let k = BigUint::from_bytes_be(&[K]);

        // k * g**x mod p
        let p = dh::p();
        let kx = k.mul(dh::g().modpow(&x, &p)).mod_floor(&p);

        // a + u * x
        let mut a_plus_ux = self.private_exponent.clone();
        a_plus_ux += &u.mul(&x);
        // S = ((B - k * g**x) ** (a + u * x)) % P
        let big_s = server_public_key.sub(kx).modpow(&a_plus_ux, &p);
        // K = SHA-256(S)
        let big_k = isha256::Sha256::digest(&big_s.to_bytes_be()).map_err(|e| Error::Sha256(e))?;

        // HMAC-SHA256(K, salt)
        hmac_sha256(big_k.as_ref(), salt.to_be_bytes().as_ref()).map_err(|e| Error::Sha256(e))
    }
}
