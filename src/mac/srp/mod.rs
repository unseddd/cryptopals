use num::bigint::BigUint;

use crate::dh;

mod full;
mod simple;

/// "Full" Secure Remote Password implementation
pub use full::*;

/// Simplified Secure Remote Password implementation
pub use simple::*;

// Shared constant used to generate/validate client challenges
const K: u8 = 3;

/// Successful login message
pub const SUCCESSFUL_LOGIN: &'static str = "Welcome to the System!";

/// Failed login message
pub const FAILED_LOGIN: &'static str = "You hackin' muh shit, bruh?";

/// Secure Remote Password errors
#[derive(Debug)]
pub enum Error {
    Sha256(isha2::Error),
    DiffieHellman(dh::Error),
    AlreadyRegistered,
    FailedLogin(&'static str),
    InvalidEmail,
    InvalidPassword,
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
