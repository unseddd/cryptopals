pub mod mt19937;
pub mod mt19937_64;
pub mod password_token;
pub mod recovery;
pub mod stream;

#[derive(Debug)]
pub enum Error {
    InvalidIndex,
}
