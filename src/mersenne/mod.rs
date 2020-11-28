pub mod mt19937;
pub mod mt19937_64;

mod recovery;

pub use recovery::*;

#[derive(Debug)]
pub enum Error {
    InvalidIndex,
}
