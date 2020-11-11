#![macro_use]
use alloc::{vec, vec::Vec};

use crate::encoding::{xor, Error as XORError};

/// Maximum key length used for guessing Vigenere key length
const MAX_KEY_LENGTH: usize = 128;

#[derive(Debug, PartialEq)]
pub enum Error {
    BlockLength,
    GuessLength,
    Xor(XORError),
}

/// Find the hamming distance between two byte slices
pub fn hamming_distance(left: &[u8], right: &[u8]) -> Result<u64, Error> {
    Ok(xor(left, right)
        .map_err(|e| Error::Xor(e))?
        .iter()
        .map(|x| x.count_ones() as u64)
        .sum())
}

/// Guess the key length based on the two key-length groups with the lowest Hamming distance
pub fn guess_key_length(bytes: &[u8], start_len: usize) -> Result<usize, Error> {
    let bytes_len = bytes.len();
    if bytes_len < MAX_KEY_LENGTH * 4 || start_len >= bytes_len || start_len >= MAX_KEY_LENGTH {
        return Err(Error::GuessLength);
    }

    let mut best_guess = 0.0_f64;
    let mut res = MAX_KEY_LENGTH;

    for i in start_len..MAX_KEY_LENGTH {
        let guess = (hamming_distance(&bytes[..i], &bytes[i..i * 2])?
            + hamming_distance(&bytes[..i], &bytes[i * 2..i * 3])?
            + hamming_distance(&bytes[..i], &bytes[i * 3..i * 4])?
            + hamming_distance(&bytes[i..i * 2], &bytes[i * 2..i * 3])?
            + hamming_distance(&bytes[i..i * 2], &bytes[i * 3..i * 4])?
            + hamming_distance(&bytes[i * 2..i * 3], &bytes[i * 3..i * 4])?)
            as f64
            / (i as f64 * 6.0);

        if best_guess == 0.0_f64 || guess < best_guess {
            best_guess = guess;
            res = i;
        }
    }

    Ok(res)
}

/// Convenience function to return multiple (num_guesses) key lengths
pub fn guess_key_length_multi(bytes: &[u8], start_len: usize, num_guesses: usize) -> Result<Vec<usize>, Error> {
    let mut res = Vec::with_capacity(num_guesses);

    res.push(guess_key_length(&bytes, start_len)?);

    // guess the next key length starting with the previously guessed key length + 1 
    for i in 1..num_guesses {
        res.push(guess_key_length(&bytes, res[i - 1] + 1)?);
    }

    Ok(res)
}

/// Split ciphertext into key length blocks
///
/// Returns a MxN two-dimensional matrix, (M = key length, N = floor(cipher length / key length))
///
/// If ciphertext is not a multiple of the key length, drops last (ciphertext % key length) bytes
pub fn get_key_blocks(ciphertext: &[u8], key_len: usize) -> Vec<Vec<u8>> {
    let ciphertext_len = ciphertext.len();
    let mut xor_blocks: Vec<Vec<u8>> = vec![Vec::with_capacity(ciphertext_len / key_len); key_len];

    for i in 0..ciphertext_len / key_len {
        let base = i * key_len;
        for j in 0..key_len {
            xor_blocks[j].push(ciphertext[base + j]);
        }
    }

    xor_blocks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_hamming_distance() {
        assert_eq!(
            hamming_distance(b"this is a test", b"wokka wokka!!!").unwrap(),
            37
        );
    }

    #[test]
    fn check_get_key_blocks() {
        let exp_key = b"TheKey".to_vec();
        let key_rpt = b"TheKeyTheKeyTheKey".to_vec();
        let blocks = get_key_blocks(&key_rpt, exp_key.len());

        assert_eq!(blocks[0].len(), key_rpt.len() / exp_key.len());
        for (i, block) in blocks.iter().enumerate() {
            for &byte in block {
                assert_eq!(exp_key[i], byte);
            }
        }
    }
}
