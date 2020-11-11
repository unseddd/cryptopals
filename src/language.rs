use alloc::vec::Vec;

use hashbrown::HashMap;
use libm::{fabs, fmin};

use crate::encoding::{xor_key, Error as EncodingError};

#[derive(Debug, PartialEq)]
pub enum Error {
    Encoding(EncodingError),
}

const UNKNOWN_EN: u8 = 0;
pub const BIGRAM_COUNT: usize = 728;

/// Attempt at guessing Single byte XOR key
pub struct Attempt {
    pub key: u8,
    pub delta: f64,
}

impl Attempt {
    pub fn new() -> Self {
        Self { key: 0, delta: 0.0 }
    }
}

/// Unigram frequencies of English characters (case-insensitive)
///
/// Frequencies from: https://en.wikipedia.org/wiki/Letter_frequency
pub fn english_frequency(byte: u8) -> f64 {
    match byte {
        0x41 | 0x61 /* A | a */ => 0.08167,
        0x42 | 0x62 /* B | b */ => 0.01492,
        0x43 | 0x63 /* C | c */ => 0.02782,
        0x44 | 0x64 /* D | d */ => 0.04253,
        0x45 | 0x65 /* E | e */ => 0.12702,
        0x46 | 0x66 /* F | f */ => 0.02228,
        0x47 | 0x67 /* G | g */ => 0.02015,
        0x48 | 0x68 /* H | h */ => 0.06094,
        0x49 | 0x69 /* I | i */ => 0.06966,
        0x4a | 0x6a /* J | j */ => 0.00153,
        0x4b | 0x6b /* K | k */ => 0.00772,
        0x4c | 0x6c /* L | l */ => 0.04025,
        0x4d | 0x6d /* M | m */ => 0.02406,
        0x4e | 0x6e /* N | n */ => 0.06749,
        0x4f | 0x6f /* O | o */ => 0.07507,
        0x50 | 0x70 /* P | p */ => 0.01929,
        0x51 | 0x71 /* Q | q */ => 0.00095,
        0x52 | 0x72 /* R | r */ => 0.05987,
        0x53 | 0x73 /* S | s */ => 0.06327,
        0x54 | 0x74 /* T | t */ => 0.09056,
        0x55 | 0x75 /* U | u */ => 0.02758,
        0x56 | 0x76 /* V | v */ => 0.00978,
        0x57 | 0x77 /* W | w */ => 0.02360,
        0x58 | 0x78 /* X | x */ => 0.00150,
        0x59 | 0x79 /* Y | y */ => 0.01974,
        0x5a | 0x7a /* Z | z */ => 0.00074,
        UNKNOWN_EN => 0.00002,  // heuristic for unknown character occurence
        _ => 0.0,  // characters never in english text
    }
}

/// Guess which single byte has been XORed against a message to produce the given ciphertext
pub fn guess_single_xor_key(
    ciphertext: &[u8],
    bigrams: &HashMap<u16, f64>,
) -> Result<Attempt, Error> {
    let mut winner = Attempt::new();

    for attempt in 0x00..=0xff {
        let dec = xor_key(&ciphertext, attempt).map_err(|e| Error::Encoding(e))?;

        let obs_bigrams = observe_bigrams(
            &dec.iter()
                .filter(|&&x| x != 0x20)
                .map(|&x| x)
                .collect::<Vec<u8>>(),
        );

        let delta = matches_bigram_distribution(&bigrams, &obs_bigrams);

        if winner.key == 0 || winner.delta > delta {
            winner = Attempt {
                key: attempt,
                delta: delta,
            };
        }
    }

    Ok(winner)
}

/// Guess which single byte has been XORed against a message to produce the given ciphertext
pub fn guess_single_xor_key_tri(
    ciphertext: &[u8],
    trigrams: &HashMap<u32, f64>,
) -> Result<Attempt, Error> {
    let mut winner = Attempt::new();

    for attempt in 0x00..=0xff {
        let dec = xor_key(&ciphertext, attempt).map_err(|e| Error::Encoding(e))?;

        let obs_trigrams = observe_trigrams(
            &dec.iter()
                .filter(|&&x| x != 0x20)
                .map(|&x| x)
                .collect::<Vec<u8>>(),
        );

        let delta = matches_trigram_distribution(&trigrams, &obs_trigrams);

        if winner.key == 0 || fmin(winner.delta, delta) == delta && !delta.is_nan() {
            winner = Attempt {
                key: attempt,
                delta: delta,
            };
        }
    }

    Ok(winner)
}

pub fn guess_single_xor_key_simple(ciphertext: &[u8]) -> Result<Attempt, Error> {
    let mut res = Attempt{ key: 0, delta: 1420.69 };

    for attempt in 0x00..=0xff {
        let dec = xor_key(&ciphertext, attempt).map_err(|e| Error::Encoding(e))?;

        let score = dec.iter().fold(1420_u64, |delta, b| {
            match *b {
                0x61..=0x7a => delta.saturating_sub(1),
                0x41..=0x5a => delta,
                0x21..=0x40 => delta + 1,
                _ => delta,
            }
        });

        if score < res.delta as u64 {
            res.key = attempt;
            res.delta = score as f64;
        }
    }

    Ok(res)
}

/// Build bigrams based on unigram frequency model
/// Naive likelihood calculation by the product of the two unigram frequencies
pub fn build_english_bigrams() -> HashMap<u16, f64> {
    let mut res: HashMap<u16, f64> = HashMap::with_capacity(BIGRAM_COUNT);
    for b in 0x61..=0x7a {
        let _i = u16::from_le_bytes([0x00, b]);
        let i_ = u16::from_le_bytes([b, 0x00]);
        let uni = english_frequency(b);

        res.insert(_i, uni);
        res.insert(i_, uni);

        for c in 0x61..=0x7a {
            let bi = english_frequency(c);
            res.insert(u16::from_le_bytes([b, c]), uni * bi);
            res.insert(u16::from_le_bytes([c, b]), uni * bi);
        }
    }
    res
}

/// Build trigrams based on unigram frequency model
/// Naive likelihood calculation by the product of the three unigram frequencies
pub fn build_english_trigrams() -> HashMap<u32, f64> {
    let mut res: HashMap<u32, f64> = HashMap::with_capacity(BIGRAM_COUNT);
    for b in 0x61..=0x7a {
        let _i = u32::from_le_bytes([0x00, 0x00, 0x00, b]);
        let i_ = u32::from_le_bytes([0x00, 0x00, b, 0x00]);
        let i__ = u32::from_le_bytes([0x00, b, 0x00, 0x00]);
        let uni = english_frequency(b);

        res.insert(_i, uni);
        res.insert(i_, uni);
        res.insert(i__, uni);

        for c in 0x61..=0x7a {
            for d in 0x61..=0x7a {
                let bi = english_frequency(c);
                let tri = english_frequency(d);
                res.insert(u32::from_le_bytes([0x00, b, c, d]), uni * bi * tri);
                res.insert(u32::from_le_bytes([0x00, c, d, b]), uni * bi * tri);
                res.insert(u32::from_le_bytes([0x00, d, b, c]), uni * bi * tri);

                res.insert(u32::from_le_bytes([0x00, c, b, d]), uni * bi * tri);
                res.insert(u32::from_le_bytes([0x00, d, c, b]), uni * bi * tri);
            }
        }
    }
    res
}

/// Get the frequency percentage of observed bigrams in a given byte string
pub fn observe_bigrams(bytes: &[u8]) -> HashMap<u16, f64> {
    let bytes_len = bytes.len();
    let mut res: HashMap<u16, f64> = HashMap::with_capacity(bytes.len() + 2);

    // get count of observed bigrams
    for (i, byte) in bytes.iter().enumerate() {
        let bigram = if i == 0 {
            u16::from_le_bytes([0x00, *byte])
        } else if i < bytes_len - 1 {
            u16::from_le_bytes([*byte, bytes[i + 1]])
        } else {
            u16::from_le_bytes([*byte, 0x00])
        };

        if let Some(entry) = res.get_mut(&bigram) {
            *entry += 1.0;
        } else {
            res.insert(bigram, 1.0);
        }
    }

    // convert count to frequency percentage
    let bytes_len = bytes_len as f64;
    for (_, hz) in res.iter_mut() {
        *hz = *hz / bytes_len;
    }

    res
}

/// Get the frequency percentage of observed bigrams in a given byte string
pub fn observe_trigrams(bytes: &[u8]) -> HashMap<u32, f64> {
    let bytes_len = bytes.len();
    let mut res: HashMap<u32, f64> = HashMap::with_capacity(bytes.len() + 8);

    // get count of observed trigrams
    for (i, byte) in bytes.iter().enumerate() {
        let trigram = if i == 0 {
            u32::from_le_bytes([0x00, 0x00, 0x00, *byte])
        } else if i < bytes_len - 2 {
            u32::from_le_bytes([0x00, *byte, bytes[i + 1], bytes[i + 2]])
        } else if i < bytes_len - 1 {
            u32::from_le_bytes([0x00, *byte, bytes[i + 1], 0x00])
        } else {
            u32::from_le_bytes([0x00, *byte, 0x00, 0x00])
        };

        if let Some(entry) = res.get_mut(&trigram) {
            *entry += 1.0;
        } else {
            res.insert(trigram, 1.0);
        }
    }

    // convert count to frequency percentage
    let bytes_len = bytes_len as f64;
    for (_, hz) in res.iter_mut() {
        *hz = *hz / bytes_len;
    }

    res
}

/// Get the delta of how closely observed bigrams match the expected distribution
pub fn matches_bigram_distribution(
    expected: &HashMap<u16, f64>,
    observed: &HashMap<u16, f64>,
) -> f64 {
    let mut delta = 0.0_f64;
    for (obs_key, obs_hz) in observed.iter() {
        delta += if expected.contains_key(obs_key) {
            fabs(expected[obs_key] - obs_hz)
        } else {
            1.0
        };
    }
    delta / expected.len() as f64
}

/// Get the delta of how closely observed trigrams match the expected distribution
pub fn matches_trigram_distribution(
    expected: &HashMap<u32, f64>,
    observed: &HashMap<u32, f64>,
) -> f64 {
    let mut delta = 0.0_f64;
    for (obs_key, obs_hz) in observed.iter() {
        delta += if expected.contains_key(obs_key) {
            fabs(expected[obs_key] - obs_hz)
        } else {
            1.0
        };
    }
    delta / expected.len() as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_build_english_bigrams() {
        let grams = build_english_bigrams();
        assert_eq!(grams.len(), BIGRAM_COUNT);
    }
}
