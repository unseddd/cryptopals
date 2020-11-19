#![macro_use]
use alloc::vec;
use alloc::vec::Vec;

use rand::{thread_rng, Rng};

use craes::{aes, cbc, pkcs7};

use crate::encoding;

use super::{gen_rand_iv, gen_rand_key, Error};
use super::{EQUAL, SEMICOLON};

/// Ciphertext and key material output by the CBC oracle
pub struct CbcOracleOutput {
    pub ciphertext: Vec<u8>,
    pub key: [u8; aes::KEY_LEN_128],
    pub iv: [u8; cbc::IV_LEN],
}

/// CBC oracle to encrypt user data under a random key and IV
///
/// Prepends a fixed key-value data string
/// Appends another fixed key-value data string
///
/// Quotes out ";" and "=" metacharacters from user-input
pub fn cbc_oracle(user_data: &[u8]) -> Result<CbcOracleOutput, Error> {
    let mut plaintext = b"comment1=cooking%20MCs;userdata=".to_vec();

    let msg: Vec<u8> = user_data
        .iter()
        .filter(|&&b| b != SEMICOLON && b != EQUAL)
        .map(|&b| b)
        .collect();

    let suffix = b";comment2=%20like%20a%20pound%20of%20bacon";

    plaintext.extend_from_slice(&msg);
    plaintext.extend_from_slice(&suffix[..]);

    let mut rng = thread_rng();

    let key = gen_rand_key(&mut rng);
    let iv = gen_rand_iv(&mut rng);

    let cipher = cbc::encrypt(&pkcs7::pad(&plaintext), &key, &iv).map_err(|e| Error::Cbc(e))?;

    Ok(CbcOracleOutput {
        ciphertext: cipher,
        key: key,
        iv: iv,
    })
}

pub fn cbc_oracle_found_admin(output: &CbcOracleOutput) -> Result<bool, Error> {
    let plaintext =
        cbc::decrypt(&output.ciphertext, &output.key, &output.iv).map_err(|e| Error::Cbc(e))?;

    let target = b";admin=true;";

    for chunk in plaintext.chunks_exact(target.len()) {
        if &chunk == &target {
            return Ok(true);
        }
    }

    Ok(false)
}

const CBC_NUM_PLAINTEXTS: usize = 10;

pub struct CbcPaddingOracle {
    key: [u8; aes::KEY_LEN_128],
    plaintexts: [Vec<u8>; CBC_NUM_PLAINTEXTS],
}

#[derive(Clone)]
pub struct PadOracleOutput {
    pub ciphertext: Vec<u8>,
    pub iv: [u8; cbc::IV_LEN],
}

impl CbcPaddingOracle {
    /// Create a new CBC padding oracle
    ///
    /// A new random key is generated, and fixed for the oracle's lifetime
    pub fn new() -> Self {
        let key = gen_rand_key(&mut thread_rng());
        let texts = [
            encoding::from_base64(b"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=".as_ref())
                .unwrap(),
            encoding::from_base64(
                b"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic="
                    .as_ref(),
            )
            .unwrap(),
            encoding::from_base64(
                b"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==".as_ref(),
            )
            .unwrap(),
            encoding::from_base64(
                b"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==".as_ref(),
            )
            .unwrap(),
            encoding::from_base64(
                b"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl".as_ref(),
            )
            .unwrap(),
            encoding::from_base64(b"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==".as_ref())
                .unwrap(),
            encoding::from_base64(
                b"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==".as_ref(),
            )
            .unwrap(),
            encoding::from_base64(
                b"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=".as_ref(),
            )
            .unwrap(),
            encoding::from_base64(b"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=".as_ref())
                .unwrap(),
            encoding::from_base64(
                b"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93".as_ref(),
            )
            .unwrap(),
        ];

        Self {
            key: key,
            plaintexts: texts,
        }
    }

    // Create a CBC padding oracle with fixed key for debugging
    #[allow(dead_code)]
    fn new_debug() -> Self {
        Self {
            key: [
                0xaf, 0x40, 0xdf, 0x8d, 0x07, 0x6c, 0x10, 0xbb, 0x70, 0x08, 0x50, 0x42, 0x3b, 0xb5,
                0x4d, 0x79,
            ],
            plaintexts: [
                vec![],
                vec![],
                vec![],
                vec![],
                vec![],
                vec![],
                vec![],
                vec![],
                vec![],
                vec![],
            ],
        }
    }

    /// Encrypt a random plaintext from the list of plaintexts under a random key
    ///
    /// Key is generated randomly on oracle creation, and fixed for the oracle's liftetime
    pub fn encrypt(&self) -> Result<PadOracleOutput, Error> {
        let mut rng = thread_rng();

        let pt_ind = rng.gen_range::<usize, usize, usize>(0, CBC_NUM_PLAINTEXTS);
        let iv = gen_rand_iv(&mut rng);

        self.encrypt_inner(&self.plaintexts[pt_ind], &iv)
    }

    // Useful for debugging
    fn encrypt_inner(
        &self,
        plaintext: &[u8],
        iv: &[u8; cbc::IV_LEN],
    ) -> Result<PadOracleOutput, Error> {
        let cipher =
            cbc::encrypt(&pkcs7::pad(&plaintext), &self.key, &iv).map_err(|e| Error::Cbc(e))?;

        Ok(PadOracleOutput {
            ciphertext: cipher,
            iv: *iv,
        })
    }

    /// Padding oracle decryption
    ///
    /// Opens a side-channel for determining if PKCS#7 padding is correct
    ///
    /// Obviously, do not do this in practice
    pub fn decrypt(&self, ciphertext: &[u8], iv: &[u8; cbc::IV_LEN]) -> Result<bool, Error> {
        let pt = cbc::decrypt(&ciphertext, &self.key, &iv).map_err(|e| Error::Cbc(e))?;

        match pkcs7::unpad(&pt) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

/// Decrypt the ciphertext produced by the CBC padding oracle
pub fn decrypt_cbc_padding_oracle(
    oracle: &CbcPaddingOracle,
    out: &mut PadOracleOutput,
) -> Result<Vec<u8>, Error> {
    let ciph_len = out.ciphertext.len();

    let mut res: Vec<u8> = Vec::with_capacity(ciph_len);

    // traverse the ciphertext in reverse
    for block_num in 0..ciph_len / aes::BLOCK_LEN {
        // run the oracle one block at a time
        // start at the previous block
        let block_start = if block_num == 0 {
            0
        } else {
            (block_num - 1) * aes::BLOCK_LEN
        };
        let block_end = block_start + aes::BLOCK_LEN;

        let mut dy_bytes = [0_u8; aes::BLOCK_LEN];

        let (iv, block) = if block_num == 0 {
            dy_bytes.copy_from_slice(out.iv.as_ref());
            (out.iv.as_ref(), &out.ciphertext[block_start..block_end])
        } else {
            dy_bytes.copy_from_slice(&out.ciphertext[block_start..block_end]);
            (
                &out.ciphertext[block_start..block_end],
                &out.ciphertext[block_start + aes::BLOCK_LEN..block_end + aes::BLOCK_LEN],
            )
        };

        let pos = last_word_oracle(&oracle, &block, &mut dy_bytes)?;
        if pos == 0 {
            // full padding block, so we know the plaintext
            res.extend_from_slice(&[16_u8; aes::BLOCK_LEN]);
        } else {
            block_decryption_oracle(&oracle, &block, &mut dy_bytes, pos)?;
            encoding::xor_equals(&mut dy_bytes, &iv).unwrap();
            res.extend_from_slice(&dy_bytes);
        }
    }

    Ok(res)
}

// "Last Word Oracle" from Vaudenay's paper
// "Security Flaws Induced by CBC Padding Applications to SSL, IPSEC, WTLS...":
// https://www.iacr.org/cryptodb/archive/2002/EUROCRYPT/2850/2850.pdf
fn last_word_oracle(
    oracle: &CbcPaddingOracle,
    block: &[u8],
    iv: &mut [u8; cbc::IV_LEN],
) -> Result<usize, Error> {
    let pos = aes::BLOCK_LEN - 1;

    for i in 0x00..=0xff {
        if iv[pos] == i as u8 {
            continue;
        };

        iv[pos] ^= i;
        if oracle.decrypt(&block, &iv)? {
            for n in 0..aes::BLOCK_LEN - 1 {
                iv[n] ^= 1;

                // if changed value caused decryption to fail,
                // we reached the last valid padding byte
                if !oracle.decrypt(&block, &iv)? {
                    iv[n] ^= 1;
                    for j in n..=pos {
                        iv[j] ^= (aes::BLOCK_LEN - n) as u8;
                    }
                    return Ok(n);
                } else {
                    // return to original val
                    iv[n] ^= 1;
                }
            }
            // only the last value resulted in valid oracle padding
            // store the value ^ 1 to get the plaintext value
            iv[pos] ^= 1;
            return Ok(pos);
        } else {
            // return to original value
            iv[pos] ^= i;
        }
    }

    Ok(pos)
}

// "Block Decryption Oracle" from Vaudenay's paper
// "Security Flaws Induced by CBC Padding Applications to SSL, IPSEC, WTLS...":
// https://www.iacr.org/cryptodb/archive/2002/EUROCRYPT/2850/2850.pdf
fn block_decryption_oracle(
    oracle: &CbcPaddingOracle,
    block: &[u8],
    dy_bytes: &mut [u8; cbc::IV_LEN],
    pos: usize,
) -> Result<(), Error> {
    if pos >= aes::BLOCK_LEN {
        return Err(Error::InvalidPosition);
    }

    let mut r = [0_u8; aes::BLOCK_LEN];
    thread_rng().fill(&mut r[0..=pos]);

    for j in (0..pos).rev() {
        for k in j + 1..aes::BLOCK_LEN {
            r[k] = dy_bytes[k] ^ (aes::BLOCK_LEN - j) as u8;
        }

        for i in 0x00..=0xff {
            if r[j] == i {
                continue;
            };

            r[j] ^= i;
            if oracle.decrypt(&block, &r)? {
                dy_bytes[j] = r[j] ^ (aes::BLOCK_LEN - j) as u8;
                break;
            } else {
                // return to original value
                r[j] ^= i;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXED_IV: [u8; cbc::IV_LEN] = [
        0xba, 0x78, 0x95, 0xb6, 0x15, 0x36, 0xf2, 0xf1, 0x80, 0xd6, 0x2b, 0xa2, 0xe8, 0xd3, 0xb5,
        0x65,
    ];

    #[test]
    fn check_last_word_oracle() {
        let mut pt = [
            0x1, 0x10, 0xf, 0xe, 0xd, 0xc, 0xb, 0xa, 0x9, 0x8, 0x7, 0x6, 0x5, 0x4, 0x3, 0x2,
        ]
        .to_vec();

        let oracle = CbcPaddingOracle::new_debug();

        for i in 0..aes::BLOCK_LEN - 2 {
            let mut iv = FIXED_IV.clone();
            let out = oracle.encrypt_inner(&pt, &iv).unwrap();

            let mut pos =
                last_word_oracle(&oracle, &out.ciphertext[..aes::BLOCK_LEN], &mut iv).unwrap();
            assert_eq!(pos, aes::BLOCK_LEN - 1);

            iv.copy_from_slice(&out.ciphertext[..aes::BLOCK_LEN]);
            pos = last_word_oracle(&oracle, &out.ciphertext[aes::BLOCK_LEN..], &mut iv).unwrap();
            assert_eq!(pos, i);

            // add a byte to the plaintext,
            // resulting in the next lowest value of padding bytes in the second block
            pt.push(FIXED_IV[i]);
        }
    }

    #[test]
    fn check_block_decryption_oracle() {
        let pt = b"Ostensibly rando".to_vec();

        let oracle = CbcPaddingOracle::new();

        let mut iv = FIXED_IV.clone();
        let out = oracle.encrypt_inner(&pt, &iv).unwrap();

        let mut res: Vec<u8> = Vec::with_capacity(out.ciphertext.len());
        let block_num = out.ciphertext.len() / aes::BLOCK_LEN;

        for i in 0..block_num {
            let block_start = aes::BLOCK_LEN * i;
            let block_end = block_start + aes::BLOCK_LEN;
            let block = &out.ciphertext[block_start..block_end];

            if i > 0 {
                iv.copy_from_slice(
                    &out.ciphertext[block_start - aes::BLOCK_LEN..block_end - aes::BLOCK_LEN],
                );
            }

            let pos = last_word_oracle(&oracle, block, &mut iv).unwrap();
            if pos == 0 {
                // full padding block, so we know what it is :)
                res.extend_from_slice(&[16_u8; aes::BLOCK_LEN]);
            } else {
                block_decryption_oracle(&oracle, block, &mut iv, pos).unwrap();
            }

            if i == 0 {
                for (mb, ib) in iv.iter_mut().zip(FIXED_IV.iter()) {
                    *mb ^= *ib;
                }
                assert_eq!(iv, pt[..aes::BLOCK_LEN]);
            } else {
                if pos != 0 {
                    for (mb, ib) in iv.iter_mut().zip(
                        out.ciphertext[block_start - aes::BLOCK_LEN..block_end - aes::BLOCK_LEN]
                            .iter(),
                    ) {
                        *mb ^= *ib;
                    }
                    assert_eq!(iv, pt[aes::BLOCK_LEN..]);
                } else {
                    assert_eq!(res[..aes::BLOCK_LEN], [16_u8; aes::BLOCK_LEN]);
                }
            }
        }
    }

    #[test]
    fn check_decrypt_cbc_padding_oracle() {
        let exp_pt = b"Ostensibly rando";
        let exp_pad = [16_u8; aes::BLOCK_LEN];
        let oracle = CbcPaddingOracle::new();
        let mut out = oracle.encrypt_inner(exp_pt.as_ref(), &FIXED_IV).unwrap();

        let pt = decrypt_cbc_padding_oracle(&oracle, &mut out).unwrap();

        assert_eq!(exp_pt[..], pt[..aes::BLOCK_LEN]);
        assert_eq!(exp_pad[..], pt[aes::BLOCK_LEN..]);
    }
}
