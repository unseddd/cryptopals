use alloc::vec::Vec;
use core::convert::TryInto;
use hashbrown::HashMap;

use crate::bytes::constant_eq;
use crate::encoding::from_hex_bytes;

#[derive(Debug)]
pub enum Error {
    Invalid,
    AccountExists,
}

pub struct CbcMac {
    key: [u8; craes::aes::KEY_LEN_128],
    iv: [u8; craes::cbc::IV_LEN],
}

/// Length of the CBC-MAC and IV
pub const IV_MAC_LEN: usize = craes::cbc::IV_LEN + craes::aes::BLOCK_LEN;

/// Length of the CBC-MAC
pub const MAC_LEN: usize = craes::aes::BLOCK_LEN;

/// Length of CBC-MAC account server signed transfer message
pub const CBC_SNG_XFER_MSG_LEN: usize = 29 + IV_MAC_LEN;

impl CbcMac {
    /// Create a new CBC Mac from a given key and IV
    pub fn new(key: [u8; craes::aes::KEY_LEN_128], iv: [u8; craes::cbc::IV_LEN]) -> Self {
        Self { key: key, iv: iv }
    }

    /// Sign a given message using CBC-MAC w/ IV according to Cryptopals #49
    ///
    /// No input validation done, in the real world you would want to
    ///       since this is just for the challenge, assume input valid
    pub fn sign_with_iv(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        let c = craes::cbc::encrypt(&craes::pkcs7::pad(msg), &self.key, &self.iv).map_err(|_| Error::Invalid)?;
        let mut res = msg.to_vec();
        // add the IV, per the first half of Cryptopals #49
        res.extend_from_slice(&self.iv);
        // add the CBC-MAC, the last block of the CBC encrypted message
        res.extend_from_slice(&c[c.len() - MAC_LEN..]);
        Ok(res)
    }

    /// Sign a given message using CBC-MAC w/ fixed IV according to Cryptopals #49
    ///
    /// No input validation done, in the real world you would want to
    ///       since this is just for the challenge, assume input valid
    pub fn sign_fixed_iv(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        let c = craes::cbc::encrypt(&craes::pkcs7::pad(msg), &self.key, &self.iv).map_err(|_| Error::Invalid)?;
        let mut res = msg.to_vec();
        // add the CBC-MAC, the last block of the CBC encrypted message
        res.extend_from_slice(&c[c.len() - MAC_LEN..]);
        Ok(res)
    }

    /// Verify a CBC-MAC w/ IV signed message according to Cryptopals #49
    ///
    /// Mild input validation done, otherwise assume valid because challenge
    pub fn verify_with_iv(&self, signature: &[u8]) -> Result<bool, Error> {
        let sig_len = signature.len();
        if sig_len < IV_MAC_LEN {
            return Err(Error::Invalid);
        }
        let msg_len = sig_len - IV_MAC_LEN;
        let msg = &signature[..msg_len];
        // take IV from the message, don't verify it matches our internal IV
        // allows attacker control over IV, and the first block of ciphertext
        // unwrap is safe, IV guaranteed to be correct length
        let iv: [u8; craes::cbc::IV_LEN] = signature[msg_len..msg_len + craes::cbc::IV_LEN].try_into().unwrap();
        let mac = &signature[sig_len - MAC_LEN..];

        let c = craes::cbc::encrypt(&craes::pkcs7::pad(msg), &self.key, &iv).map_err(|_| Error::Invalid)?;
        let c_mac = &c[c.len() - MAC_LEN..];

        Ok(constant_eq(mac, c_mac))
    }

    /// Verify a CBC-MAC w/ fixed IV signed message according to Cryptopals #49
    pub fn verify_fixed_iv(&self, signature: &[u8]) -> Result<bool, Error> {
        let sig_len = signature.len();
        if sig_len < MAC_LEN {
            return Err(Error::Invalid);
        }
        let msg_len = sig_len - MAC_LEN;
        let msg = &signature[..msg_len];
        // take IV from the message, don't verify it matches our internal IV
        // allows attacker control over IV, and the first block of ciphertext
        // unwrap is safe, IV guaranteed to be correct length
        let mac = &signature[sig_len - MAC_LEN..];

        let c = craes::cbc::encrypt(&craes::pkcs7::pad(msg), &self.key, &self.iv).map_err(|_| Error::Invalid)?;
        let c_mac = &c[c.len() - MAC_LEN..];

        Ok(constant_eq(mac, c_mac))
    }
}

impl From<[u8; craes::aes::KEY_LEN_128]> for CbcMac {
    fn from(key: [u8; craes::aes::KEY_LEN_128]) -> Self {
        Self { key: key, iv: [0_u8; craes::cbc::IV_LEN] }
    }
}

/// Some bank's implementation of a account transfer server using CBC-MAC
pub struct CbcMacServer {
    // Map of account IDs to ammount
    accounts: HashMap<u8, u32>,
    mac: CbcMac,
}

impl CbcMacServer {
    /// Create a new CBC-MAC server
    pub fn new(key: [u8; craes::aes::KEY_LEN_128], iv: [u8; craes::cbc::IV_LEN]) -> Self {
        Self { accounts: Default::default(), mac: CbcMac::new(key, iv) }
    }

    /// Add an account with an initial balance (this is a very trusting bank ;)
    pub fn add_account(&mut self, id: u8, balance: u32) -> Result<(), Error> {
        if self.accounts.contains_key(&id) {
            return Err(Error::AccountExists);
        }

        self.accounts.insert(id, balance);

        Ok(())
    }

    /// Get the balance of an account
    pub fn get_balance(&self, id: u8) -> Result<u32, Error> {
        if !self.accounts.contains_key(&id) {
            return Err(Error::Invalid);
        }

        Ok(self.accounts[&id])
    }

    /// Transfer message format:
    ///
    /// from=#{from-id}&to=#{to-id}&amount=#{amount} || IV || MAC
    ///
    /// `from-id` and `to-id` are little-endian 8-bit unsigned integers
    /// `amount` is a big-endian 32-bit unsigned integer
    /// `IV` is a big-endian 16-byte CBC IV
    /// `MAC` is a big-endian 16-byte AES block
    pub fn verify_transfer(&self, msg: &[u8]) -> Result<bool, Error> {
        let msg_len = msg.len();
        if msg_len != CBC_SNG_XFER_MSG_LEN {
            return Err(Error::Invalid);
        }
        if &msg[..5] != b"from=" || &msg[7..11] != b"&to=" || &msg[13..21] != b"&amount=" {
            return Err(Error::Invalid);
        }
        self.mac.verify_with_iv(msg)
    }

    /// Multi-transfer message format:
    ///
    /// from=#{from-id}&tx_list=#{transactions} || MAC
    /// transactions = to:amount[;to:amount]*
    ///
    /// `from-id` and `to-id` are little-endian 8-bit unsigned integers
    /// `amount` is a big-endian 32-bit unsigned integer
    pub fn verify_multi_transfer(&self, msg: &[u8]) -> Result<bool, Error> {
        if &msg[..5] != b"from=" || &msg[7..16] != b"&tx_list=" {
            return Err(Error::Invalid);
        }
        self.mac.verify_fixed_iv(msg)
    }


    /// Process a transfer message moving an amount from one account to another
    pub fn process_transfer(&mut self, msg: &[u8]) -> Result<(), Error> {
        if !self.verify_transfer(msg)? {
            return Err(Error::Invalid);
        }

        // unwrap safe, slices guaranteed correct length
        let from_id = u8::from_le_bytes(from_hex_bytes(&msg[5..7]).unwrap().as_slice().try_into().unwrap());
        let to_id = u8::from_le_bytes(from_hex_bytes(&msg[11..13]).unwrap().as_slice().try_into().unwrap());
        let amount = u32::from_be_bytes(from_hex_bytes(&msg[21..29]).unwrap().as_slice().try_into().unwrap());

        if !self.accounts.contains_key(&from_id) || !self.accounts.contains_key(&to_id) {
            return Err(Error::Invalid);
        }

        self.transfer(from_id, to_id, amount)
    }

    /// Process a multi-transaction transfer message moving amount(s) from one account to other(s)
    pub fn process_multi_transfer(&mut self, msg: &[u8]) -> Result<(), Error> {
        if !self.verify_multi_transfer(msg)? {
            return Err(Error::Invalid);
        }

        // unwrap safe, slices guaranteed correct length
        let from_id = u8::from_le_bytes(from_hex_bytes(&msg[5..7]).unwrap().as_slice().try_into().unwrap());

        if !self.accounts.contains_key(&from_id) {
            return Err(Error::Invalid);
        }

        let msg_len = msg.len();

        let tx_list = &msg[16..msg_len-MAC_LEN];
        let tx_list_len = tx_list.len();
        let mut txes: Vec<(u8, u32)> = Vec::with_capacity(tx_list_len / 13);
        let mut total_amount = 0;
        if tx_list[2] != 0x3a {
            return Err(Error::Invalid);
        }
        let to_id = u8::from_le_bytes(from_hex_bytes(&tx_list[..2]).unwrap().as_slice().try_into().unwrap());
        let amount = u32::from_be_bytes(from_hex_bytes(&tx_list[3..11]).unwrap().as_slice().try_into().unwrap());
        txes.push((to_id, amount));

        let mut tx_idx = 11;
        if tx_list_len > tx_idx {
            loop {
                for &b in tx_list[tx_idx..].iter() {
                    if b == 0x3b {
                        tx_idx += 1;
                        break;
                    }
                    tx_idx += 1;
                }

                if tx_idx + 11 > tx_list_len { break };

                let tx = &tx_list[tx_idx..tx_idx+11];

                if tx[2] != 0x3a /* b":" */ {
                    // skip poorly formatted transactions, what could be the harm?
                    // (hint: needed for the length-extension attack)
                    continue;
                }

                // allow transferring to the same user multiple times
                let to_id = u8::from_le_bytes(from_hex_bytes(&tx[..2]).unwrap().as_slice().try_into().unwrap());
                let amount = u32::from_be_bytes(from_hex_bytes(&tx[3..]).unwrap().as_slice().try_into().unwrap());
                if !self.accounts.contains_key(&to_id) {
                    return Err(Error::Invalid);
                }

                // don't transfer before processing entire message, there could be an attack (lel)
                total_amount += amount;
                txes.push((to_id, amount));
                tx_idx += 11;
            }
        }

        // better check the user's account has enough money before any actual transfers happen
        // wouldn't want anyone to lose money, now...
        if self.accounts[&from_id] < total_amount {
            return Err(Error::Invalid);
        }

        for (to_id, amount) in txes.iter() {
            // transfer from one account to another
            self.transfer(from_id, *to_id, *amount)?;
        }

        Ok(())
    }

    fn transfer(&mut self, from_id: u8, to_id: u8, amount: u32) -> Result<(), Error> {
        let from_bal = self.accounts[&from_id];
        if amount > from_bal {
            return Err(Error::Invalid);
        }
        self.accounts.insert(from_id, from_bal - amount);
        let to_bal = self.accounts[&to_id];
        self.accounts.insert(to_id, to_bal + amount);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_cbc_mac() {
        let msg = b"Somehow, it'll all work out";

        let key = [1_u8; craes::aes::KEY_LEN_128];
        let iv = [2_u8; craes::cbc::IV_LEN];

        let mac = CbcMac::new(key, iv);

        let signed_msg = mac.sign_with_iv(msg.as_ref()).unwrap();
        assert!(mac.verify_with_iv(&signed_msg).unwrap());
    }
}
