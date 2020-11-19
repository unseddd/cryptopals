use core::convert::TryInto;

use super::{mt19937, recovery};

/// Generate a 16 byte password token based on current time
pub fn generate(time: u32) -> [u8; 16] {
    let mut rng = mt19937::Mt19937::new(time);
    let mut res = [0_u8; 16];

    for i in 0..4 {
        let num = rng.extract_number().to_le_bytes();
        res[i * 4..(i + 1) * 4].copy_from_slice(num.as_ref());
    }

    res
}

pub fn test_valid_token(token: &[u8; 16], now: u32) -> bool {
    let rand_num = u32::from_le_bytes(token[..4].try_into().unwrap());

    recovery::recover_seed(rand_num, now) != 0
}
