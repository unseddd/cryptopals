use alloc::vec::Vec;

#[derive(Debug, PartialEq)]
pub enum Error {
    Base64Length,
    HexLength,
    InvalidBase64,
    ParseByte(u8),
    ParseHex,
    ParseInt,
    XORLength,
}

/// Hex-decode a string
///
/// errors: returns Error on odd length and empty hex strings
pub fn from_hex(hex: &str) -> Result<Vec<u8>, Error> {
    let hex_len = hex.len();
    if hex_len % 2 != 0 || hex_len == 0 {
        return Err(Error::HexLength);
    }

    let mut res = Vec::with_capacity(hex_len / 2);
    for i in 0..(hex_len / 2) {
        res.push(u8::from_str_radix(&hex[i * 2..=i * 2 + 1], 16).map_err(|_| Error::ParseInt)?);
    }
    Ok(res)
}

/// Convert from hex-encode byte slices
///
/// Note: useful for hex-strings read from a file
pub fn from_hex_bytes(hex: &[u8]) -> Result<Vec<u8>, Error> {
    let hex_len = hex.len();
    if hex_len % 2 != 0 || hex_len == 0 {
        return Err(Error::HexLength);
    }

    let mut res = Vec::with_capacity(hex_len / 2);
    for i in 0..(hex_len / 2) {
        let b1 =
            u8::from_str_radix(core::str::from_utf8(&[hex[i * 2]]).unwrap_or("0"), 16).unwrap_or(0);
        let b2 = u8::from_str_radix(core::str::from_utf8(&[hex[i * 2 + 1]]).unwrap_or("0"), 16)
            .unwrap_or(0);
        res.push((b1 << 4) + b2);
    }
    Ok(res)
}

const BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
//const BASE64URL_ALPHABET: [u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Base64 encode a byte slice
///
/// errors: returns Error on empty byte slice
pub fn to_base64(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let bytes_len = bytes.len();

    if bytes_len == 0 {
        return Err(Error::Base64Length);
    }

    let bits_len = bytes_len * 8;
    let padding_len = match bits_len % 24 {
        8 => 2,
        16 => 1,
        _ => 0,
    };

    let b64_len = base64_len(bytes_len);
    let mut b64 = Vec::with_capacity(b64_len);

    // Process three input bytes as group of six bit indexes into alphabet
    let num_groups = bits_len / 24 + (padding_len != 0) as usize * 1;
    for i in 0..num_groups {
        let base_i = i * 3;
        let byte_1 = bytes[base_i];
        let byte_2 = if i == num_groups - 1 && padding_len == 2 {
            0u8
        } else {
            bytes[base_i + 1]
        };
        let byte_3 = if i == num_groups - 1 && padding_len != 0 {
            0u8
        } else {
            bytes[base_i + 2]
        };

        // first six bits of first byte
        b64.push(BASE64_ALPHABET[((byte_1 & 0xfc) >> 2) as usize]);
        // last two bits of first byte, first four bits of second byte
        b64.push(BASE64_ALPHABET[(((byte_1 & 0x03) << 4) | ((byte_2 & 0xf0) >> 4)) as usize]);
        // last four bits of second byte, first two bits of third byte
        b64.push(BASE64_ALPHABET[((byte_2 & 0x0f) << 2 | ((byte_3 & 0xc0) >> 6)) as usize]);
        // last six bits of third byte
        b64.push(BASE64_ALPHABET[(byte_3 & 0x3f) as usize]);
    }

    // process any padding bytes
    for b in &mut b64[b64_len - padding_len..] {
        *b = 0x3d; // =
    }

    Ok(b64)
}

/// Decode Base64-encoded byte slice
///
/// Returns Error for invalid Base64 length, or invalid encoding
///
/// Inefficient and likely buggy. Use rust-base64 for real applications
pub fn from_base64(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let bytes_len = bytes.len();
    let bits_len = bytes_len * 8;

    if bytes_len % 4 != 0 || bits_len < 32 || bytes_len == 0 {
        return Err(Error::Base64Length);
    }

    let mut res: Vec<u8> = Vec::with_capacity(bytes_len);
    for (i, &byte) in bytes.iter().enumerate() {
        if byte == 0x3d {
            if i != bytes_len - 2 && i != bytes_len - 1 {
                return Err(Error::InvalidBase64);
            }
        } else if !BASE64_ALPHABET.contains(&byte) {
            return Err(Error::InvalidBase64);
        }
    }

    let num_groups = bytes_len / 4;
    for i in 0..num_groups {
        let base = i * 4;

        // lookup indices in the base64 alphabet to get the next 24 bits of encoded data
        let enc_bytes: u32 = ((from_base64_byte(bytes[base]) as u32) << 18)
            | ((from_base64_byte(bytes[base + 1]) as u32) << 12)
            | ((from_base64_byte(bytes[base + 2]) as u32) << 6)
            | (from_base64_byte(bytes[base + 3]) as u32);

        res.push(((enc_bytes & 0x00ff_0000) >> 16) as u8);
        res.push(((enc_bytes & 0x0000_ff00) >> 8) as u8);
        res.push((enc_bytes & 0x0000_00ff) as u8);
    }

    let pad_len = if bytes[bytes_len - 2..] == b"=="[..] {
        2
    } else if bytes[bytes_len - 1] == 0x3d
    /* "=" */
    {
        1
    } else {
        0
    };

    Ok(res[..res.len() - pad_len].to_vec())
}

/// Get the index of the encoded byte in the Base64 alphabet
///
/// Panics on non-Base64 alphabet characters
fn from_base64_byte(byte: u8) -> u8 {
    for (i, &b) in BASE64_ALPHABET.iter().enumerate() {
        if b == byte {
            return i as u8;
        }
    }
    0_u8
}

fn base64_len(len: usize) -> usize {
    let bits_len = len * 8;
    let num_groups = bits_len / 24 + (bits_len % 24 != 0) as usize * 1;
    num_groups * 4
}

/// XOR fixed-length byte slices
///
/// errors: returns Error on unequal lengths
pub fn xor(left: &[u8], right: &[u8]) -> Result<Vec<u8>, Error> {
    let left_len = left.len();
    let right_len = right.len();
    if left_len != right_len {
        return Err(Error::XORLength);
    }
    let mut res: Vec<u8> = Vec::with_capacity(left_len);
    for (&i, &j) in left.iter().zip(right.iter()) {
        res.push(i ^ j);
    }
    Ok(res)
}

/// XOR fixed-length byte slices
///
/// errors: returns Error on unequal lengths
pub fn xor_equals(left: &mut [u8], right: &[u8]) -> Result<(), Error> {
    if left.len() != right.len() {
        return Err(Error::XORLength);
    }
    for (i, j) in left.iter_mut().zip(right.iter()) {
        *i ^= *j;
    }
    Ok(())
}

/// XOR a byte slice with a key byte
///
/// errors: returns Error on empty byte slice
pub fn xor_key(bytes: &[u8], key: u8) -> Result<Vec<u8>, Error> {
    let bytes_len = bytes.len();
    if bytes_len == 0 {
        return Err(Error::XORLength);
    }
    let mut res: Vec<u8> = Vec::with_capacity(bytes_len);
    for &byte in bytes.iter() {
        res.push(byte ^ key);
    }
    Ok(res)
}

/// XOR a byte slice with a key byte slice
///
/// Key repeats every key_len bytes, e.g.
///
/// b"This is a string"
/// b"This KeyThis Key"
pub fn xor_multi_key(bytes: &[u8], key: &[u8]) -> Vec<u8> {
    let key_len = key.len();

    let mut res = Vec::with_capacity(bytes.len());
    for (i, byte) in bytes.iter().enumerate() {
        res.push(byte ^ key[i % key_len]);
    }

    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_from_base64_byte() {
        for (i, &byte) in BASE64_ALPHABET.iter().enumerate() {
            assert_eq!(from_base64_byte(byte), i as u8);
        }

        let a = b"Zm9vYmFy".to_vec();
        assert_eq!(from_base64_byte(a[0]), 0x19);
        assert_eq!(from_base64_byte(a[1]), 0x26);
        assert_eq!(from_base64_byte(a[2]), 0x3d);
        assert_eq!(from_base64_byte(a[3]), 0x2f);

        // 0110 0100 0000 0000 0000 0000 (0x19 << 18)
        // 0000 0010 0110 0000 0000 0000 (0x26 << 12)
        // 0000 0000 0000 1111 0100 0000 (0x3d << 6)
        // 0000 0000 0000 0000 0010 1111 (0x2f)
        // -----------------------------
        // 0110 0110 0110 1111 0110 1111 (0x666f4f)

        assert_eq!(from_base64_byte(a[4]), 0x18);
        assert_eq!(from_base64_byte(a[5]), 0x26);
        assert_eq!(from_base64_byte(a[6]), 0x05);
        assert_eq!(from_base64_byte(a[7]), 0x32);

        // 0110 0000 0000 0000 0000 0000 (0x18 << 18)
        // 0000 0010 0110 0000 0000 0000 (0x26 << 12)
        // 0000 0000 0000 0001 0100 0000 (0x05 << 6)
        // 0000 0000 0000 0000 0011 0010 (0x32)
        // -----------------------------
        // 0110 0010 0110 0001 0111 0010 (0x626172)
    }

    #[test]
    fn base64() {
        let mut hex = Vec::<u8>::new();
        hex.push(0x01);

        let mut b64 = to_base64(&hex).unwrap();
        let mut exp_b64 = b"AQ==".to_vec();
        assert_eq!(b64[..], exp_b64[..]);

        hex.push(0x01);
        b64 = to_base64(&hex).unwrap();
        exp_b64 = b"AQE=".to_vec();
        assert_eq!(b64[..], exp_b64[..]);

        hex.push(0x01);
        b64 = to_base64(&hex).unwrap();
        exp_b64 = b"AQEB".to_vec();
        assert_eq!(b64[..], exp_b64[..]);

        // alphabet
        // 00 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25
        // A  B  C  D  E  F  G  H  I  J  K  L  M  N  O  P  Q  R  S  T  U  V  W  X  Y  Z
        //
        // 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51
        // a  b  c  d  e  f  g  h  i  j  k  l  m  n  o  p  q  r  s  t  u  v  w  x  y  z
        //
        // 52 53 54 55 56 57 58 59 60 61 62 63
        // 0  1  2  3  4  5  6  7  8  9  +  /;
        //
        // Z (25) + m (38) + 8 (60) + = (00)
        // 0000 0000 0000 0000 0001 1001 << 18
        // 0000 0000 0000 0000 0010 0110 << 12
        // 0000 0000 0000 0000 0011 1100 << 6
        // 0000 0000 0000 0000 0000 0000 << 0
        //
        // 0110 1000 0000 0000 0000 0000
        // 0000 0010 1100 0000 0000 0000
        // 0000 0000 0000 1111 0000 0000
        // 0000 0000 0000 0000 0000 0000
        // -----------------------------
        // 0110 1010 1100 1111 0000 0000

        b64 = b"Zg==".to_vec();
        let mut exp_text = b"f".to_vec();
        assert_eq!(to_base64(&exp_text).unwrap()[..], b64[..]);
        assert_eq!(from_base64(b64.as_ref()).unwrap()[..], exp_text[..]);

        b64 = b"Zm8=".to_vec();
        exp_text = b"fo".to_vec();
        assert_eq!(to_base64(&exp_text).unwrap()[..], b64[..]);
        assert_eq!(from_base64(b64.as_ref()).unwrap()[..], exp_text[..]);

        b64 = b"Zm9vYmE=".to_vec();
        exp_text = b"fooba".to_vec();
        assert_eq!(to_base64(&exp_text).unwrap()[..], b64[..]);
        assert_eq!(from_base64(b64.as_ref()).unwrap()[..], exp_text[..]);

        b64 = b"Zm9vYmFy".to_vec();
        exp_text = b"foobar".to_vec();
        assert_eq!(to_base64(&exp_text).unwrap()[..], b64[..]);
        assert_eq!(from_base64(b64.as_ref()).unwrap()[..], exp_text[..]);
    }
}
