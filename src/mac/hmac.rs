const PAD_LEN: usize = 64;
// Pad buffer for zeroizing sensitive data
const ZERO_PAD: [u8; PAD_LEN] = [0_u8; PAD_LEN];

/// Calculate HMAC-SHA1 of a given text using the provided key
pub fn hmac_sha1(text: &[u8], key: &[u8]) -> Result<[u8; isha1::DIGEST_LEN], isha1::Error> {
    let key_len = key.len();

    let mut k_ipad = [0_u8; PAD_LEN];
    let mut k_opad = [0_u8; PAD_LEN];

    if key_len > PAD_LEN {
        let mut digest = isha1::Sha1::digest(&key)?;
        k_ipad[..isha1::DIGEST_LEN].copy_from_slice(digest.as_ref());
        k_opad[..isha1::DIGEST_LEN].copy_from_slice(digest.as_ref());
        digest.copy_from_slice(&ZERO_PAD[..isha1::DIGEST_LEN]);
    } else {
        k_ipad[..key_len].copy_from_slice(&key);
        k_opad[..key_len].copy_from_slice(&key);
    }

    for (ipad, opad) in k_ipad.iter_mut().zip(k_opad.iter_mut()) {
        *ipad ^= 0x36;
        *opad ^= 0x5c;
    }

    let mut sha = isha1::Sha1::new();

    sha.input(&k_ipad)?;

    // zero any potentially sensitive data
    k_ipad.copy_from_slice(&ZERO_PAD);

    sha.input(&text)?;

    let mut digest = sha.finalize()?;

    sha.input(&k_opad)?;

    // zero any potentially sensitive data
    k_opad.copy_from_slice(&ZERO_PAD);

    sha.input(&digest)?;

    // zero any potentially sensitive data
    digest.copy_from_slice(&ZERO_PAD[..isha1::DIGEST_LEN]);

    sha.finalize()
}

/// Calculate HMAC-SHA256 of a given text using the provided key
pub fn hmac_sha256(text: &[u8], key: &[u8]) -> Result<[u8; isha256::DIGEST_LEN], isha256::Error> {
    let key_len = key.len();

    let mut k_ipad = [0_u8; PAD_LEN];
    let mut k_opad = [0_u8; PAD_LEN];

    if key_len > PAD_LEN {
        let mut digest = isha256::Sha256::digest(&key)?;
        k_ipad[..isha256::DIGEST_LEN].copy_from_slice(digest.as_ref());
        k_opad[..isha256::DIGEST_LEN].copy_from_slice(digest.as_ref());
        digest.copy_from_slice(&ZERO_PAD[..isha256::DIGEST_LEN]);
    } else {
        k_ipad[..key_len].copy_from_slice(&key);
        k_opad[..key_len].copy_from_slice(&key);
    }

    for (ipad, opad) in k_ipad.iter_mut().zip(k_opad.iter_mut()) {
        *ipad ^= 0x36;
        *opad ^= 0x5c;
    }

    let mut sha = isha256::Sha256::new();

    sha.input(&k_ipad)?;

    // zero any potentially sensitive data
    k_ipad.copy_from_slice(&ZERO_PAD);

    sha.input(&text)?;

    let mut digest = sha.finalize()?;

    sha.input(&k_opad)?;

    // zero any potentially sensitive data
    k_opad.copy_from_slice(&ZERO_PAD);

    sha.input(&digest)?;

    // zero any potentially sensitive data
    digest.copy_from_slice(&ZERO_PAD[..isha256::DIGEST_LEN]);

    sha.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    // HMAC-SHA1 + HMAC-SHA256 test vectors from RFC-4634: https://tools.ietf.org/rfc/rfc4634.txt
    #[test]
    fn check_hmac_sha_one() {
        let key = [0x0b; 20];
        let data = b"Hi There";
        let expected_sha1 = [
            0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64, 0xe2, 0x8b, 0xc0, 0xb6, 0xfb, 0x37,
            0x8c, 0x8e, 0xf1, 0x46, 0xbe, 0x00,
        ];
        let expected_sha256 = [
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
            0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
            0x2e, 0x32, 0xcf, 0xf7,
        ];

        let result_sha1 = hmac_sha1(data.as_ref(), key.as_ref()).unwrap();
        let result_sha256 = hmac_sha256(data.as_ref(), key.as_ref()).unwrap();

        assert_eq!(result_sha1, expected_sha1);
        assert_eq!(result_sha256, expected_sha256);
    }

    #[test]
    fn check_hmac_sha_two() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let expected_sha1 = [
            0xef, 0xfc, 0xdf, 0x6a, 0xe5, 0xeb, 0x2f, 0xa2, 0xd2, 0x74, 0x16, 0xd5, 0xf1, 0x84,
            0xdf, 0x9c, 0x25, 0x9a, 0x7c, 0x79,
        ];
        let expected_sha256 = [
            0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95,
            0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9,
            0x64, 0xec, 0x38, 0x43,
        ];

        let result_sha1 = hmac_sha1(data.as_ref(), key.as_ref()).unwrap();
        let result_sha256 = hmac_sha256(data.as_ref(), key.as_ref()).unwrap();
        assert_eq!(result_sha1, expected_sha1);
        assert_eq!(result_sha256, expected_sha256);
    }

    #[test]
    fn check_hmac_sha_three() {
        let key = [0xaa; 20];
        let data = [0xdd; 50];
        let expected_sha1 = [
            0x12, 0x5d, 0x73, 0x42, 0xb9, 0xac, 0x11, 0xcd, 0x91, 0xa3, 0x9a, 0xf4, 0x8a, 0xa1,
            0x7b, 0x4f, 0x63, 0xf1, 0x75, 0xd3,
        ];
        let expected_sha256 = [
            0x77, 0x3e, 0xa9, 0x1e, 0x36, 0x80, 0x0e, 0x46, 0x85, 0x4d, 0xb8, 0xeb, 0xd0, 0x91,
            0x81, 0xa7, 0x29, 0x59, 0x09, 0x8b, 0x3e, 0xf8, 0xc1, 0x22, 0xd9, 0x63, 0x55, 0x14,
            0xce, 0xd5, 0x65, 0xfe,
        ];

        let result_sha1 = hmac_sha1(data.as_ref(), key.as_ref()).unwrap();
        let result_sha256 = hmac_sha256(data.as_ref(), key.as_ref()).unwrap();
        assert_eq!(result_sha1, expected_sha1);
        assert_eq!(result_sha256, expected_sha256);
    }

    #[test]
    fn check_hmac_sha_four() {
        let key = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
        ];
        let data = [0xcd; 50];
        let expected_sha1 = [
            0x4c, 0x90, 0x07, 0xf4, 0x02, 0x62, 0x50, 0xc6, 0xbc, 0x84, 0x14, 0xf9, 0xbf, 0x50,
            0xc8, 0x6c, 0x2d, 0x72, 0x35, 0xda,
        ];
        let expected_sha256 = [
            0x82, 0x55, 0x8a, 0x38, 0x9a, 0x44, 0x3c, 0x0e, 0xa4, 0xcc, 0x81, 0x98, 0x99, 0xf2,
            0x08, 0x3a, 0x85, 0xf0, 0xfa, 0xa3, 0xe5, 0x78, 0xf8, 0x07, 0x7a, 0x2e, 0x3f, 0xf4,
            0x67, 0x29, 0x66, 0x5b,
        ];

        let result_sha1 = hmac_sha1(data.as_ref(), key.as_ref()).unwrap();
        let result_sha256 = hmac_sha256(data.as_ref(), key.as_ref()).unwrap();
        assert_eq!(result_sha1, expected_sha1);
        assert_eq!(result_sha256, expected_sha256);
    }

    #[test]
    fn check_hmac_sha1_five() {
        let key = [0xc; 20];
        let data = b"Test With Truncation";
        let expected_sha1 = [
            0x4c, 0x1a, 0x03, 0x42, 0x4b, 0x55, 0xe0, 0x7f, 0xe7, 0xf2, 0x7b, 0xe1,
        ];
        let expected_sha256 = [
            0xa3, 0xb6, 0x16, 0x74, 0x73, 0x10, 0x0e, 0xe0, 0x6e, 0x0c, 0x79, 0x6c, 0x29, 0x55,
            0x55, 0x2b,
        ];

        let result_sha1 = hmac_sha1(data.as_ref(), key.as_ref()).unwrap();
        let result_sha256 = hmac_sha256(data.as_ref(), key.as_ref()).unwrap();
        assert_eq!(result_sha1[..12], expected_sha1[..]);
        assert_eq!(result_sha256[..16], expected_sha256[..]);
    }

    #[test]
    fn check_hmac_sha_six() {
        let key = [0xaa; 131];
        let data = b"Test Using Larger Than Block-Size Key - Hash Key First";
        let expected_sha1 = [
            0xaa, 0x4a, 0xe5, 0xe1, 0x52, 0x72, 0xd0, 0x0e, 0x95, 0x70, 0x56, 0x37, 0xce, 0x8a,
            0x3b, 0x55, 0xed, 0x40, 0x21, 0x12,
        ];
        let expected_sha256 = [
            0x60, 0xe4, 0x31, 0x59, 0x1e, 0xe0, 0xb6, 0x7f, 0x0d, 0x8a, 0x26, 0xaa, 0xcb, 0xf5,
            0xb7, 0x7f, 0x8e, 0x0b, 0xc6, 0x21, 0x37, 0x28, 0xc5, 0x14, 0x05, 0x46, 0x04, 0x0f,
            0x0e, 0xe3, 0x7f, 0x54,
        ];

        let result_sha1 = hmac_sha1(data.as_ref(), key[..80].as_ref()).unwrap();
        let result_sha256 = hmac_sha256(data.as_ref(), key.as_ref()).unwrap();
        assert_eq!(result_sha1, expected_sha1);
        assert_eq!(result_sha256, expected_sha256);
    }

    #[test]
    fn check_hmac_sha_seven() {
        let key = [0xaa; 131];
        let data_sha1 =
            b"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data";
        let data_sha256 = b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.";
        let expected_sha1 = [
            0xe8, 0xe9, 0x9d, 0x0f, 0x45, 0x23, 0x7d, 0x78, 0x6d, 0x6b, 0xba, 0xa7, 0x96, 0x5c,
            0x78, 0x08, 0xbb, 0xff, 0x1a, 0x91,
        ];
        let expected_sha256 = [
            0x9b, 0x09, 0xff, 0xa7, 0x1b, 0x94, 0x2f, 0xcb, 0x27, 0x63, 0x5f, 0xbc, 0xd5, 0xb0,
            0xe9, 0x44, 0xbf, 0xdc, 0x63, 0x64, 0x4f, 0x07, 0x13, 0x93, 0x8a, 0x7f, 0x51, 0x53,
            0x5c, 0x3a, 0x35, 0xe2,
        ];

        let result_sha1 = hmac_sha1(data_sha1.as_ref(), key[..80].as_ref()).unwrap();
        let result_sha256 = hmac_sha256(data_sha256.as_ref(), key.as_ref()).unwrap();
        assert_eq!(result_sha1, expected_sha1);
        assert_eq!(result_sha256, expected_sha256);
    }
}
