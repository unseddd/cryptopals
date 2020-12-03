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
