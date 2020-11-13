use craes::{aes, cbc, ecb, pkcs7};

use cryptopals::user;

#[test]
fn challenge_nine() {
    // see craes/src/pkcs7.rs for full tests
    let mut msg = b"Y".to_vec();
    let mut padded = pkcs7::pad(&msg);

    // check when 15 padding bytes needed
    assert_eq!(padded.len(), aes::BLOCK_LEN);
    assert_eq!(padded[1..], [15_u8; 15][..]);

    msg.extend_from_slice(b"ELLOW ");
    padded = pkcs7::pad(&msg);

    // check when 8 padding bytes needed
    assert_eq!(padded.len(), aes::BLOCK_LEN);
    assert_eq!(padded[7..], [9_u8; 9][..]);

    msg.extend_from_slice(b"SUBMARINE");
    padded = pkcs7::pad(&msg);

    // check when no padding bytes needed
    assert_eq!(padded.len(), aes::BLOCK_LEN);
    assert_eq!(padded, msg);

    msg.extend_from_slice(b"!");
    padded = pkcs7::pad(&msg);

    // check when 15 padding bytes needed for next block
    assert_eq!(padded.len(), 2*aes::BLOCK_LEN);
    assert_eq!(padded[aes::BLOCK_LEN+1..], [15_u8; 15]);
}

#[test]
fn challenge_ten() {
    use std::io::Write;

    use crate::common::read_lines;
    use cryptopals::encoding::from_base64;

    let buf = read_lines("tests/res/set2_challenge10.txt");
    let ciphertext = from_base64(&buf).unwrap();

    let key = b"YELLOW SUBMARINE";
    let iv = [0_u8; cbc::IV_LEN];

    // Decrypt and write to a file, then read the mad skillz of the iceman
    let mut out = std::fs::File::create("tests/res/set2_challenge10.out").unwrap();
    out.write_all(&cbc::decrypt(&ciphertext, &key, &iv).unwrap()).unwrap();
}

#[test]
fn challenge_eleven() {
    use cryptopals::oracle::*;

    // supply a uniform message to the oracle
    let msg = [0_u8; aes::BLOCK_LEN * 3];

    // mode used here to validate the detection algorithm is working
    // for general purposes, the mode used to encrypt will be opaque
    let (ciph, mode) = oracle(&msg).unwrap();

    let detected_mode = detect_oracle(&ciph).unwrap();

    assert_eq!(detected_mode, mode);
}

#[test]
fn challenge_twelve() {
    use std::io::Write;
    use rand::thread_rng;

    use cryptopals::oracle;

    let key = oracle::gen_rand_key(&mut thread_rng());

    let det_msg = [0x41; aes::BLOCK_LEN * 3];

    // Detect the block size of the ECB oracle
    assert_eq!(oracle::detect_block_size().unwrap(), aes::BLOCK_LEN);

    // Detect the oracle is encrypting using ECB mode
    let ecb_out = oracle::ecb_oracle(&det_msg, &key).unwrap();
    assert_eq!(oracle::detect_oracle(&ecb_out).unwrap(), oracle::AesMode::Ecb);

    // Decrypt the unknown text a byte at a time
    let decrypted = oracle::decrypt_ecb_oracle_simple(&key).unwrap();

    let mut out = std::fs::File::create("tests/res/set2_challenge12.out").unwrap();
    out.write_all(decrypted.as_ref()).unwrap();
}

fn profile_for(email: &str) -> Result<(Vec<u8>, [u8; aes::KEY_LEN_128]), String> {
    let profile = user::Profile::from_email(email).map_err(|e| format!("{:?}", e))?;
    let prof_buf = format!("{}", profile);

    encrypt_profile(prof_buf.as_bytes())
}

fn encrypt_profile(profile: &[u8]) -> Result<(Vec<u8>, [u8; aes::KEY_LEN_128]), String> {
    use rand::thread_rng;
    use cryptopals::oracle::gen_rand_key;

    let key = gen_rand_key(&mut thread_rng());

    let ciph = ecb::encrypt(&pkcs7::pad(profile), &key).map_err(|e| format!("{:?}", e))?;

    Ok((ciph, key))
}

fn decrypt_profile(ciphertext: &[u8], key: &[u8; aes::KEY_LEN_128]) -> Result<user::Profile, String> {
    let prof_buf = ecb::decrypt(ciphertext, key).map_err(|e| format!("decryption: {:?}", e))?;
    let unpadded = pkcs7::unpad(&prof_buf).map_err(|e| format!("padding: {:?}", e))?;

    user::Profile::from_bytes(&unpadded).map_err(|e| format!("profile: {:?}", e))
}

#[test]
fn challenge_thirteen() {
    // # = 10
    // % = 11
    // $ = 12
    // ^ = 19
    // email=########## admin%%%%%%%%%%% ^^^^^^^^^^^^^^^^ ^^^&uid=10&role= user$$$$$$$$$$$$
    // ---------------- ---------------- ---------------- ---------------- ----------------
    let prof_string = core::str::from_utf8(&[10_u8; 10]).unwrap().to_string()
        + "admin"
        + core::str::from_utf8(&[11; 11]).unwrap()
        + core::str::from_utf8(&[19; 19]).unwrap();

    let (mut prof_ciph, key) = profile_for(&prof_string).unwrap();
    let copy = prof_ciph.clone();

    // remove the last block with the padded "user" string
    for _i in 0..aes::BLOCK_LEN { prof_ciph.pop(); }

    // replace with the padded "admin" string
    prof_ciph.extend_from_slice(&copy[aes::BLOCK_LEN..aes::BLOCK_LEN*2]);

    let exp_profile = user::Profile{ email: prof_string.as_bytes().to_vec(), uid: 10, role: b"admin".to_vec() };
    let profile = decrypt_profile(&prof_ciph, &key).unwrap();

    assert_eq!(profile, exp_profile);
}

#[test]
fn challenge_fourteen() {
    use std::io::Write;

    use cryptopals::oracle;

    let rand_oracle = oracle::RandEcbOracle::new();

    // Decrypt the unknown text a byte at a time
    let decrypted = oracle::decrypt_ecb_oracle_hard(&rand_oracle).unwrap();

    let mut out = std::fs::File::create("tests/res/set2_challenge14.out").unwrap();
    out.write_all(decrypted.as_ref()).unwrap();
}

#[test]
fn challenge_fifteen() {
    let ice_baby = b"ICE ICE BABY".to_vec();
    let mut good_pad = ice_baby.clone();
    good_pad.extend_from_slice(&[4_u8; 4]);

    assert_eq!(pkcs7::unpad(&good_pad).unwrap()[..], ice_baby[..]);

    for bad_pad in [[5_u8; 4], [1_u8, 2_u8, 3_u8, 4_u8]].iter() {
        let mut s = ice_baby.clone();
        s.extend_from_slice(bad_pad);
        assert!(pkcs7::unpad(bad_pad.as_ref()).is_err());
    }
}

#[test]
fn challenge_sixteen() {
    use cryptopals::oracle;

    // 32 bytes | user-data | 43 bytes
    // 
    // + = arbitrary byte
    // : = 0x3a (";" ^ 1)
    // < = 0x3c ("=" ^ 1)
    //
    // ++++++++++++++++ :admin<true:++++
    // ---------------- ----------------
    // 0     6    11
    let attempt = core::str::from_utf8(&[0x41_u8; 16]).unwrap().to_string()
        + ":admin<true:++++";

    let mut cbc_output = oracle::cbc_oracle(attempt.as_bytes()).unwrap();

    // create the edits in the first block of user-input
    cbc_output.ciphertext[32] ^= 1;
    cbc_output.ciphertext[38] ^= 1;
    cbc_output.ciphertext[43] ^= 1;

    assert!(oracle::cbc_oracle_found_admin(&cbc_output).unwrap());

}
