use std::thread::sleep;
use std::time;

use rand::{thread_rng, Rng};

use cryptopals::mac::hmac_sha1;

#[test]
fn challenge_twenty_five() {
    use crate::common::read_lines;
    use cryptopals::ctr::edit;
    use cryptopals::encoding::from_base64;

    let editor = edit::EditCtr::new();
    let b64 = read_lines("tests/res/set4_challenge25.txt");
    let plaintext = from_base64(&b64).unwrap();

    let ciphertext = editor.encrypt(&plaintext);

    let mut recovered_plaintext: Vec<u8> = Vec::with_capacity(plaintext.len());

    for (i, byte) in ciphertext.iter().enumerate() {
        // edit the ciphertext with a zero-byte to recover the keystream byte (lol much secure)
        let nc = editor.edit(&ciphertext, i, 0).unwrap();
        recovered_plaintext.push(nc[i] ^ byte);
    }

    assert_eq!(recovered_plaintext, plaintext);
}

#[test]
fn challenge_twenty_six() {
    use cryptopals::ctr::bitflip;

    let bitflipper = bitflip::BitFlipper::new();
    // bit-flipped target string
    // when target positions are XORed with one, results in the target string
    let user_data = b":admin<true:";

    let mut ciphertext = bitflipper.encrypt(user_data.as_ref());

    for &pos in [32, 38, 43].iter() {
        ciphertext[pos] ^= 1;
    }

    assert!(bitflipper.found_admin(&ciphertext));
}

#[test]
fn challenge_twenty_seven() {
    use craes::aes::BLOCK_LEN;
    use cryptopals::oracle::{cbc_oracle, cbc_oracle_detect_high_ascii, Error};

    // three blocks of trash
    let user_data = b"YELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINE";

    let mut output = cbc_oracle(user_data.as_ref()).unwrap();

    let block_one = output.ciphertext[..BLOCK_LEN].to_vec();

    // set the second ciphertext block to all zeroes
    output.ciphertext[BLOCK_LEN..BLOCK_LEN * 2].copy_from_slice(&[0; BLOCK_LEN]);

    // set the third ciphertext block to the first ciphertext block
    // this results in the plaintext: decrypt(ciphertexttext[0]) ^ 0..0
    // the first ciphertext block will get decrypted and XORed with the IV
    output.ciphertext[BLOCK_LEN * 2..BLOCK_LEN * 3].copy_from_slice(&block_one);

    // set the IV to the key, so first plaintext block:
    // decrypt(ciphertext[0]) ^ key
    // simulates the receiver app following the faulty protocol described in the challenge text
    output.iv = output.key;

    // as the attacker, retrieve the plaintext from the high ASCII decryption error
    let plaintext = match cbc_oracle_detect_high_ascii(&output) {
        Ok(()) => panic!("failed to generate high ASCII values in the plaintext"),
        Err(Error::CbcHighAscii(e)) => e,
        Err(e) => panic!("unexpected error: {:?}", e),
    };

    // since plaintext[0] = decrypt(ciphertext[0]) ^ key,
    // and plaintext[2] = decrypt(ciphertext[0])
    // plaintext[0] ^ plaintext[2] == key
    let found_key = craes::xor(
        &plaintext[..BLOCK_LEN],
        &plaintext[BLOCK_LEN * 2..BLOCK_LEN * 3],
    )
    .unwrap();

    assert_eq!(found_key.as_slice(), output.key.as_ref());
}

#[test]
fn challenge_twenty_eight() {
    use cryptopals::mac::Sha1SecretMac;

    let mut msg = b"real or random?".to_vec();

    let key = 0x420691337_u128;

    for i in 0..=255 {
        let i_macer = Sha1SecretMac::from_key(key + i);
        let i_mac = i_macer.mac(msg.as_ref()).unwrap();

        for j in 0..=255 {
            if i != j {
                let j_macer = Sha1SecretMac::from_key(key + j);
                let j_mac = j_macer.mac(msg.as_ref()).unwrap();

                // "prove" that we can't find a collision using a different key
                assert!(j_mac != i_mac);
            }
        }
    }

    let orig_msg = msg.clone();
    let macer = Sha1SecretMac::new();
    let mac = macer.mac(msg.as_ref()).unwrap();

    for i in 0..=255 {
        if orig_msg[0] != i {
            msg[0] = i;
        } else {
            msg[1] = i;
        }

        let new_mac = macer.mac(msg.as_ref()).unwrap();

        // "prove" that we can't find a collision using a different message
        assert!(new_mac != mac);
    }
}

#[test]
fn challenge_twenty_nine() {
    use cryptopals::mac::Sha1SecretMac;

    let key = 0x4_2069_1337_u128;
    let orig_msg = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";

    // for convenience, create the full message to get the proper length needed for padding
    let mut full_msg = key.to_le_bytes().to_vec();
    full_msg.extend_from_slice(orig_msg.as_ref());

    let macer = Sha1SecretMac::from_key(key);

    // simulate getting a secret-prefix MAC of the original message
    let orig_mac = macer.mac(orig_msg.as_ref()).unwrap();

    // attacker appends forged message, and calculates a new signature without knowledge of the key
    let forge_msg = b";admin=true";

    // copy the original message and padding, without the secret key
    // represents info available to the attacker
    let mut full_forge_msg = orig_msg.to_vec();

    let mut msg_padding = isha1::Sha1::pad_message(&full_msg).unwrap();

    msg_padding.extend_from_slice(forge_msg.as_ref());

    full_forge_msg.extend_from_slice(&msg_padding);

    // forge a MAC with the SHA-1 state fixed at the result of the original MAC
    let total_forge_len = ((core::mem::size_of_val(&key) + full_forge_msg.len()) * 8) as u64;
    let forge_mac = macer
        .mac_from_mac(forge_msg.as_ref(), &orig_mac, total_forge_len)
        .unwrap();

    // simulate supplying the full forged message to the original MACer
    let new_mac = macer.mac(&full_forge_msg).unwrap();

    // verify it matches the forged MAC
    assert_eq!(forge_mac, new_mac);
}

#[test]
fn challenge_thirty() {
    use cryptopals::mac::Md4SecretMac;

    let key = 0x4_2069_1337_u128;
    let orig_msg = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";

    // for convenience, create the full message to get the proper length needed for padding
    let mut full_msg = key.to_le_bytes().to_vec();
    full_msg.extend_from_slice(orig_msg.as_ref());

    let macer = Md4SecretMac::from_key(key);

    // simulate getting a secret-prefix MAC of the original message
    let orig_mac = macer.mac(orig_msg.as_ref()).unwrap();

    // attacker appends forged message, and calculates a new signature without knowledge of the key
    let forge_msg = b";admin=true";

    // copy the original message and padding, without the secret key
    // represents info available to the attacker
    let mut full_forge_msg = orig_msg.to_vec();

    let mut msg_padding = bmd4::Md4::pad_message(&full_msg).unwrap();

    msg_padding.extend_from_slice(forge_msg.as_ref());

    full_forge_msg.extend_from_slice(&msg_padding);

    // forge a MAC with the SHA-1 state fixed at the result of the original MAC
    let total_forge_len = ((core::mem::size_of_val(&key) + full_forge_msg.len()) * 8) as u64;
    let forge_mac = macer
        .mac_from_mac(forge_msg.as_ref(), &orig_mac, total_forge_len)
        .unwrap();

    // simulate supplying the full forged message to the original MACer
    let new_mac = macer.mac(&full_forge_msg).unwrap();

    // verify it matches the forged MAC
    assert_eq!(forge_mac, new_mac);
}

// normally would put this stuff in the library, but requires `std`
// for sleep and timing
//
// not going to make the library require `std` for two challenges...
const WAIT_MS: u64 = 20000;
const WAIT_SHORT_MS: u64 = 5000;

#[derive(Clone)]
pub struct InsecureHmacer {
    key: u128,
    // time to wait in insecure_compare
    wait: u64,
}

impl InsecureHmacer {
    /// Create a new InsecureHmacer with random key
    pub fn new(wait: u64) -> Self {
        Self {
            key: thread_rng().gen_range::<u128, u128, u128>(1, core::u128::MAX),
            wait: wait,
        }
    }

    pub fn validate_signature(
        &self,
        file_data: &[u8],
        signature: &[u8; isha1::DIGEST_LEN],
    ) -> Result<bool, isha1::Error> {
        let comp_sig = hmac_sha1(file_data, self.key.to_le_bytes().as_ref())?;
        Ok(Self::insecure_compare(&comp_sig, &signature, self.wait))
    }

    fn insecure_compare(
        sig_el: &[u8; isha1::DIGEST_LEN],
        sig_ar: &[u8; isha1::DIGEST_LEN],
        wait: u64,
    ) -> bool {
        for (el, ar) in sig_el.iter().zip(sig_ar.iter()) {
            sleep(time::Duration::from_micros(wait));
            if el != ar {
                return false;
            }
        }
        true
    }
}

fn inner_timing_loop(
    hmac: InsecureHmacer,
    bad_sig: &mut [u8; isha1::DIGEST_LEN],
    text: &[u8],
    i: usize,
    beg: u8,
    end: u8,
    ) -> bool {
    let wait = WAIT_MS as u128;
    let jitter = wait / 2;
    let delta_lim = WAIT_MS as u128 * (i + 1) as u128 + jitter;
    loop {
        for j in beg..=end {
            bad_sig[i] = j;
            let now = time::Instant::now();
            if hmac.validate_signature(text.as_ref(), &bad_sig).unwrap() {
                return true;
            }
            let delta = now.elapsed().as_micros();

            if delta > delta_lim {
                return true;
            }
        }

        return false;
    }
}

fn inner_timing_loop_short(
    hmac: InsecureHmacer,
    bad_sig: &mut [u8; isha1::DIGEST_LEN],
    text: &[u8],
    i: usize,
    beg: u8,
    end: u8,
    ) -> bool {
    let i_u128 = i as u128;
    let wait = WAIT_SHORT_MS as u128;
    let jitter = wait / 750 * (i_u128 + 1);
    let delta_lim = wait * (i_u128 + 2) + jitter;
    loop {
        for j in beg..=end {
            bad_sig[i] = j;
            let now = time::Instant::now();
            if hmac.validate_signature(text.as_ref(), &bad_sig).unwrap() {
                return true;
            }
            let delta = now.elapsed().as_micros();

            if delta >= delta_lim {
                return true;
            }
        }

        return false;
    }
}

fn time_thread(
    hmac: InsecureHmacer,
    bad_sig: &[u8; isha1::DIGEST_LEN],
    text: &'static [u8],
    i: usize,
    beg: u8,
    end: u8,
    ) -> std::thread::JoinHandle<Result<u8, isha1::Error>> {
    let mut bad_sig_t = bad_sig.clone();
    let hm = hmac.clone();
    let t = text.clone();

    std::thread::spawn(move || {
        if inner_timing_loop(hm, &mut bad_sig_t, t.as_ref(), i, beg, end) {
            return Ok(bad_sig_t[i]);
        } else {
            return Err(isha1::Error::InvalidLength);
        }
    })
}

fn time_thread_short(
    hmac: InsecureHmacer,
    bad_sig: &[u8; isha1::DIGEST_LEN],
    text: &'static [u8],
    i: usize,
    beg: u8,
    end: u8,
    ) -> std::thread::JoinHandle<Result<u8, isha1::Error>> {
    let mut bad_sig_t = bad_sig.clone();
    let hm = hmac.clone();
    let t = text.clone();

    std::thread::spawn(move || {
        if inner_timing_loop_short(hm, &mut bad_sig_t, t.as_ref(), i, beg, end) {
            return Ok(bad_sig_t[i]);
        } else {
            return Err(isha1::Error::InvalidLength);
        }
    })
}

#[test]
fn challenge_thirty_one() {
    let insec_hmac = InsecureHmacer::new(WAIT_MS);

    let file_text = b"Is this the real life, is this just fantasy?";

    let bad_key = 0x00_u128;

    let mut bad_sig = hmac_sha1(file_text.as_ref(), bad_key.to_le_bytes().as_ref()).unwrap();

    for i in 0..isha1::DIGEST_LEN {
        // spawn 32 threads to counter the artificial wait caused by the sleep in insecure_compare
        let t00 = time_thread(insec_hmac.clone(), &bad_sig, file_text.as_ref(), i, 0x00, 0x07);
        let t01 = time_thread(insec_hmac.clone(), &bad_sig, file_text.as_ref(), i, 0x08, 0x0f);

        let t10 = time_thread(insec_hmac.clone(), &bad_sig, file_text.as_ref(), i, 0x10, 0x17);
        let t11 = time_thread(insec_hmac.clone(), &bad_sig, file_text.as_ref(), i, 0x18, 0x1f);

        let t20 = time_thread(insec_hmac.clone(), &bad_sig, file_text.as_ref(), i, 0x20, 0x27);
        let t21 = time_thread(insec_hmac.clone(), &bad_sig, file_text.as_ref(), i, 0x28, 0x2f);

        let t30 = time_thread(insec_hmac.clone(), &bad_sig, file_text.as_ref(), i, 0x30, 0x37);
        let t31 = time_thread(insec_hmac.clone(), &bad_sig, file_text.as_ref(), i, 0x38, 0x3f);

        let t40 = time_thread(insec_hmac.clone(), &bad_sig, file_text.as_ref(), i, 0x40, 0x47);
        let t41 = time_thread(insec_hmac.clone(), &bad_sig, file_text.as_ref(), i, 0x48, 0x4f);

        let t50 = time_thread(insec_hmac.clone(), &bad_sig, file_text.as_ref(), i, 0x50, 0x57);
        let t51 = time_thread(insec_hmac.clone(), &bad_sig, file_text.as_ref(), i, 0x58, 0x5f);

        let t60 = time_thread(insec_hmac.clone(), &bad_sig, file_text.as_ref(), i, 0x60, 0x67);
        let t61 = time_thread(insec_hmac.clone(), &bad_sig, file_text.as_ref(), i, 0x68, 0x6f);

        let t70 = time_thread(insec_hmac.clone(), &bad_sig, file_text.as_ref(), i, 0x70, 0x77);
        let t71 = time_thread(insec_hmac.clone(), &bad_sig, file_text.as_ref(), i, 0x78, 0x7f);

        let t80 = time_thread(insec_hmac.clone(), &bad_sig, file_text.as_ref(), i, 0x80, 0x87);
        let t81 = time_thread(insec_hmac.clone(), &bad_sig, file_text.as_ref(), i, 0x88, 0x8f);

        let t90 = time_thread(insec_hmac.clone(), &bad_sig, file_text.as_ref(), i, 0x90, 0x97);
        let t91 = time_thread(insec_hmac.clone(), &bad_sig, file_text.as_ref(), i, 0x98, 0x9f);

        let ta0 = time_thread(insec_hmac.clone(), &bad_sig, file_text.as_ref(), i, 0xa0, 0xa7);
        let ta1 = time_thread(insec_hmac.clone(), &bad_sig, file_text.as_ref(), i, 0xa8, 0xaf);

        let tb0 = time_thread(insec_hmac.clone(), &bad_sig, file_text.as_ref(), i, 0xb0, 0xb7);
        let tb1 = time_thread(insec_hmac.clone(), &bad_sig, file_text.as_ref(), i, 0xb8, 0xbf);

        let tc0 = time_thread(insec_hmac.clone(), &bad_sig, file_text.as_ref(), i, 0xc0, 0xc7);
        let tc1 = time_thread(insec_hmac.clone(), &bad_sig, file_text.as_ref(), i, 0xc8, 0xcf);

        let td0 = time_thread(insec_hmac.clone(), &bad_sig, file_text.as_ref(), i, 0xd0, 0xd7);
        let td1 = time_thread(insec_hmac.clone(), &bad_sig, file_text.as_ref(), i, 0xd8, 0xdf);

        let te0 = time_thread(insec_hmac.clone(), &bad_sig, file_text.as_ref(), i, 0xe0, 0xe7);
        let te1 = time_thread(insec_hmac.clone(), &bad_sig, file_text.as_ref(), i, 0xe8, 0xef);

        let tf0 = time_thread(insec_hmac.clone(), &bad_sig, file_text.as_ref(), i, 0xf0, 0xf7);
        let tf1 = time_thread(insec_hmac.clone(), &bad_sig, file_text.as_ref(), i, 0xf8, 0xff);

        if let Ok(res) = t00.join().unwrap() {
            bad_sig[i] = res;
            continue;
        } else if let Ok(res) = t01.join().unwrap() {
            bad_sig[i] = res;
            continue;
        } else if let Ok(res) = t10.join().unwrap() {
            bad_sig[i] = res;
            continue;
        } else if let Ok(res) = t11.join().unwrap() {
            bad_sig[i] = res;
            continue;
        } else if let Ok(res) = t20.join().unwrap() {
            bad_sig[i] = res;
            continue;
        } else if let Ok(res) = t21.join().unwrap() {
            bad_sig[i] = res;
            continue;
        } else if let Ok(res) = t30.join().unwrap() {
            bad_sig[i] = res;
            continue;
        } else if let Ok(res) = t31.join().unwrap() {
            bad_sig[i] = res;
            continue;
        } else if let Ok(res) = t40.join().unwrap() {
            bad_sig[i] = res;
            continue;
        } else if let Ok(res) = t41.join().unwrap() {
            bad_sig[i] = res;
            continue;
        } else if let Ok(res) = t50.join().unwrap() {
            bad_sig[i] = res;
            continue;
        } else if let Ok(res) = t51.join().unwrap() {
            bad_sig[i] = res;
            continue;
        } else if let Ok(res) = t60.join().unwrap() {
            bad_sig[i] = res;
            continue;
        } else if let Ok(res) = t61.join().unwrap() {
            bad_sig[i] = res;
            continue;
        } else if let Ok(res) = t70.join().unwrap() {
            bad_sig[i] = res;
            continue;
        } else if let Ok(res) = t71.join().unwrap() {
            bad_sig[i] = res;
            continue;
        } else if let Ok(res) = t80.join().unwrap() {
            bad_sig[i] = res;
            continue;
        } else if let Ok(res) = t81.join().unwrap() {
            bad_sig[i] = res;
            continue;
        } else if let Ok(res) = t90.join().unwrap() {
            bad_sig[i] = res;
            continue;
        } else if let Ok(res) = t91.join().unwrap() {
            bad_sig[i] = res;
            continue;
        } else if let Ok(res) = ta0.join().unwrap() {
            bad_sig[i] = res;
            continue;
        } else if let Ok(res) = ta1.join().unwrap() {
            bad_sig[i] = res;
            continue;
        } else if let Ok(res) = tb0.join().unwrap() {
            bad_sig[i] = res;
            continue;
        } else if let Ok(res) = tb1.join().unwrap() {
            bad_sig[i] = res;
            continue;
        } else if let Ok(res) = tc0.join().unwrap() {
            bad_sig[i] = res;
            continue;
        } else if let Ok(res) = tc1.join().unwrap() {
            bad_sig[i] = res;
            continue;
        } else if let Ok(res) = td0.join().unwrap() {
            bad_sig[i] = res;
            continue;
        } else if let Ok(res) = td1.join().unwrap() {
            bad_sig[i] = res;
            continue;
        } else if let Ok(res) = te0.join().unwrap() {
            bad_sig[i] = res;
            continue;
        } else if let Ok(res) = te1.join().unwrap() {
            bad_sig[i] = res;
            continue;
        } else if let Ok(res) = tf0.join().unwrap() {
            bad_sig[i] = res;
            continue;
        } else if let Ok(res) = tf1.join().unwrap() {
            bad_sig[i] = res;
            continue;
        } else {
            let good_sig =
                hmac_sha1(file_text.as_ref(), insec_hmac.key.to_le_bytes().as_ref()).unwrap();
            assert!(
                false,
                "no byte found at index: {}\n\tgood sig: {:?}\n\tbad sig: {:?}",
                i, good_sig, bad_sig,
            );
        }
    }

    assert!(
        insec_hmac
            .validate_signature(file_text.as_ref(), &bad_sig)
            .unwrap(),
        "no valid signature found"
    );
}

#[test]
fn challenge_thirty_two() {
    let insec_hmac = InsecureHmacer::new(WAIT_SHORT_MS);

    let file_text = b"Is this the real life, is this just fantasy?";

    let bad_key = 0x00_u128;

    let mut bad_sig = hmac_sha1(file_text.as_ref(), bad_key.to_le_bytes().as_ref()).unwrap();

    for i in 0..isha1::DIGEST_LEN {
        // spawn 32 threads to counter the artificial wait caused by the sleep in insecure_compare
        let t00 = time_thread_short(insec_hmac.clone(), &bad_sig, file_text.as_ref(), i, 0x00, 0x07);
        let t01 = time_thread_short(insec_hmac.clone(), &bad_sig, file_text.as_ref(), i, 0x08, 0x0f);

        let t10 = time_thread_short(insec_hmac.clone(), &bad_sig, file_text.as_ref(), i, 0x10, 0x17);
        let t11 = time_thread_short(insec_hmac.clone(), &bad_sig, file_text.as_ref(), i, 0x18, 0x1f);

        let t20 = time_thread_short(insec_hmac.clone(), &bad_sig, file_text.as_ref(), i, 0x20, 0x27);
        let t21 = time_thread_short(insec_hmac.clone(), &bad_sig, file_text.as_ref(), i, 0x28, 0x2f);

        let t30 = time_thread_short(insec_hmac.clone(), &bad_sig, file_text.as_ref(), i, 0x30, 0x37);
        let t31 = time_thread_short(insec_hmac.clone(), &bad_sig, file_text.as_ref(), i, 0x38, 0x3f);

        let t40 = time_thread_short(insec_hmac.clone(), &bad_sig, file_text.as_ref(), i, 0x40, 0x47);
        let t41 = time_thread_short(insec_hmac.clone(), &bad_sig, file_text.as_ref(), i, 0x48, 0x4f);

        let t50 = time_thread_short(insec_hmac.clone(), &bad_sig, file_text.as_ref(), i, 0x50, 0x57);
        let t51 = time_thread_short(insec_hmac.clone(), &bad_sig, file_text.as_ref(), i, 0x58, 0x5f);

        let t60 = time_thread_short(insec_hmac.clone(), &bad_sig, file_text.as_ref(), i, 0x60, 0x67);
        let t61 = time_thread_short(insec_hmac.clone(), &bad_sig, file_text.as_ref(), i, 0x68, 0x6f);

        let t70 = time_thread_short(insec_hmac.clone(), &bad_sig, file_text.as_ref(), i, 0x70, 0x77);
        let t71 = time_thread_short(insec_hmac.clone(), &bad_sig, file_text.as_ref(), i, 0x78, 0x7f);

        let t80 = time_thread_short(insec_hmac.clone(), &bad_sig, file_text.as_ref(), i, 0x80, 0x87);
        let t81 = time_thread_short(insec_hmac.clone(), &bad_sig, file_text.as_ref(), i, 0x88, 0x8f);

        let t90 = time_thread_short(insec_hmac.clone(), &bad_sig, file_text.as_ref(), i, 0x90, 0x97);
        let t91 = time_thread_short(insec_hmac.clone(), &bad_sig, file_text.as_ref(), i, 0x98, 0x9f);

        let ta0 = time_thread_short(insec_hmac.clone(), &bad_sig, file_text.as_ref(), i, 0xa0, 0xa7);
        let ta1 = time_thread_short(insec_hmac.clone(), &bad_sig, file_text.as_ref(), i, 0xa8, 0xaf);

        let tb0 = time_thread_short(insec_hmac.clone(), &bad_sig, file_text.as_ref(), i, 0xb0, 0xb7);
        let tb1 = time_thread_short(insec_hmac.clone(), &bad_sig, file_text.as_ref(), i, 0xb8, 0xbf);

        let tc0 = time_thread_short(insec_hmac.clone(), &bad_sig, file_text.as_ref(), i, 0xc0, 0xc7);
        let tc1 = time_thread_short(insec_hmac.clone(), &bad_sig, file_text.as_ref(), i, 0xc8, 0xcf);

        let td0 = time_thread_short(insec_hmac.clone(), &bad_sig, file_text.as_ref(), i, 0xd0, 0xd7);
        let td1 = time_thread_short(insec_hmac.clone(), &bad_sig, file_text.as_ref(), i, 0xd8, 0xdf);

        let te0 = time_thread_short(insec_hmac.clone(), &bad_sig, file_text.as_ref(), i, 0xe0, 0xe7);
        let te1 = time_thread_short(insec_hmac.clone(), &bad_sig, file_text.as_ref(), i, 0xe8, 0xef);

        let tf0 = time_thread_short(insec_hmac.clone(), &bad_sig, file_text.as_ref(), i, 0xf0, 0xf7);
        let tf1 = time_thread_short(insec_hmac.clone(), &bad_sig, file_text.as_ref(), i, 0xf8, 0xff);

        if let Ok(res) = t00.join().unwrap() {
            bad_sig[i] = res;
            continue;
        } else if let Ok(res) = t01.join().unwrap() {
            bad_sig[i] = res;
            continue;
        } else if let Ok(res) = t10.join().unwrap() {
            bad_sig[i] = res;
            continue;
        } else if let Ok(res) = t11.join().unwrap() {
            bad_sig[i] = res;
            continue;
        } else if let Ok(res) = t20.join().unwrap() {
            bad_sig[i] = res;
            continue;
        } else if let Ok(res) = t21.join().unwrap() {
            bad_sig[i] = res;
            continue;
        } else if let Ok(res) = t30.join().unwrap() {
            bad_sig[i] = res;
            continue;
        } else if let Ok(res) = t31.join().unwrap() {
            bad_sig[i] = res;
            continue;
        } else if let Ok(res) = t40.join().unwrap() {
            bad_sig[i] = res;
            continue;
        } else if let Ok(res) = t41.join().unwrap() {
            bad_sig[i] = res;
            continue;
        } else if let Ok(res) = t50.join().unwrap() {
            bad_sig[i] = res;
            continue;
        } else if let Ok(res) = t51.join().unwrap() {
            bad_sig[i] = res;
            continue;
        } else if let Ok(res) = t60.join().unwrap() {
            bad_sig[i] = res;
            continue;
        } else if let Ok(res) = t61.join().unwrap() {
            bad_sig[i] = res;
            continue;
        } else if let Ok(res) = t70.join().unwrap() {
            bad_sig[i] = res;
            continue;
        } else if let Ok(res) = t71.join().unwrap() {
            bad_sig[i] = res;
            continue;
        } else if let Ok(res) = t80.join().unwrap() {
            bad_sig[i] = res;
            continue;
        } else if let Ok(res) = t81.join().unwrap() {
            bad_sig[i] = res;
            continue;
        } else if let Ok(res) = t90.join().unwrap() {
            bad_sig[i] = res;
            continue;
        } else if let Ok(res) = t91.join().unwrap() {
            bad_sig[i] = res;
            continue;
        } else if let Ok(res) = ta0.join().unwrap() {
            bad_sig[i] = res;
            continue;
        } else if let Ok(res) = ta1.join().unwrap() {
            bad_sig[i] = res;
            continue;
        } else if let Ok(res) = tb0.join().unwrap() {
            bad_sig[i] = res;
            continue;
        } else if let Ok(res) = tb1.join().unwrap() {
            bad_sig[i] = res;
            continue;
        } else if let Ok(res) = tc0.join().unwrap() {
            bad_sig[i] = res;
            continue;
        } else if let Ok(res) = tc1.join().unwrap() {
            bad_sig[i] = res;
            continue;
        } else if let Ok(res) = td0.join().unwrap() {
            bad_sig[i] = res;
            continue;
        } else if let Ok(res) = td1.join().unwrap() {
            bad_sig[i] = res;
            continue;
        } else if let Ok(res) = te0.join().unwrap() {
            bad_sig[i] = res;
            continue;
        } else if let Ok(res) = te1.join().unwrap() {
            bad_sig[i] = res;
            continue;
        } else if let Ok(res) = tf0.join().unwrap() {
            bad_sig[i] = res;
            continue;
        } else if let Ok(res) = tf1.join().unwrap() {
            bad_sig[i] = res;
            continue;
        } else {
            let good_sig =
                hmac_sha1(file_text.as_ref(), insec_hmac.key.to_le_bytes().as_ref()).unwrap();
            assert!(
                false,
                "no byte found at index: {}\n\tgood sig: {:?}\n\tbad sig: {:?}",
                i, good_sig, bad_sig,
            );
        }
    }

    assert!(
        insec_hmac
            .validate_signature(file_text.as_ref(), &bad_sig)
            .unwrap(),
        "no valid signature found"
    );
}
