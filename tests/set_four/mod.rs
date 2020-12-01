#[test]
fn challenge_twenty_five() {
    use cryptopals::ctr::edit;
    use cryptopals::encoding::from_base64;
    use crate::common::read_lines;

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
    output.ciphertext[BLOCK_LEN..BLOCK_LEN*2].copy_from_slice(&[0; BLOCK_LEN]);

    // set the third ciphertext block to the first ciphertext block
    // this results in the plaintext: decrypt(ciphertexttext[0]) ^ 0..0 
    // the first ciphertext block will get decrypted and XORed with the IV
    output.ciphertext[BLOCK_LEN*2..BLOCK_LEN*3].copy_from_slice(&block_one);

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
    let found_key = craes::xor(&plaintext[..BLOCK_LEN], &plaintext[BLOCK_LEN*2..BLOCK_LEN*3]).unwrap();

    assert_eq!(found_key.as_slice(), output.key.as_ref());
}

#[test]
fn challenge_twenty_eight() {
    use cryptopals::mac::Sha1SecretMac;

    let mut msg = b"real or random?".to_vec();

    for i in 0..=255 {
        let i_macer = Sha1SecretMac::from_key(i);
        let i_mac = i_macer.mac(msg.as_ref()).unwrap();

        for j in 0..=255 {
            if i != j {
                let j_macer = Sha1SecretMac::from_key(j);
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
