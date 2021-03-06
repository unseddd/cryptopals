use std::io::Write;

use craes::ctr;

use cryptopals::encoding::from_base64;
use cryptopals::oracle;

fn encrypt_ctr_plaintexts(plaintexts: &Vec<Vec<u8>>) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    use cryptopals::oracle::gen_rand_key;
    use rand::thread_rng;

    let len = plaintexts.len();

    let mut ciphertexts: Vec<Vec<u8>> = Vec::with_capacity(len);
    let mut xor_blocks: Vec<Vec<u8>> = Vec::with_capacity(len);

    let key = gen_rand_key(&mut thread_rng());
    let nonce = 0_u64;
    let mut count = 0_u64;

    for plaintext in plaintexts.iter() {
        let ciphertext = ctr::encrypt(&plaintext, &key, nonce, &mut count, &ctr::Endian::Little);

        get_ctr_xor_blocks(&ciphertext, &mut xor_blocks);

        ciphertexts.push(ciphertext);

        // reset counter to generate same keystream for the next encryption
        count = 0;
    }

    (ciphertexts, xor_blocks)
}

// Add each byte in the ciphertext to its corresponding xor block
fn get_ctr_xor_blocks(ciphertext: &Vec<u8>, xor_blocks: &mut Vec<Vec<u8>>) {
    for (i, byte) in ciphertext.iter().enumerate() {
        if i >= xor_blocks.len() {
            xor_blocks.resize(i + 1, Vec::new());
        }
        xor_blocks[i].push(*byte);
    }
}

fn decrypt_ctr_ciphertexts(ciphertexts: &Vec<Vec<u8>>, xor_blocks: &Vec<Vec<u8>>, file_name: &str) {
    let key = get_ctr_keystream(&xor_blocks);

    let mut out = std::fs::File::create(file_name).unwrap();
    for ciphertext in ciphertexts.iter() {
        let msg = craes::xor(&ciphertext, &key[..ciphertext.len()]).unwrap();
        out.write_all(&msg).unwrap();
        out.write_all(&[0x0a]).unwrap();
    }
}

fn get_ctr_keystream(xor_blocks: &Vec<Vec<u8>>) -> Vec<u8> {
    use cryptopals::language::{build_english_trigrams, guess_single_xor_key_tri};

    let mut key: Vec<u8> = Vec::new();

    let trigrams = build_english_trigrams();

    for block in xor_blocks.iter() {
        let guess = guess_single_xor_key_tri(&block, &trigrams).unwrap();
        key.push(guess.key);
    }

    key
}

#[test]
fn challenge_seventeen() {
    let pad_oracle = oracle::CbcPaddingOracle::new();
    let mut output = pad_oracle.encrypt().unwrap();

    let plaintext = oracle::decrypt_cbc_padding_oracle(&pad_oracle, &mut output).unwrap();

    let mut out = std::fs::File::create("tests/res/set3_challenge17.out").unwrap();
    out.write_all(&plaintext).unwrap();
}

#[test]
fn challenge_eighteen() {
    let ciphertext = from_base64(
        b"L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==".as_ref(),
    )
    .unwrap();
    let key = b"YELLOW SUBMARINE";
    let nonce = 0_u64;
    let mut count = 0_u64;

    let plaintext = ctr::decrypt(&ciphertext, &key, nonce, &mut count, &ctr::Endian::Little);

    let mut out = std::fs::File::create("tests/res/set3_challenge14.out").unwrap();
    out.write_all(&plaintext).unwrap();
}

#[test]
fn challenge_nineteen() {
    let plaintexts = vec![
        from_base64(b"SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==".as_ref()).unwrap(),
        from_base64(b"Q29taW5nIHdpdGggdml2aWQgZmFjZXM=".as_ref()).unwrap(),
        from_base64(b"RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==".as_ref()).unwrap(),
        from_base64(b"RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=".as_ref()).unwrap(),
        from_base64(b"SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk".as_ref()).unwrap(),
        from_base64(b"T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==".as_ref()).unwrap(),
        from_base64(b"T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=".as_ref()).unwrap(),
        from_base64(b"UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==".as_ref()).unwrap(),
        from_base64(b"QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=".as_ref()).unwrap(),
        from_base64(b"T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl".as_ref()).unwrap(),
        from_base64(b"VG8gcGxlYXNlIGEgY29tcGFuaW9u".as_ref()).unwrap(),
        from_base64(b"QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==".as_ref()).unwrap(),
        from_base64(b"QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=".as_ref()).unwrap(),
        from_base64(b"QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==".as_ref()).unwrap(),
        from_base64(b"QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=".as_ref()).unwrap(),
        from_base64(b"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=".as_ref()).unwrap(),
        from_base64(b"VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==".as_ref()).unwrap(),
        from_base64(b"SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==".as_ref()).unwrap(),
        from_base64(b"SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==".as_ref()).unwrap(),
        from_base64(b"VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==".as_ref()).unwrap(),
        from_base64(b"V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==".as_ref()).unwrap(),
        from_base64(b"V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==".as_ref()).unwrap(),
        from_base64(b"U2hlIHJvZGUgdG8gaGFycmllcnM/".as_ref()).unwrap(),
        from_base64(b"VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=".as_ref()).unwrap(),
        from_base64(b"QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=".as_ref()).unwrap(),
        from_base64(b"VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=".as_ref()).unwrap(),
        from_base64(b"V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=".as_ref()).unwrap(),
        from_base64(b"SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==".as_ref()).unwrap(),
        from_base64(b"U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==".as_ref()).unwrap(),
        from_base64(b"U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=".as_ref()).unwrap(),
        from_base64(b"VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==".as_ref()).unwrap(),
        from_base64(b"QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu".as_ref()).unwrap(),
        from_base64(b"SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=".as_ref()).unwrap(),
        from_base64(b"VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs".as_ref()).unwrap(),
        from_base64(b"WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=".as_ref()).unwrap(),
        from_base64(b"SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0".as_ref()).unwrap(),
        from_base64(b"SW4gdGhlIGNhc3VhbCBjb21lZHk7".as_ref()).unwrap(),
        from_base64(b"SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=".as_ref()).unwrap(),
        from_base64(b"VHJhbnNmb3JtZWQgdXR0ZXJseTo=".as_ref()).unwrap(),
        from_base64(b"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=".as_ref()).unwrap(),
    ];

    let (ciphertexts, xor_blocks) = encrypt_ctr_plaintexts(&plaintexts);
    decrypt_ctr_ciphertexts(&ciphertexts, &xor_blocks, "tests/res/set3_challenge19.out");
}

#[test]
fn challenge_twenty() {
    use crate::common::read_multi_lines;

    let b64s = read_multi_lines("tests/res/set3_challenge20.txt");

    let plaintexts = b64s
        .iter()
        .map(|b| from_base64(b.as_ref()).unwrap())
        .collect();

    let (ciphertexts, xor_blocks) = encrypt_ctr_plaintexts(&plaintexts);
    decrypt_ctr_ciphertexts(&ciphertexts, &xor_blocks, "tests/res/set3_challenge20.out");
}

#[test]
fn challenge_twenty_one() {
    use cryptopals::mersenne::{mt19937, mt19937_64};

    let expected_nums: [u32; 16] = [
        3499211612, 581869302, 3890346734, 3586334585, 545404204, 4161255391, 3922919429,
        949333985, 2715962298, 1323567403, 418932835, 2350294565, 1196140740, 809094426,
        2348838239, 4264392720,
    ];

    let mut generator = mt19937::Mt19937::new(5489);

    let mut extracted_nums = [0_u32; 16];

    for (i, expected) in expected_nums.iter().enumerate() {
        extracted_nums[i] = generator.extract_number();
        assert_eq!(*expected, extracted_nums[i]);
    }

    let expected_nums_64: [u64; 16] = [
        14514284786278117030,
        4620546740167642908,
        13109570281517897720,
        17462938647148434322,
        355488278567739596,
        7469126240319926998,
        4635995468481642529,
        418970542659199878,
        9604170989252516556,
        6358044926049913402,
        5058016125798318033,
        10349215569089701407,
        2583272014892537200,
        10032373690199166667,
        9627645531742285868,
        15810285301089087632,
    ];
    let mut extracted_nums_64 = [0_u64; 16];

    let mut generator_64 = mt19937_64::Mt19937::new(5489);

    for (i, expected) in expected_nums_64.iter().enumerate() {
        extracted_nums_64[i] = generator_64.extract_number();
        assert_eq!(*expected, extracted_nums_64[i]);
    }
}

#[test]
fn challenge_twenty_two() {
    use std::time::SystemTime;

    use rand::{thread_rng, Rng};

    use cryptopals::mersenne::{mt19937, recovery};

    let time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;

    let mut generator = mt19937::Mt19937::new(time);

    let rand_num = generator.extract_number();

    // simulate waiting a random number of seconds
    let wait_secs = thread_rng().gen_range::<u32, u32, u32>(40, 100_000);
    let sim_now = time + wait_secs;

    assert_eq!(recovery::recover_seed(rand_num, sim_now), time);
}

#[test]
fn challenge_twenty_three() {
    use rand::{thread_rng, RngCore};

    use cryptopals::mersenne::{mt19937, recovery};

    let mut generator = mt19937::Mt19937::new(thread_rng().next_u32());
    let mut clone_rng = recovery::clone(&mut generator).unwrap();

    for _i in 0..mt19937::N {
        assert_eq!(clone_rng.extract_number(), generator.extract_number());
    }
}

#[test]
fn challenge_twenty_four_a() {
    use core::convert::TryInto;

    use rand::{thread_rng, Rng};

    use cryptopals::mersenne::{recovery, stream};

    // Since the key recovery is probabilistic, more ciphertexts == more accuracy
    let num_ciphertexts = 169;

    let a_s = b"AAAAAAAAAA";
    let mut rng = thread_rng();

    let count = 0;

    let mut plaintexts: Vec<Vec<u8>> = Vec::with_capacity(num_ciphertexts);
    let mut ciphertexts: Vec<Vec<u8>> = Vec::with_capacity(num_ciphertexts);
    let mut xor_blocks: Vec<Vec<u8>> = Vec::with_capacity(num_ciphertexts);

    // Create a MT19937 stream cipher with a random 16-bit "key"
    let key = rng.gen_range::<u16, u16, u16>(1, 65535);
    let cipher = stream::Cipher::new(key);

    // Generate ciphertexts for the breaking
    for _i in 0..num_ciphertexts {
        let rand_len = rng.gen_range::<usize, usize, usize>(5, 32);
        let mut rand_bytes = vec![0_u8; rand_len];

        // fill with random characters in A-Z range
        for byte in rand_bytes.iter_mut() {
            *byte = rng.gen_range::<u8, u8, u8>(0x61, 0x7a);
        }

        rand_bytes.extend_from_slice(a_s.as_ref());

        let ciphertext = cipher.encrypt(&rand_bytes, count);

        plaintexts.push(rand_bytes);

        get_ctr_xor_blocks(&ciphertext, &mut xor_blocks);

        ciphertexts.push(ciphertext);
    }

    let keystream = get_ctr_keystream(&xor_blocks);

    // Sanity check to ensure the first generator output is recovered accurately
    for (plaintext, ciphertext) in plaintexts.iter().zip(ciphertexts.iter()) {
        let recovered_plaintext = craes::xor(&ciphertext, &keystream[..ciphertext.len()]).unwrap();
        assert_eq!(recovered_plaintext[..4], plaintext[..4]);
    }

    let first_output = u32::from_le_bytes(keystream[..4].try_into().unwrap());

    assert_eq!(recovery::recover_seed_u16(first_output), key);
}

#[test]
fn challenge_twenty_four_b() {
    use core::convert::TryInto;

    use std::time::SystemTime;

    use rand::{thread_rng, Rng};

    use cryptopals::mersenne::{password_token, recovery};

    let time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;

    let token = password_token::generate(time);

    // simulate waiting a random number of seconds
    let wait_secs = thread_rng().gen_range::<u32, u32, u32>(40, 100_000);
    let sim_now = time + wait_secs;

    let rand_num = u32::from_le_bytes(token[..4].try_into().unwrap());

    assert_eq!(recovery::recover_seed(rand_num, sim_now), time);
}

#[test]
fn challenge_twenty_four_c() {
    use std::time::SystemTime;

    use rand::{thread_rng, Rng};

    use cryptopals::mersenne::password_token;

    let time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;

    let token = password_token::generate(time);

    let mut bad_tokens: Vec<[u8; 16]> = Vec::with_capacity(4);

    let mut rng = thread_rng();

    // create random "tokens" filled with garbage
    for _i in 0..4 {
        let mut bad_token = [0_u8; 16];
        rng.fill(&mut bad_token);
        bad_tokens.push(bad_token);
    }

    // simulate waiting a random number of seconds
    let wait_secs = rng.gen_range::<u32, u32, u32>(40, 100_000);
    let sim_now = time + wait_secs;

    assert!(password_token::test_valid_token(&token, sim_now));

    for bad_token in bad_tokens.iter() {
        assert_eq!(password_token::test_valid_token(bad_token, sim_now), false);
    }
}
