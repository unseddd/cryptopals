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
        // add each byte in the ciphertext to its corresponding xor block
        for (i, byte) in ciphertext.iter().enumerate() {
            if i >= xor_blocks.len() {
                xor_blocks.resize(i + 1, Vec::new());
            }
            xor_blocks[i].push(*byte);
        }
        ciphertexts.push(ciphertext);

        // reset counter to generate same keystream for the next encryption
        count = 0;
    }

    (ciphertexts, xor_blocks)
}

fn decrypt_ctr_ciphertexts(ciphertexts: &Vec<Vec<u8>>, xor_blocks: &Vec<Vec<u8>>, file_name: &str) {
    use cryptopals::language::{build_english_trigrams, guess_single_xor_key_tri};

    let mut key: Vec<u8> = Vec::new();

    let trigrams = build_english_trigrams();

    for block in xor_blocks.iter() {
        let guess = guess_single_xor_key_tri(&block, &trigrams).unwrap();
        key.push(guess.key);
    }

    let mut out = std::fs::File::create(file_name).unwrap();
    for ciphertext in ciphertexts.iter() {
        let msg = craes::xor(&ciphertext, &key[..ciphertext.len()]).unwrap();
        out.write_all(&msg).unwrap();
        out.write_all(&[0x0a]).unwrap();
    }
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
