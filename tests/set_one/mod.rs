use cryptopals::{
    encoding::{from_base64, from_hex, from_hex_bytes, to_base64, xor, xor_key, xor_multi_key},
    language::{build_english_bigrams, guess_single_xor_key, Attempt},
};

#[test]
fn challenge_one() {
    let hex = from_hex("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d").unwrap();
    let exp_b64 = b"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
    let b64 = to_base64(&hex).unwrap();

    assert_eq!(b64[..], exp_b64[..]);
}

#[test]
fn challenge_two() {
    let xor_in = from_hex("1c0111001f010100061a024b53535009181c").unwrap();
    let xor_key = from_hex("686974207468652062756c6c277320657965").unwrap();
    let exp_xor = from_hex("746865206b696420646f6e277420706c6179").unwrap();
    let xor_out = xor(&xor_in, &xor_key).unwrap();

    assert_eq!(xor_out, exp_xor);
}

#[test]
fn challenge_three() {
    use cryptopals::language::{build_english_trigrams, guess_single_xor_key_tri};

    let ciphertext =
        from_hex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736").unwrap();

    let trigrams = build_english_trigrams();
    let winner = guess_single_xor_key_tri(&ciphertext, &trigrams).unwrap();

    let msg = xor_key(&ciphertext, winner.key).unwrap();
    println!("Found key: {:02x}, delta: {}", winner.key, winner.delta);
    println!("{}", core::str::from_utf8(&msg).unwrap());

    assert_eq!(msg[..], b"Cooking MC's like a pound of bacon"[..]);
}

// remove/comment #[ignore] to run/ignore
// takes too long to run normally
#[test]
fn challenge_four() {
    use std::io::prelude::*;

    let path = "tests/res/set1_challenge4.txt";
    let mut file = std::fs::File::open(path).unwrap();

    let mut line = [0u8; 60];
    let mut newline = [0u8; 1];

    let bigrams = build_english_bigrams();
    let mut winner = Attempt::new();

    let mut ciphertext = Vec::with_capacity(60);
    while let Ok(()) = file.read_exact(line.as_mut()) {
        let _ = file.read_exact(newline.as_mut());

        let bytes = from_hex_bytes(&line).unwrap();
        let maybe_winner = guess_single_xor_key(&bytes, &bigrams).unwrap();

        if winner.key == 0 || winner.delta > maybe_winner.delta {
            ciphertext = bytes;
            winner = maybe_winner;
        }
    }

    let msg = xor_key(&ciphertext, winner.key).unwrap();
    println!("Found key: {:02x}, delta: {}", winner.key, winner.delta);
    println!("{}", core::str::from_utf8(&msg).unwrap());

    assert_eq!(msg[..], b"Now that the party is jumping\n"[..]);
}

#[test]
fn challenge_five() {
    let input = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    let key = b"ICE";
    let expected = from_hex("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f").unwrap();

    assert_eq!(
        expected[..],
        xor_multi_key(input.as_ref(), key.as_ref())[..]
    );
}

#[test]
fn challenge_six() {
    use std::io::{Read, Write};

    use crate::common::{to_hex, read_lines};

    use cryptopals::hamming::{get_key_blocks, guess_key_length_multi};
    use cryptopals::language::{
        build_english_trigrams,
        guess_single_xor_key_tri,
        matches_trigram_distribution,
        observe_trigrams
    };

    let mut file = std::fs::File::open("tests/res/set1_challenge6.txt").unwrap();
    // File for troubleshooting this challenge
    // Contains an encryption with known plaintext and key
    //let mut file = std::fs::File::open("tests/res/set1_own_crypt.txt").unwrap();

    let mut buf: Vec<u8> = vec![0u8; file.metadata().unwrap().len() as usize];
    file.read_exact(&mut buf).unwrap();

    let b64: Vec<u8> = buf.iter().filter(|&&x| x != 0x0a).map(|&x| x).collect();
    let buf = read_lines("tests/res/set1_challenge6.txt");
    let ciphertext = from_base64(&b64).unwrap();

    let trigrams = build_english_trigrams();

    // guess key lengths, starting with key length 2
    let num_guesses = 4;
    let length_guesses = guess_key_length_multi(&ciphertext, 2, num_guesses).unwrap();

    let mut out_file = std::fs::File::create("tests/res/set1_challenge6.out").unwrap();
    // File for storing decryption attempts of the troubleshooting ciphertext
    //let mut out_file = std::fs::File::create("tests/res/set1_own_crypt.out").unwrap();
    for &key_len in length_guesses.iter() {
        let mut key: Vec<u8> = Vec::with_capacity(key_len);
        let blocks = get_key_blocks(&ciphertext, key_len);

        // guess the key bytes for each block based on trigrams
        for block in blocks.iter() {
            let guess = guess_single_xor_key_tri(&block, &trigrams).unwrap();
            // uncomment to use a simpler form of key guessing (faster, but less accurate)
            //let guess = guess_single_xor_key_simple(&block).unwrap();
            key.push(guess.key);
        }

        let msg = xor_multi_key(&ciphertext, &key);

        out_file
            .write_all(
                format!(
                    "key: {}\nkey length: {}\nmessage:\n{}\n\n",
                    to_hex(&key),
                    key_len,
                    core::str::from_utf8(&msg).unwrap(),
                )
                .as_bytes(),
            )
            .unwrap();
    }
}

// Test for troubleshooting challenge six
#[test]
#[ignore]
fn own_crypt() {
    use std::io::Write;

    let mut file = std::fs::File::create("tests/res/set1_own_crypt.txt").unwrap();

    // use repeating text at the beginning to help with guessing key length
    let plaintext = b"Repeating text: text text text text text text. In 1863, Friedrich Kasiski was the first to publish a successful general attack on the Vigenere cipher. Earlier attacks relied on knowledge of the plaintext or the use of a recognizable word as a key. Kasiski's method had no such dependencies. Although Kasiski was the first to publish an account of the attack, it is clear that others had been aware of it. In 1854, Charles Babbage was goaded into breaking the Vigenere cipher when John Hall Brock Thwaites submitted a 'new' cipher to the Journal of the Society of the Arts. When Babbage showed that Thwaites' cipher was essentially just another recreation of the Vigenere cipher, Thwaites presented a challenge to Babbage: given an original text (from Shakespeare's The Tempest : Act 1, Scene 2) and its enciphered version, he was to find the key words that Thwaites had used to encipher the original text. Babbage soon found the key words: 'two' and 'combined'. Babbage then enciphered the same passage from Shakespeare using different key words and challenged Thwaites to find Babbage's key words.[20] Babbage never explained the method that he used. Studies of Babbage's notes reveal that he had used the method later published by Kasiski and suggest that he had been using the method as early as 1846.";

    let key = b"FUCKMEUP";

    let ciphertext = xor_multi_key(&plaintext[..], &key[..]);

    file.write_all(&to_base64(&ciphertext).unwrap()).unwrap();
}

#[test]
fn challenge_seven() {
    use std::io::Write;
    use crate::common::read_lines;

    let key = b"YELLOW SUBMARINE";

    let buf = read_lines("tests/res/set1_challenge7.txt");
    let mut ciphertext = from_base64(&buf).unwrap();

    assert_eq!(ciphertext.len() % craes::aes::BLOCK_LEN, 0);

    let plaintext = craes::ecb::aes_inv_128_ecb(&ciphertext, &key).unwrap();

    let mut out_file = std::fs::File::create("tests/res/set1_challenge7.out").unwrap();
    out_file.write_all(&plaintext).unwrap();
}
