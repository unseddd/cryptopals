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
