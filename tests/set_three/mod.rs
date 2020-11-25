use craes::ctr;

use cryptopals::oracle;
use cryptopals::encoding;

#[test]
fn challenge_seventeen() {
    use std::io::Write;

    let pad_oracle = oracle::CbcPaddingOracle::new();
    let mut output = pad_oracle.encrypt().unwrap();

    let plaintext = oracle::decrypt_cbc_padding_oracle(&pad_oracle, &mut output).unwrap();

    let mut out = std::fs::File::create("tests/res/set3_challenge17.out").unwrap();
    out.write_all(&plaintext).unwrap();
}

#[test]
fn challenge_eighteen() {
    use std::io::Write;

    let ciphertext = encoding::from_base64(b"L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==".as_ref()).unwrap();
    let key = b"YELLOW SUBMARINE";
    let nonce = 0_u64;
    let mut count = 0_u64;

    let plaintext = ctr::decrypt(&ciphertext, &key, nonce, &mut count, &ctr::Endian::Little);

    let mut out = std::fs::File::create("tests/res/set3_challenge14.out").unwrap();
    out.write_all(&plaintext).unwrap();
}
