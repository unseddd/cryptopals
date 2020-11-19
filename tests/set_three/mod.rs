use cryptopals::oracle;

#[test]
fn challenge_seventeen() {
    use std::io::Write;

    let pad_oracle = oracle::CbcPaddingOracle::new();
    let mut output = pad_oracle.encrypt().unwrap();

    let plaintext = oracle::decrypt_cbc_padding_oracle(&pad_oracle, &mut output).unwrap();

    let mut out = std::fs::File::create("tests/res/set3_challenge17.out").unwrap();
    out.write_all(&plaintext).unwrap();
}
