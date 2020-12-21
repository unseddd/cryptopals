use num::bigint::BigUint;
use num::Integer;

use rand::{thread_rng, Rng};

#[test]
fn challenge_forty_one() {
    let msg = b"unreadable bytes";
    let sk = irsa::RsaPrivateKey::from_exponent(3, irsa::RSA_1024_LEN).unwrap();
    let pk = irsa::RsaPublicKey::from(&sk);
    let ciphertext = pk.encrypt(msg.as_ref()).unwrap();

    // S = random number > 1 < N
    let s = thread_rng().gen_range::<u128, u128, u128>(2, u128::MAX);
    let mut bn_s = BigUint::from_bytes_le(s.to_le_bytes().as_ref());
    bn_s = bn_s.mod_floor(&pk.n);

    // C' = ((S**E mod N) * C) mod N
    let mut c_prime = bn_s.modpow(&pk.e, &pk.n);
    let c_bn = BigUint::from_bytes_be(&ciphertext);
    c_prime *= &c_bn;
    c_prime = c_prime.mod_floor(&pk.n);

    // Submit C' to the "server" (fake it here by just decrypting)
    let p_prime = sk.decrypt(&c_prime.to_bytes_be()).unwrap();

    // invS = 1/S mod N
    let inv_s = irsa::inv_mod_slow(&bn_s, &pk.n).unwrap();

    // P = P'/S mod N
    let mut p = BigUint::from_bytes_be(&p_prime);
    p *= &inv_s;
    p = p.mod_floor(&pk.n);

    let recovered = p.to_bytes_be();

    assert_eq!(recovered[..], msg[..]);
}

#[test]
fn challenge_forty_two() {
    let forge_msg = b"hi mom";

    // encode the message using PKCS#1-v1.5
    let encoded =
        irsa::pkcs1v1_5::encode(forge_msg.as_ref(), irsa::RSA_1024_LEN / 8, irsa::Hash::Sha1)
            .unwrap();

    // ensure the leading forged message bytes follow PKCS#1-v1.5 format
    let mut forge_encoded = [0x00, 0x01, 0xff, 0x00].to_vec();

    // take the last bytes of the encoded message (ASN.1 || HASH(m))
    forge_encoded.extend_from_slice(&encoded[encoded.len() - 35..]);
    for _i in forge_encoded.len()..(irsa::RSA_1024_LEN / 8) {
        // fill the end with non-zero trash
        forge_encoded.push(0xff);
    }

    // cube root the result
    let forge_bn = BigUint::from_bytes_be(&forge_encoded);
    let forge_sig = forge_bn.cbrt().to_bytes_be();

    // create random 1024-bit private/public key with public exponent 3
    let priv_key = irsa::RsaPrivateKey::from_exponent(3, irsa::RSA_1024_LEN).unwrap();
    let pub_key = irsa::RsaPublicKey::from(&priv_key);

    // check that the forged message passes verification
    let res = pub_key
        .verify_pkcs1_v1_5_insecure(forge_msg.as_ref(), &forge_sig, irsa::Hash::Sha1)
        .unwrap();
    assert_eq!(res, irsa::Verification::Consistent);
}
