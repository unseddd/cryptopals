use num::bigint::BigUint;
use num::Integer;

use rand::{thread_rng, Rng};

#[test]
fn challenge_forty_one() {
    let msg = b"unreadable bytes";
    let sk = irsa::RsaPrivateKey::from_exponent(3, irsa::RSA_1024_LEN).unwrap();
    let pk = irsa::RsaPublicKey::from(&sk);
    let ciphertext =  pk.encrypt(msg.as_ref()).unwrap();

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
