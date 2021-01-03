use num::bigint::BigUint;
use num::Integer;

use rand::{thread_rng, Rng};

use isha2::Sha2;
use prime_math::InvMod;

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
    let inv_s = bn_s.invmod(&pk.n);

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

#[test]
fn challenge_forty_three() {
    let msg = b"when I die, launch my body into the sun";
    let mut rng = thread_rng();

    // Generate DSA parameters and private key
    let primes = idsa::generate_prob_primes(
        idsa::L_1024,
        idsa::N_160,
        idsa::N_160,
        idsa::ParameterValidation::Discard,
        &mut rng,
    )
    .unwrap();
    let g = idsa::generate_unverifiable_g(&primes).unwrap();
    let private_key =
        idsa::DsaPrivateKey::from_parameters(primes, g, None, idsa::Trusted::True, &mut rng)
            .unwrap();

    // Sign according to FIPS 186-4, but insecurely return the secret nonce `k`
    let (r, s, k) = private_key.sign_insecure(msg.as_ref(), &mut rng).unwrap();

    // r_inv = 1 / r mod q
    let r_inv = r.invmod(private_key.q());
    let h_bytes = isha2::sha256::Sha256::digest(msg.as_ref()).unwrap();
    // h = H(msg)
    // take the leftmost 160-bits of H, because FIPS 186-4 tells us to
    let mut res = BigUint::from_bytes_be(&h_bytes[..idsa::N_160 as usize / 8]);
    // (s * k) - H(msg) / r mod q
    res = (((&s * &k) - &res) * &r_inv).mod_floor(private_key.q());
    // res == x
    assert_eq!(&res, private_key.x());
}

#[test]
fn challenge_forty_four() {
    use num::BigInt;

    let msg0 = b"courage is a practice, not something innate";
    let msg1 = b"everyone experiences fear, only how you deal with it matters";
    let mut rng = thread_rng();

    // Generate DSA parameters and private key
    let primes = idsa::generate_prob_primes(
        idsa::L_1024,
        idsa::N_160,
        idsa::N_160,
        idsa::ParameterValidation::Discard,
        &mut rng,
    )
    .unwrap();
    let g = idsa::generate_unverifiable_g(&primes).unwrap();
    let private_key =
        idsa::DsaPrivateKey::from_parameters(primes, g, None, idsa::Trusted::True, &mut rng)
            .unwrap();

    // Sign according to FIPS 186-4, but insecurely return the secret nonce `k`
    // Recover `k` to sign the second message with the same `k`
    //
    // This is just to setup the attack scenario,
    // pretend like the attacker doesn't have access to `k` yet
    let (r0, s0, k) = private_key.sign_insecure(msg0.as_ref(), &mut rng).unwrap();
    let (_r1, s1) = private_key.sign_with_k_insecure(msg1.as_ref(), &k).unwrap();

    // recover `k` as the attacker
    let qi: BigInt = private_key.q().clone().into();
    // take the hashes of the messages
    let h0 = isha2::sha256::Sha256::digest(msg0.as_ref()).unwrap();
    let h1 = isha2::sha256::Sha256::digest(msg1.as_ref()).unwrap();
    // take the leftmost 160-bits of H, because FIPS 186-4 tells us to
    let m0i = BigInt::from_bytes_be(num::bigint::Sign::Plus, &h0[..20]);
    let m1i = BigInt::from_bytes_be(num::bigint::Sign::Plus, &h1[..20]);
    let s0i: BigInt = s0.clone().into();
    let s1i: BigInt = s1.clone().into();
    // ki = (m1 - m2) / (s1 - s2) mod q
    let ki = ((&m0i - &m1i).mod_floor(&qi) * (s0i - s1i).invmod(&qi)).mod_floor(&qi);

    // validate recovered `k` matches the one used to sign the message
    let (_, rec_k) = ki.into_parts();
    assert_eq!(rec_k, k);

    // Now that we have `k`, recover the private key using the attack from #43

    // r_inv = 1 / r mod q
    let r_inv = r0.invmod(private_key.q());
    let (_, mut x) = m0i.into_parts();
    // (s * k) - H(msg) / r mod q
    x = (((&s0 * &rec_k) - &x) * &r_inv).mod_floor(private_key.q());
    // res == x
    assert_eq!(&x, private_key.x());
}

#[test]
fn challenge_forty_five_a() {
    let msg0 = b"Hello, world";
    let msg1 = b"Goodbye, world";
    let mut rng = thread_rng();

    // Generate DSA parameters and private key
    let primes = idsa::generate_prob_primes(
        idsa::L_1024,
        idsa::N_160,
        idsa::N_160,
        idsa::ParameterValidation::Discard,
        &mut rng,
    )
    .unwrap();
    let g = BigUint::from(0_u8);
    let private_key =
        idsa::DsaPrivateKey::from_parameters(primes, g, None, idsa::Trusted::True, &mut rng)
            .unwrap();
    let public_key = idsa::DsaPublicKey::from(&private_key);

    let mut k_bytes = [0_u8; 20];
    rng.fill(&mut k_bytes);
    k_bytes[0] |= 0x80;
    let k = BigUint::from_bytes_be(k_bytes.as_ref());

    // Sign according to FIPS 186-4, using g=0 as the generator
    //
    // Supply non-canonical `k`, since generating a secret nonce according to FIPS 186-4
    // with a g=0 generator results in infinite loop
    let (r0, s0) = private_key.sign_with_k_insecure(msg0.as_ref(), &k).unwrap();
    let (r1, s1) = private_key.sign_with_k_insecure(msg1.as_ref(), &k).unwrap();
    // verify each message against its respective signature
    public_key.verify_insecure(msg0.as_ref(), &r0, &s0).unwrap();
    public_key.verify_insecure(msg1.as_ref(), &r1, &s1).unwrap();
    // verify the first message against the second signature
    public_key.verify_insecure(msg0.as_ref(), &r1, &s1).unwrap();
    // verify the second message against the first signature
    public_key.verify_insecure(msg1.as_ref(), &r0, &s0).unwrap();
    // verify the bad signatures fail using normal verification, since r and s == 0 mod q
    assert!(public_key.verify(msg0.as_ref(), &r1, &s1).is_err());
    assert!(public_key.verify(msg1.as_ref(), &r0, &s0).is_err());
}

#[test]
fn challenge_forty_five_b() {
    let msg0 = b"Hello, world";
    let msg1 = b"Goodbye, world";
    let mut rng = thread_rng();

    // Generate DSA parameters and private key
    let primes = idsa::generate_prob_primes(
        idsa::L_1024,
        idsa::N_160,
        idsa::N_160,
        idsa::ParameterValidation::Discard,
        &mut rng,
    )
    .unwrap();
    let g = BigUint::from(1_u8);
    let private_key =
        idsa::DsaPrivateKey::from_parameters(primes, g, None, idsa::Trusted::True, &mut rng)
            .unwrap();
    let public_key = idsa::DsaPublicKey::from(&private_key);

    let mut k_bytes = [0_u8; 20];
    rng.fill(&mut k_bytes);
    k_bytes[0] |= 0x80;
    let k = BigUint::from_bytes_be(k_bytes.as_ref());

    // Sign according to FIPS 186-4, using g=1 as the generator
    //
    // Supply non-canonical `k`, since generating a secret nonce according to FIPS 186-4
    // with a g=1 generator results in infinite loop
    let (r0, s0) = private_key.sign_with_k_insecure(msg0.as_ref(), &k).unwrap();
    let (r1, s1) = private_key.sign_with_k_insecure(msg1.as_ref(), &k).unwrap();
    // verify each message against its respective signature
    public_key.verify(msg0.as_ref(), &r0, &s0).unwrap();
    public_key.verify(msg1.as_ref(), &r1, &s1).unwrap();
    // verify the first message against the second signature
    public_key.verify(msg0.as_ref(), &r1, &s1).unwrap();
    // verify the second message against the first signature
    public_key.verify(msg1.as_ref(), &r0, &s0).unwrap();
    // verify a random message verifies against the generated signatures
    let mut rand_msg = [0u8; 32];
    rng.fill(&mut rand_msg);
    public_key.verify(rand_msg.as_ref(), &r0, &s0).unwrap();
    public_key.verify(rand_msg.as_ref(), &r1, &s1).unwrap();
}
