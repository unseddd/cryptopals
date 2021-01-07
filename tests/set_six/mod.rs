use num::bigint::BigUint;
use num::rational::Ratio;
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

pub struct RsaParityOracle {
    private_key: irsa::RsaPrivateKey,
    public_key: irsa::RsaPublicKey,
}

impl RsaParityOracle {
    /// Create a new RsaParityOracle
    pub fn new() -> Self {
        let sk = irsa::RsaPrivateKey::new(irsa::RSA_1024_LEN).unwrap();
        let pk = irsa::RsaPublicKey::new(&sk).unwrap();
        Self {
            private_key: sk,
            public_key: pk,
        }
    }

    /// Encrypt a message under the oracle's public key
    pub fn encrypt(&self, msg: &[u8]) -> Vec<u8> {
        self.public_key.encrypt(&msg).unwrap()
    }

    /// Parity oracle
    ///
    /// Returns whether the decryption of the plaintext is even (true) or odd (false)
    pub fn oracle(&self, ciphertext: &[u8]) -> bool {
        let pt = self.private_key.decrypt(ciphertext).unwrap();
        pt[pt.len() - 1] & 0x1 == 0
    }

    /// Get the public modulus N
    pub fn n(&self) -> &BigUint {
        &self.public_key.n
    }

    /// Get the public exponent e
    pub fn e(&self) -> &BigUint {
        &self.public_key.e
    }
}

#[test]
fn challenge_forty_six() {
    use cryptopals::encoding::from_base64;
    use num::ToPrimitive;

    let msg_b64 = b"VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==";
    let msg = from_base64(msg_b64.as_ref()).unwrap();
    // for comparison
    let msg_bn = BigUint::from_bytes_be(&msg);
    let oracle = RsaParityOracle::new();
    let ciphertext = oracle.encrypt(&msg);
    let mut ciph_bn = BigUint::from_bytes_be(&ciphertext);

    let n = oracle.n();
    let mut upper_bound = oracle.n().clone();
    let mut lower_bound = BigUint::from(0_u8);
    let two = BigUint::from(2_u8);

    for i in 0..n.bits() {
        // double the ciphertext
        ciph_bn = (&ciph_bn * &two.modpow(oracle.e(), n)).mod_floor(n);

        // divide modulus N by the next power of two
        let new_bound = n.div_floor(&two.pow((i + 1) as u32));
        // shrink bounds by the next power of two
        if oracle.oracle(&ciph_bn.to_bytes_be()) {
            // plaintext * 2**(i*e) mod n didn't wrap modulus
            // shrink the upper bound
            upper_bound = &upper_bound - &new_bound;
        } else {
            // plaintext * 2**(i*e) mod n did wrap modulus
            // shrink the lower bound
            lower_bound = &lower_bound + &new_bound;
        }

        // "hollywood style" decryption lel
        println!("cracking: {}", upper_bound);
    }

    assert!(
        upper_bound >= msg_bn && lower_bound <= msg_bn,
        "failure\nupper_bound: {}\nlower_bound: {}\nmessage    : {}",
        upper_bound,
        lower_bound,
        msg_bn,
    );

    // FIXME: best results are in a range of candidates < 1024
    //     usually around 480-550
    //     how to improve?
    let mut range = (&upper_bound - &lower_bound).to_u32().unwrap();
    assert!(range < 1024);
    range /= 4;
    lower_bound += range;
    upper_bound -= range;

    for i in 0..range {
        match core::str::from_utf8(&(&lower_bound + i).to_bytes_be()) {
            Ok(s) => println!("attempt: {}", s),
            _ => (),
        }
    }
}

pub struct RsaPkcsOracle {
    pubkey: irsa::RsaPublicKey,
    pvtkey: irsa::RsaPrivateKey,
}

const ZEROS: [u8; 1024] = [0u8; 1024];

impl RsaPkcsOracle {
    /// Create a new padding oracle with 256-bit RSA keys
    pub fn new(size: usize) -> Self {
        let pvt = irsa::RsaPrivateKey::from_exponent_insecure(3, size).unwrap();
        Self {
            pubkey: irsa::RsaPublicKey::from_private_key_insecure(&pvt),
            pvtkey: pvt,
        }
    }

    /// Encode a message using original PKCS#1 spec
    pub fn encode_pkcs(&self, msg: &[u8]) -> Vec<u8> {
        let n_len = self.pubkey.n.bits() as usize / 8;
        let mut encmsg: Vec<u8> = Vec::with_capacity(n_len);
        encmsg.extend_from_slice(&[0x00, 0x02]);
        let pad_len = n_len - 3 - msg.len();
        encmsg.extend_from_slice(&vec![0xff; pad_len]);
        encmsg.push(0x00);
        encmsg.extend_from_slice(msg);
        encmsg
    }

    /// Encode message with PCKS#1, and encrypt under the oracle's public key
    pub fn encrypt_pkcs(&self, msg: &[u8]) -> Vec<u8> {
        self.pubkey.encrypt(&self.encode_pkcs(msg)).unwrap()
    }

    /// Returns true or false if decryption is PKCS conforming
    pub fn verify(&self, ciphertext_bn: &BigUint, s: &[u8]) -> bool {
        let s_enc = BigUint::from_bytes_be(&self.pubkey.encrypt(s).unwrap());
        let t_enc = (ciphertext_bn * s_enc)
            .mod_floor(&self.pubkey.n)
            .to_bytes_be();
        let dec = match self.pvtkey.decrypt(&t_enc) {
            Ok(d) => d,
            Err(_) => return false,
        };
        let mut msg = ZEROS[..(self.pubkey.n_len / 8) - dec.len()].to_vec();
        msg.extend_from_slice(&dec);
        // validate PKCS conforming according to Bleichenbacher '98 Definition 1
        if &msg[..2] != &[0x0, 0x2] {
            return false;
        };
        for &b in msg[2..10].iter() {
            if b == 0x0 {
                return false;
            };
        }
        for &b in msg[10..].iter() {
            if b == 0x0 {
                return true;
            };
        }
        true
    }

    /// Get the oracle's RSA modulus
    pub fn n(&self) -> &BigUint {
        &self.pubkey.n
    }
}

/*
#[allow(dead_code)]
fn bleichenbacher_1(oracle: &RsaPkcsOracle, c: &BigUint) -> Result<(BigUint, BigUint), String> {
    let n = oracle.n();
    let k = (n.bits() / 8) as usize;
    let mut s0_bytes: Vec<u8> = Vec::with_capacity(k - 1);
    s0_bytes.resize(k -1, 0);

    let mut rng = thread_rng();
    loop {
        rng.fill(s0_bytes.as_mut_slice());
        s0_bytes[0] |= 0x80;
        if oracle.verify(&c, &s0_bytes) {
            let c0 = (c * BigUint::from_bytes_be(&oracle.encrypt(&s0_bytes))).mod_floor(n);
            return Ok((BigUint::from_bytes_be(&s0_bytes), c0));
        }
    }
}
*/

fn bleichenbacher_2ab(
    oracle: &RsaPkcsOracle,
    c0: &BigUint,
    si: &mut BigUint,
    three_b: &BigUint,
) -> Result<(), String> {
    println!("2ab. finding si s.t. c0*(si**e) mod n is PKCS conforming");
    let mut i = 1;
    while &*si < three_b && i < 20_000_000 {
        if oracle.verify(&c0, &si.to_bytes_be()) {
            // found a PKCS conforming c0(si**e) mod n
            println!(
                "    found candidate si: {}\n    attempts          : {}",
                si, i
            );
            return Ok(());
        }
        *si += 1_u32;
        i += 1;
    }
    Err(format!(
        "2ab. no valid si found\nsi: {}\n3B: {}",
        si, three_b
    ))
}

fn bleichenbacher_2c(
    oracle: &RsaPkcsOracle,
    c0: &BigUint,
    m_i: &[(BigUint, BigUint)],
    si: &mut BigUint,
    si_1: &BigUint,
    two_b: &BigUint,
    three_b: &BigUint,
) -> Result<(), String> {
    println!("2c. log(n) search for finding si s.t. c0*(si**e) mod n is PKCS conforming");
    let (a, b) = &m_i[0];

    let n = oracle.n();
    let one = Ratio::from_integer(BigUint::from(1_u8));

    let mut r = (Ratio::from_integer((2_u32 * b * si_1) - two_b) / n).ceil();

    println!("    r      : {}", r.to_integer());

    loop {
        // 2B + ri*n / b <= si < 3B + ri*n / a
        // (2B + ri*n) / b
        let rn = &r * n;
        let mut s_lo = ((&rn + two_b) / b).floor().to_integer();
        // (3B + ri*n) / a
        let s_hi = ((&rn + three_b) / a).ceil().to_integer();

        while s_lo < s_hi {
            if oracle.verify(&c0, &s_lo.to_bytes_be()) {
                *si = s_lo;
                return Ok(());
            }
            s_lo += 1_u32;
        }

        r += &one;
    }
}

// construct next set of intervals for testing
fn bleichenbacher_3(
    m: &mut Vec<Vec<(BigUint, BigUint)>>,
    si: &BigUint,
    two_b: &BigUint,
    three_b: &BigUint,
    n: &BigUint,
) {
    println!("3. narrowing search range, round: {}, si: {}", m.len(), si);

    let two_bf = Ratio::from_integer(two_b.clone());
    let three_bf = Ratio::from_integer(three_b.clone());
    let one = Ratio::from_integer(BigUint::from(1_u8));

    let mut m_i: Vec<(BigUint, BigUint)> = Vec::new();
    let last_m = &m[m.len() - 1];
    for (a, b) in last_m.iter() {
        // (a*si - 3B + 1) / n <= r <= (b*si - 2B) / n
        let mut r = (Ratio::from_integer((a * si) - three_b + 1_u32) / n).ceil();
        let r_hi = (Ratio::from_integer((b * si) - two_b) / n).floor();

        while r <= r_hi {
            // Mi = [max(a, ceil((2B + r*n) / si)), min(b, floor((3B - 1 + rn) / si))
            let rn = &r * n;
            let lo_max: BigUint = ((&two_bf + &rn) / si).ceil().to_integer();
            let hi_min: BigUint = ((&three_bf - &one + &rn) / si).floor().to_integer();

            let lo = core::cmp::max(a.clone(), lo_max);
            let hi = core::cmp::min(b.clone(), hi_min);

            assert!(
                &lo < three_b && &lo <= &hi && &hi >= two_b,
                "3. invalid lo and hi range\n    lo: {}\n    hi: {}",
                lo,
                hi
            );

            match m_i.last() {
                Some(lo_hi) => {
                    let nlo_hi = (lo, hi);
                    if &nlo_hi != lo_hi {
                        println!("    r_lo: {}\n    r_hi: {}", r, r_hi);
                        println!("        lo: {}\n        hi: {}", nlo_hi.0, nlo_hi.1);
                        m_i.push(nlo_hi);
                    }
                }
                None => m_i.push((lo, hi)),
            }

            r += &one;
        }
    }
    println!(
        "    last len: {}\n    this len: {}",
        m[m.len() - 1].len(),
        m_i.len()
    );
    if m_i.len() == 1 {
        println!("    m_i[lo]: {}\n    m_i[hi]: {}\n", m_i[0].0, m_i[0].1);
    }
    m.push(m_i);
}

#[test]
fn challenge_forty_seven() {
    let msg = b"Things you want to keep";
    let oracle = RsaPkcsOracle::new(256);

    let two = BigUint::from(2_u8);
    let n = oracle.n();
    let k = (n.bits() / 8) as u32;
    let k_2 = (k - 2) * 8;
    // 2B = 2**((k-2) * 8) * 2 = 2**((k-2)*8 + 1)
    let big_b = two.pow(k_2);
    let two_b = &big_b * &two;
    // 3B = 2**((k-2) * 8) * 3
    let three_b = &two_b + &big_b;
    let i_max = 2_000_000_usize;

    // Step 1.
    // Skip step 1. because c0 is already a PKCS conforming ciphertext
    // Simulate capturing a target PKCS#1 encoded ciphertext
    let c0 = BigUint::from_bytes_be(&oracle.encrypt_pkcs(msg.as_ref()));
    let s0 = BigUint::from(1_u8);

    // round 1, search for s0 > ceil(n / 3B)
    let mut si = Ratio::new(n.clone(), three_b.clone()).ceil().to_integer();
    let mut si_1 = s0.clone();

    let mut m: Vec<Vec<(BigUint, BigUint)>> =
        [[(two_b.clone(), (&three_b - 1_u32))].to_vec()].to_vec();
    let encmsg = oracle.encode_pkcs(msg.as_ref());

    let mut j = 1;
    for i in 1..i_max {
        println!("iteration: {}", i);

        if i == 1 || m[i - 1].len() > 1 {
            // Step 2.a/b
            bleichenbacher_2ab(&oracle, &c0, &mut si, &three_b).unwrap();
        } else {
            // Step 2.c searching with one interval left.
            bleichenbacher_2c(&oracle, &c0, &m[i - 1], &mut si, &si_1, &two_b, &three_b).unwrap();
        }

        // Step 3. construct next set of intervals based on the previous set
        bleichenbacher_3(&mut m, &si, &two_b, &three_b, n);

        // Step 4. if a == b, then m = a(s0)**-1 mod n
        let (a, b) = m[i - 1].last().unwrap();
        if m[i].len() == 1 && a == b {
            // m = a * s0**-1 mod n
            let m = (a * s0.invmod(n)).mod_floor(n);
            //let m = a.mod_floor(n);
            assert_eq!(
                encmsg[1..],
                m.to_bytes_be()[..],
                "\nmsg: {}\nm[{}]: {}",
                BigUint::from_bytes_be(&encmsg),
                i,
                m
            );
            break;
        } else {
            // otherwise, set s[i-1] = s[i], and s[i] += 1
            si_1 = si.clone();
            si += 1_u32;
            j += 1;
        }
    }
    assert!(j < i_max, "no solution found");
}

#[test]
fn challenge_forty_eight() {
    let msg = b"Things you want to throw away";
    let oracle = RsaPkcsOracle::new(768);

    let two = BigUint::from(2_u8);
    let n = oracle.n();
    let k = (n.bits() / 8) as u32;
    let k_2 = (k - 2) * 8;
    // 2B = 2**((k-2) * 8) * 2 = 2**((k-2)*8 + 1)
    let big_b = two.pow(k_2);
    let two_b = &big_b * &two;
    // 3B = 2**((k-2) * 8) * 3
    let three_b = &two_b + &big_b;
    let i_max = 2_000_000_usize;

    // Step 1.
    // Skip step 1. because c0 is already a PKCS conforming ciphertext
    // Simulate capturing a target PKCS#1 encoded ciphertext
    let c0 = BigUint::from_bytes_be(&oracle.encrypt_pkcs(msg.as_ref()));
    let s0 = BigUint::from(1_u8);

    // round 1, search for s0 > ceil(n / 3B)
    let mut si = Ratio::new(n.clone(), three_b.clone()).ceil().to_integer();
    let mut si_1 = s0.clone();

    let mut m: Vec<Vec<(BigUint, BigUint)>> =
        [[(two_b.clone(), (&three_b - 1_u32))].to_vec()].to_vec();
    let encmsg = oracle.encode_pkcs(msg.as_ref());

    let mut j = 1;
    for i in 1..i_max {
        println!("iteration: {}", i);

        if i == 1 || m[i - 1].len() > 1 {
            // Step 2.a/b
            bleichenbacher_2ab(&oracle, &c0, &mut si, &three_b).unwrap();
        } else {
            // Step 2.c searching with one interval left.
            bleichenbacher_2c(&oracle, &c0, &m[i - 1], &mut si, &si_1, &two_b, &three_b).unwrap();
        }

        // Step 3. construct next set of intervals based on the previous set
        bleichenbacher_3(&mut m, &si, &two_b, &three_b, n);

        // Step 4. if a == b, then m = a(s0)**-1 mod n
        let (a, b) = m[i - 1].last().unwrap();
        if m[i].len() == 1 && a == b {
            // m = a * s0**-1 mod n
            let m = (a * s0.invmod(n)).mod_floor(n);
            //let m = a.mod_floor(n);
            assert_eq!(
                encmsg[1..],
                m.to_bytes_be()[..],
                "\nmsg: {}\nm[{}]: {}",
                BigUint::from_bytes_be(&encmsg),
                i,
                m
            );
            break;
        } else {
            // otherwise, set s[i-1] = s[i], and s[i] += 1
            si_1 = si.clone();
            si += 1_u32;
            j += 1;
        }
    }
    assert!(j < i_max, "no solution found");
}
