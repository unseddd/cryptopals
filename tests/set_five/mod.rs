use rand::{thread_rng, Rng};

use cryptopals::dh;

#[test]
#[allow(non_snake_case)]
fn challenge_thirty_three() {
    use num::bigint::BigUint;

    let mut rng = thread_rng();

    let lil_p = 37_u8;
    let lil_g = 5_u8;

    let lil_a = rng.gen_range::<u8, u8, u8>(1, lil_p);
    let lil_b = rng.gen_range::<u8, u8, u8>(1, lil_p);

    // perfor Diffie-Hellman using smol parameters
    let bn_lil_p = BigUint::from_bytes_le(&[lil_p]);
    let bn_lil_g = BigUint::from_bytes_le(&[lil_g]);

    let bn_lil_a = BigUint::from_bytes_le(&[lil_a]);
    let bn_lil_b = BigUint::from_bytes_le(&[lil_b]);

    let lil_A = bn_lil_g.modpow(&bn_lil_a, &bn_lil_p);
    let lil_B = bn_lil_g.modpow(&bn_lil_b, &bn_lil_p);

    let lil_sa = lil_B.modpow(&bn_lil_a, &bn_lil_p);
    let lil_sb = lil_A.modpow(&bn_lil_b, &bn_lil_p);

    assert_eq!(lil_sa, lil_sb);

    // now using NIST DH parameters
    let bn_a = dh::generate_secret_exp();
    let bn_A = dh::public_key(&bn_a).unwrap();

    let bn_b = dh::generate_secret_exp();
    let bn_B = dh::public_key(&bn_b).unwrap();

    let bn_sa = dh::shared(&bn_a, &bn_B).unwrap();
    let bn_sb = dh::shared(&bn_b, &bn_A).unwrap();

    assert_eq!(bn_sa, bn_sb);
}

#[test]
#[allow(non_snake_case)]
fn challenge_thirty_four() {
    use core::convert::TryInto;

    let mut rng = thread_rng();

    let bn_a = dh::generate_secret_exp();
    let bn_A = dh::public_key(&bn_a).unwrap();

    let bn_b = dh::generate_secret_exp();
    let bn_B = dh::public_key(&bn_b).unwrap();

    let bn_m = dh::generate_secret_exp();
    let bn_M = dh::public_key(&bn_m).unwrap();

    // simulate Mallory injecting MITM parameters into the DH agreement
    //
    // sending P as a public key is supposed to show that P^(anything-but-zero) mod P is zero
    //
    // the following attack is more interesting to code
    let bn_smA = dh::shared(&bn_m, &bn_A).unwrap();
    let bn_saM = dh::shared(&bn_a, &bn_M).unwrap();

    assert_eq!(bn_smA, bn_saM);

    let bn_smB = dh::shared(&bn_m, &bn_B).unwrap();
    let bn_sbM = dh::shared(&bn_b, &bn_M).unwrap();

    assert_eq!(bn_smB, bn_sbM);

    // verify that Mallory can decrypt a message sent by Alice
    let smA = isha1::Sha1::digest(&bn_smA.to_bytes_be()).unwrap()[..craes::aes::KEY_LEN_128]
        .try_into()
        .unwrap();

    let saM = isha1::Sha1::digest(&bn_saM.to_bytes_be()).unwrap()[..craes::aes::KEY_LEN_128]
        .try_into()
        .unwrap();

    let mut alice_iv = [0_u8; craes::cbc::IV_LEN];
    rng.fill(&mut alice_iv);

    let msg = craes::pkcs7::pad(b"I hope only Bob reads this".as_ref());
    let alice_ciph = craes::cbc::encrypt(&msg, &saM, &alice_iv).unwrap();

    // simulate Mallory intercepting, and decrypting Alice's message
    let mal_plain = craes::cbc::decrypt(&alice_ciph, &smA, &alice_iv).unwrap();

    assert_eq!(mal_plain[..], msg[..]);

    let smB = isha1::Sha1::digest(&bn_smB.to_bytes_be()).unwrap()[..craes::aes::KEY_LEN_128]
        .try_into()
        .unwrap();

    let sbM = isha1::Sha1::digest(&bn_smB.to_bytes_be()).unwrap()[..craes::aes::KEY_LEN_128]
        .try_into()
        .unwrap();

    let mut mal_iv = [0_u8; craes::cbc::IV_LEN];
    rng.fill(&mut mal_iv);

    // simulate Mallory re-encrypting, and sending the message to Bob
    let mal_ciph = craes::cbc::encrypt(&mal_plain, &smB, &mal_iv).unwrap();
    let bob_plain = craes::cbc::decrypt(&mal_ciph, &sbM, &mal_iv).unwrap();

    // verify Bob receives the original message
    assert_eq!(bob_plain[..], msg[..]);
}

#[test]
fn challenge_thirty_five() {
    use num::Zero;

    let p = dh::p();

    // Don't actually perform the MITM, because what's the point?
    //
    // The below cases show what will happen when G is p - 1 and 1
    //
    // When G == p, all results will be zero. This is because P^(anything-but-zero) mod P == 0
    let one = num::bigint::BigUint::from_bytes_le(&[1]);
    let p_sub_one = &p - &one;

    // only do sixteen trials to get the point across
    // feel free to mess with the range if you need convincing
    // this will always be:
    //   one for even, non-zero values of i
    //   p - 1 for odd, non-zero values of i
    for i in 1_u32..16_u32 {
        let res = p_sub_one.modpow(&i.into(), &p);

        // the test for eveness is slightly more complicated for real parameters, but not much
        if i % 2 == 0 {
            assert_eq!(res, one);
        } else {
            assert_eq!(res, p_sub_one);
        }
    }

    // only do ten trials to get the point across
    // feel free to mess with the range if you need convincing
    // this will alway be one for non-zero values of i
    for i in 1_u32..10_u32 {
        let res = one.modpow(&i.into(), &p);
        assert_eq!(res, one);
    }

    // only do ten trials to get the point across
    // feel free to mess with the range if you need convincing
    // this will alway be zero for non-zero values of i
    for i in 1_u32..10_u32 {
        let res = p.modpow(&i.into(), &p);
        assert!(res.is_zero());
    }
}

#[test]
fn challenge_thirty_six() {
    use cryptopals::mac::srp::{SecureRemotePassword, SrpClient, SrpServer};

    let mut srp_server = SrpServer::new();
    let mut srp_client = SrpClient::new();

    srp_client.set_email(b"such@much.email".as_ref()).unwrap();
    srp_client
        .set_password(b"really strong password".as_ref())
        .unwrap();

    srp_server
        .register(srp_client.email(), srp_client.password())
        .unwrap();

    let srv_big_b = srp_server.generate_public_key().unwrap();
    let salt = srp_server.salt();

    let client_challenge = srp_client.generate_challenge(&srv_big_b, salt).unwrap();
    let cli_big_a = srp_client.generate_public_key().unwrap();

    let success = srp_server
        .validate_challenge(&cli_big_a, &client_challenge)
        .unwrap();

    assert!(success);
}

#[test]
fn challenge_thirty_seven() {
    use core::ops::Mul;
    use num::bigint::BigUint;
    use num::Zero;

    use cryptopals::mac::hmac_sha256;
    use cryptopals::mac::srp::{SecureRemotePassword, SrpClient, SrpServer, SUCCESSFUL_LOGIN};

    let mut srp_server = SrpServer::new();
    let mut srp_client = SrpClient::new();

    srp_client.set_email(b"such@much.email".as_ref()).unwrap();
    srp_client
        .set_password(b"really strong password".as_ref())
        .unwrap();

    // register our brand new SRP client
    srp_server
        .register(srp_client.email(), srp_client.password())
        .unwrap();

    let salt = srp_server.salt();

    // create the forged challenge for login bypass (*no password necessary*)
    let cli_big_a: BigUint = Zero::zero();
    let s_zero = isha256::Sha256::digest(&cli_big_a.to_bytes_be()).unwrap();
    let client_challenge = hmac_sha256(s_zero.as_ref(), &salt.to_be_bytes()).unwrap();

    // with known client email, login works like a charm
    let success = srp_server
        .login(srp_client.email(), &cli_big_a, &client_challenge)
        .unwrap();

    assert_eq!(success, SUCCESSFUL_LOGIN);

    // set A to P, use the same challenge
    let big_p = dh::p();
    let success_big_p = srp_server
        .login(srp_client.email(), &big_p, &client_challenge)
        .unwrap();

    assert_eq!(success_big_p, SUCCESSFUL_LOGIN);

    // set A to P*2, use the same challenge
    let big_pp = big_p.clone().mul(2_u32);
    let success_big_pp = srp_server
        .login(srp_client.email(), &big_pp, &client_challenge)
        .unwrap();

    assert_eq!(success_big_pp, SUCCESSFUL_LOGIN);

    // set A to P^2, use the same challenge
    let big_psq = big_p.pow(2);
    let success_big_psq = srp_server
        .login(srp_client.email(), &big_psq, &client_challenge)
        .unwrap();

    assert_eq!(success_big_psq, SUCCESSFUL_LOGIN);
}

#[test]
fn challenge_thirty_eight() {
    use num::Zero;

    use cryptopals::mac::srp::{SecureRemotePassword, SimpleSrpClient, SimpleSrpServer};
    use cryptopals::mac::srp::{DICTIONARY, SUCCESSFUL_LOGIN};

    let mut srp_client = SimpleSrpClient::new();

    srp_client.set_email(b"some@much.email".as_ref()).unwrap();

    // choose random password from the dictionary
    // somewhat contrived, but see notes in the source for details
    let pass_idx = thread_rng().gen_range::<usize, usize, usize>(0, DICTIONARY.len());
    srp_client
        .set_password(DICTIONARY[pass_idx].as_ref())
        .unwrap();

    let mut srp_server = SimpleSrpServer::new();
    srp_server
        .register(srp_client.email(), srp_client.password())
        .unwrap();

    let server_pubkey = srp_server.generate_public_key().unwrap();

    let client_challenge = srp_client
        .generate_challenge(&server_pubkey, srp_server.salt(), srp_server.nonce())
        .unwrap();

    let cli_pubkey = srp_client.generate_public_key().unwrap();

    // verify successful login
    let success = srp_server
        .login(srp_client.email(), &cli_pubkey, &client_challenge)
        .unwrap();

    assert_eq!(success, SUCCESSFUL_LOGIN);

    // verify login fails with invalid public key
    let res = srp_server.login(srp_client.email(), &Zero::zero(), &client_challenge);

    assert!(res.is_err());

    let mut mitm_server = SimpleSrpServer::new();

    // set parameters to make v (sha(salt||password)) easy to crack
    // i.e. u = 1, b = 1, salt = 0
    // s.t. S = (A * v ** 1) ** 1 % P
    //        = (A * v) % P
    //      and
    //      v = SHA-256([0; 16] || password)
    mitm_server.set_crack_parameters();

    // simulate the client being fed MitM parameters for challenge generation
    let mitm_challenge = srp_client
        .generate_challenge(
            &mitm_server.generate_public_key().unwrap(),
            mitm_server.salt(),
            mitm_server.nonce(),
        )
        .unwrap();

    // crack the password at the MitM server
    let cracked_pass = mitm_server
        .crack_password(&cli_pubkey, &mitm_challenge)
        .unwrap();

    // login to the original server with the cracked password
    let mut mitm_client = SimpleSrpClient::new();

    // yeah, we MitMed the email, too...
    mitm_client.set_email(srp_client.email()).unwrap();
    mitm_client.set_password(&cracked_pass).unwrap();

    // generate a challenge using cracked + MitMed params
    let cracked_challenge = mitm_client
        .generate_challenge(&server_pubkey, srp_server.salt(), srp_server.nonce())
        .unwrap();

    // verify login is successful
    let success = srp_server
        .login(
            mitm_client.email(),
            &mitm_client.generate_public_key().unwrap(),
            &cracked_challenge,
        )
        .unwrap();

    assert_eq!(success, SUCCESSFUL_LOGIN);
}

#[test]
fn challenge_thirty_nine() {
    use num::bigint::BigUint;
    use num::ToPrimitive;

    // these are just a few examples to show RSA works
    // see the unit tests in irsa for more

    let a = BigUint::from_bytes_le(&[17]);
    let b = BigUint::from_bytes_le(3120_u16.to_le_bytes().as_ref());
    let c = irsa::inv_mod_slow(&a, &b).unwrap().to_u32().unwrap();

    assert_eq!(c, 2753);

    let pvt_key = irsa::RsaPrivateKey::from_exponent(3, irsa::RSA_1024_LEN).unwrap();
    let pub_key = irsa::RsaPublicKey::from(&pvt_key);

    let orig_text = b"0xIOnceLookedIntoTheBlackMaw...Wait,ThisIsn'tHex!";

    let ciphertext = pub_key.encrypt(orig_text.as_ref()).unwrap();
    let message = pvt_key.decrypt(&ciphertext).unwrap();

    assert_eq!(message[..], orig_text[..]);
}

#[test]
fn challenge_forty() {
    use num::bigint::BigUint;
    use num::Integer;

    let n_0 = irsa::RsaPublicKey::from(&irsa::RsaPrivateKey::from_exponent(3, irsa::RSA_1024_LEN).unwrap());
    let n_1 = irsa::RsaPublicKey::from(&irsa::RsaPrivateKey::from_exponent(3, irsa::RSA_1024_LEN).unwrap());
    let n_2 = irsa::RsaPublicKey::from(&irsa::RsaPrivateKey::from_exponent(3, irsa::RSA_1024_LEN).unwrap());

    // pretend we don't actually know this plaintext
    let orig_text = b"no way they ever read this";

    let c_0_buf = n_0.encrypt(orig_text.as_ref()).unwrap();
    let c_1_buf = n_1.encrypt(orig_text.as_ref()).unwrap();
    let c_2_buf = n_2.encrypt(orig_text.as_ref()).unwrap();

    let mut c_0 = BigUint::from_bytes_le(&c_0_buf);
    let mut c_1 = BigUint::from_bytes_le(&c_1_buf);
    let mut c_2 = BigUint::from_bytes_le(&c_2_buf);

    // m_s_0 = n_1 * n_2
    let mut m_s_0 = n_1.n.clone();
    m_s_0 *= &n_2.n;

    // m_s_1 = n_0 * n_2
    let mut m_s_1 = n_0.n.clone();
    m_s_1 *= &n_2.n;

    // m_s_2 = n_0 * n_1
    let mut m_s_2 = n_0.n.clone();
    m_s_2 *= &n_1.n;

    // c_0 * m_s_0 * invmod(m_s_0, n_0)
    c_0 *= &m_s_0;
    c_0 *= irsa::inv_mod_slow(&m_s_0, &n_0.n).unwrap();

    // c_1 * m_s_1 * invmod(m_s_1, n_1)
    c_1 *= &m_s_1;
    c_1 *= irsa::inv_mod_slow(&m_s_1, &n_1.n).unwrap();

    // c_2 * m_s_2 * invmod(m_s_2, n_2)
    c_2 *= &m_s_2;
    c_2 *= irsa::inv_mod_slow(&m_s_2, &n_2.n).unwrap();

    // sum the products
    c_0 += &c_1;
    c_0 += &c_2;

    // n_012 = n_0 * n_1 * n_2
    let mut n_012 = m_s_0.clone();
    n_012 *= &n_0.n;

    let res = c_0.mod_floor(&n_012).cbrt().to_bytes_le();

    assert_eq!(res[..], orig_text[..]);
}
