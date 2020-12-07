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
        .generate_password_exponent(srp_client.password())
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
