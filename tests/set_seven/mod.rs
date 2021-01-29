use rand::{thread_rng, Rng};

use cryptopals::bad_hash;
use cryptopals::bytes::{xor, xor_assign};
use cryptopals::encoding::from_hex_bytes;
use cryptopals::mac::cbc::{CbcMac, CbcMacServer, MAC_LEN};

#[test]
fn challenge_forty_nine_a() {
    // shared key and IV between server and legit user
    let key = b"does not matter!";
    let iv = b"we don't need it";

    // pretend everything but the signed message and attacker UID is hidden from the attacker
    let mut mac_server = CbcMacServer::new(key.clone(), iv.clone());
    let mac = CbcMac::new(key.clone(), iv.clone());
    let from_uid = 0x90_u8;
    let to_uid = 0x0d_u8;
    let attack_uid = 0xba_u8;

    // rich one over here...
    mac_server.add_account(from_uid, 1_000_000).unwrap();
    // poor bois down here
    mac_server.add_account(to_uid, 0).unwrap();
    mac_server.add_account(attack_uid, 0).unwrap();

    // rich user feels like helping out another user
    let msg = format!(
        "from={:02x}&to={:02x}&amount={:08x}",
        from_uid, to_uid, 1_000_000_u32
    );
    let signed_msg = mac.sign_with_iv(msg.as_bytes()).unwrap();

    // Verify that the server would accept the message (don't actually transfer yet)
    assert!(mac_server.verify_transfer(signed_msg.as_slice()).unwrap());

    // attacker intercepts, and feels they deserve the money more...
    let mut forged_sig = signed_msg.clone();

    // copy attacker's ID to the forged message
    forged_sig[11..13].copy_from_slice(format!("{:02x}", attack_uid).as_bytes());

    // iv[to_uid_pos] ^= to_uid ^ attack_uid
    // which will cancel the attack uid contribution in the forged message,
    // encrypting the original iv[to_uid_pos] ^ to_uid
    let to_bytes = format!("{:02x}", to_uid);
    let attack_bytes = format!("{:02x}", attack_uid);
    let xor_bytes = xor(to_bytes.as_bytes(), attack_bytes.as_bytes());
    xor_assign(&mut forged_sig[29 + 11..29 + 13], &xor_bytes);

    mac_server.process_transfer(&forged_sig).unwrap();

    assert_eq!(mac_server.get_balance(from_uid).unwrap(), 0);
    assert_eq!(mac_server.get_balance(to_uid).unwrap(), 0);
    assert_eq!(mac_server.get_balance(attack_uid).unwrap(), 1_000_000);
}

#[test]
fn challenge_forty_nine_b() {
    // shared key and IV between server and legit user
    let key = b"who needs keys?!";
    // null, but fixed IV
    //
    // attack could also work with a non-null IV,
    // but would require the IV getting leaked/guessed
    //
    // if non-null IV, instead of MAC ^ first-block, its MAC ^ IV ^ first-block
    // for the first block of the forged message
    let iv = [0_u8; craes::cbc::IV_LEN];

    // pretend everything but the signed message and attacker UID is hidden from the attacker
    let mut mac_server = CbcMacServer::new(key.clone(), iv.clone());
    let mac = CbcMac::new(key.clone(), iv.clone());
    let from_uid = 0x90_u8;
    let to_uid = 0x09_u8;
    let attack_uid = 0x0a_u8;

    // rich one over here...
    mac_server.add_account(from_uid, 2_000_000).unwrap();
    // poor bois down here
    mac_server.add_account(to_uid, 0).unwrap();
    mac_server.add_account(attack_uid, 0).unwrap();

    // Create a multi-transfer message from the rich to the poor
    //
    // Slightly contrived to save space. Also, imagine the server
    // would have some replay protection in place.
    //
    // The attack could work with even smaller amounts sent to the attacker,
    // would just need to append the attack blocks multiple times.
    let msg = format!(
        "from={:02x}&tx_list={:02x}:{:08x};{:02x}:{:08x}",
        from_uid, to_uid, 250_000_u32, attack_uid, 500_000_u32
    );
    let signed_msg = mac.sign_fixed_iv(msg.as_bytes()).unwrap();
    let sig_len = signed_msg.len();

    assert!(mac_server.verify_multi_transfer(&signed_msg).unwrap());

    let mut forged_msg = msg.as_bytes().to_vec();

    // pad the unsigned message
    let pad_len = craes::aes::BLOCK_LEN - (msg.len() % craes::aes::BLOCK_LEN);
    forged_msg.extend_from_slice(vec![pad_len as u8; pad_len].as_slice());

    // xor the CBC-MAC with the first message block
    // results in: MAC ^ MAC ^ first-block = first-block
    // when CBC-MACed by the server
    //
    // essentially cancels the contribution from the previous MAC,
    // starting CBC-MAC over with a null IV
    //
    // Is there a way to use this to make an edit in the second block?
    // For example, is there an attack where nothing is sent to the attacker account?
    //
    // Am I doing what Cryptopals wants, or totally missing the point?
    let mac_block = xor(&signed_msg[sig_len - MAC_LEN..], &signed_msg[..MAC_LEN]);
    forged_msg.extend_from_slice(&mac_block);
    // add the rest of the signed message (including CBC-MAC)
    forged_msg.extend_from_slice(&signed_msg[MAC_LEN..]);

    mac_server.process_multi_transfer(&forged_msg).unwrap();
    assert_eq!(mac_server.get_balance(attack_uid).unwrap(), 1_000_000);
}

#[test]
fn challenge_fifty() {
    let script = b"alert('MZA who was that?');\n";
    let exp_mac = from_hex_bytes(b"296b8d7cb78a243dda4d0a61d33bbdd1").unwrap();
    let cbcmac = CbcMac::new(*b"YELLOW SUBMARINE", [0; craes::cbc::IV_LEN]);
    let mac = cbcmac.mac(script.as_ref()).unwrap();

    assert_eq!(mac[..], exp_mac[..]);

    let forge_script = b"alert('Ayo, the Wu is back!');\n";

    // oops, they leaked the key! now, we can create a collision
    let forge_mac = cbcmac.mac(forge_script.as_ref()).unwrap();

    // Calculate PKCS#7 padding
    let pad_len = craes::aes::BLOCK_LEN - (forge_script.len() % craes::aes::BLOCK_LEN);
    let pad = vec![pad_len as u8; pad_len];

    // add PKCS#7 padding to the forged script
    let mut full_script = forge_script.to_vec();
    full_script.extend_from_slice(pad.as_slice());
    // xor the CBC-MAC of our forged script with the first block of the original script
    let forge_block = xor(&script[..MAC_LEN], forge_mac.as_ref());
    // append to the forged script and padding
    full_script.extend_from_slice(forge_block.as_slice());
    // add the rest of the original script to calculate the CBC-MAC
    full_script.extend_from_slice(&script[MAC_LEN..]);
    let mac_collision = cbcmac.mac(full_script.as_slice()).unwrap();

    assert_eq!(mac_collision, mac);
}

// AES cipher mode to use for compression oracle encryption
enum Cipher {
    Ctr,
    Cbc,
}

fn compression_oracle(content: &[u8], cipher: Cipher) -> usize {
    use std::io::Cursor;

    let mut cursor = Cursor::new(format_content(content));
    let mut comp_buf = Vec::with_capacity(content.len());
    lzma_rs::lzma2_compress(&mut cursor, &mut comp_buf).unwrap();

    let mut rng = thread_rng();
    let mut key = [0_u8; craes::aes::KEY_LEN_128];
    rng.fill(&mut key);
    let out = match cipher {
        Cipher::Ctr => {
            let mut count = 0;
            craes::ctr::encrypt(
                comp_buf.as_slice(),
                &key,
                0,
                &mut count,
                &craes::ctr::Endian::Little,
            )
        }
        Cipher::Cbc => {
            let mut iv = [0_u8; craes::cbc::IV_LEN];
            rng.fill(&mut iv);
            craes::cbc::encrypt(&craes::pkcs7::pad(comp_buf.as_slice()), &key, &iv).unwrap()
        }
    };
    out.len()
}

fn format_content(content: &[u8]) -> Vec<u8> {
    let mut res = format!(
        "{}\n{}\n{}\n{}{}\n",
        "POST / HTTP/1.1",
        "Host: hapless.com",
        "Cookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=",
        "Content-Length: ",
        content.len(),
    )
    .as_bytes()
    .to_vec();
    // add content
    res.extend_from_slice(content);
    // add new-line
    res.push(0x0a);
    res
}

fn attempt_chunk(i: usize, chunk: &[u8], attempt: &mut [u8], score: usize) -> usize {
    let chunk_len = chunk.len();
    let alpha = cryptopals::encoding::BASE64_ALPHABET;
    for &b in alpha.iter() {
        for &c in alpha.iter() {
            if (b ^ c).count_ones() < 3 {
                continue;
            };
            for &d in alpha.iter() {
                if (b ^ d).count_ones() < 3 || (c ^ d).count_ones() < 3 {
                    continue;
                };
                for &e in alpha.iter() {
                    if (b ^ e).count_ones() < 3
                        || (c ^ e).count_ones() < 3
                        || (d ^ e).count_ones() < 3
                    {
                        continue;
                    }
                    attempt[18 + (i * chunk_len)..18 + ((i + 1) * chunk_len)]
                        .swap_with_slice(&mut [b, c, d, e][..chunk_len]);
                    let new_score = compression_oracle(&attempt, Cipher::Ctr);
                    if new_score < score {
                        println!("new score: {}", new_score);
                        return new_score;
                    }
                }
            }
        }
    }
    score
}

#[test]
fn challenge_fifty_one() {
    // target cookie unknown to the attacker
    let target = b"TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=";

    // "cheat" a little, and let the attacker know the format (not contents) of the cookie
    // in practice this is a given, just look at the headers of a request you control
    // the format, not the content, will be the same for another user of the same service
    let mut attempt = b"Cookie: sessionid=".to_vec();

    let mut score = compression_oracle(&attempt, Cipher::Ctr);

    let dummy_slice = b":'[|";
    for i in 0..(target.len() / 4) {
        attempt.extend_from_slice(dummy_slice.as_ref());
        score = attempt_chunk(i, dummy_slice.as_ref(), &mut attempt, score);
    }

    attempt[18 + 43] = 0x3d;

    assert_eq!(attempt[18..], target[..]);
}

fn find_collision(collisions: &[u32], attempt: u32) -> bool {
    for &collision in collisions.iter() {
        if collision == attempt {
            return true;
        }
    }
    false
}

#[test]
fn challenge_fifty_two() {
    let mut rng = thread_rng();

    // generate initial collisions
    let initial_attempts = 128;
    let collisions = bad_hash::find_collisions(initial_attempts, &mut rng).unwrap();
    // ensure all collision messages actually collide to the same digest
    for (el_collision, ar_collision, digest) in collisions.iter() {
        let mut hash = bad_hash::BadHash::new();
        hash.input(el_collision).unwrap();
        let el_digest = hash.finalize();
        hash.input(ar_collision).unwrap();
        let ar_digest = hash.finalize();

        assert_eq!(el_digest, ar_digest);
        assert_eq!(el_digest, *digest);
    }

    let digest = collisions[0].2;

    let mut less_hash = bad_hash::LessBadHash::new();
    less_hash.input(&collisions[0].0).unwrap();
    let digest_32 = less_hash.finalize();

    let mut less_collisions: Vec<u32> = Vec::new();
    let mut total_attempts = 0;
    let mut attempt = 0;

    // try to find a colliding message for LessBadHash in the initial set
    for (_, collision, _) in collisions.iter() {
        total_attempts += 1;
        less_hash.input(collision).unwrap();
        attempt = less_hash.finalize();
        // check if the message collides with the LessBadHash digest of the original
        // message, or a LessBadHash digest of a BadHash colliding message
        //
        // FIXME: is this check too permissive?
        if attempt == digest_32 || find_collision(&less_collisions, attempt) {
            break;
        } else {
            less_collisions.push(attempt);
        }
    }

    if attempt != digest_32 && !find_collision(&less_collisions, attempt) {
        let domain = u16::MAX as u128;
        println!(
            "no collisions found in first n attempts: {}",
            total_attempts
        );
        let mut next = u128::from_be_bytes(collisions.last().unwrap().1) + 1;

        // generate more "cheap" collisions, and check if they collide in LessBadHash
        loop {
            total_attempts += 1;
            let collision = bad_hash::find_collision_with_digest(next, digest).unwrap();
            less_hash.input(&collision).unwrap();
            attempt = less_hash.finalize();
            println!(
                "n: {}, msg: {}, attempt: {}, target: {}",
                total_attempts, next, attempt, digest
            );
            // check if the message collides with the LessBadHash digest of the original
            // message, or a LessBadHash digest of a BadHash colliding message
            //
            // FIXME: is this check too permissive?
            if attempt == digest_32 || find_collision(&less_collisions, attempt) {
                break;
            }
            less_collisions.push(attempt);
            next += domain - (u128::from_be_bytes(collision) % domain);
        }
    }

    println!(
        "total attempts: {}, collision: {}, short collision: {}",
        total_attempts, attempt, digest_32
    );
    assert!(attempt == digest_32 || find_collision(&less_collisions, attempt));
}

#[test]
fn challenge_fifty_three() {
    let k = 8;
    // 2**8 * 16 = 2**8 BadHash-blocks
    let m = [0x42; 4096];

    let rand_block = [0x69; bad_hash::BLOCK_LEN];
    let expandable_msg = bad_hash::generate_expandable_message(k, &rand_block);
    let intermediate_states = bad_hash::map_intermediate_states(&m);

    let mut forged = Vec::with_capacity(m.len());

    // generate the prefix:
    // 12 = 1 + 1 + 1 + 1 + 1 + 1 + 1 + (2**1 + 1) + (2**0 + 1)
    forged.extend_from_slice(&rand_block);
    forged.extend_from_slice(&rand_block);
    forged.extend_from_slice(&rand_block);
    forged.extend_from_slice(&rand_block);
    forged.extend_from_slice(&rand_block);
    forged.extend_from_slice(&rand_block);
    forged.extend_from_slice(&rand_block);
    forged.extend_from_slice(&expandable_msg[6].0);
    forged.extend_from_slice(&expandable_msg[7].0);

    let mut f_sha = bad_hash::BadHash::new();
    f_sha.input(&forged).unwrap();
    let f_state = f_sha.state();
    let mut bridge = [0_u8; bad_hash::BLOCK_LEN];
    let target = intermediate_states[12];

    // find a bridge block to connect the output state of the prefix
    // to the input state of the tail of the message
    let mut rng = thread_rng();
    loop {
        rng.fill(&mut bridge);
        let mut ex_sha = bad_hash::BadHash::from_digest(f_state);
        ex_sha.input(bridge.as_ref()).unwrap();
        if ex_sha.state() == target {
            break;
        }
    }

    // add the "bridge" block
    forged.extend_from_slice(&bridge);

    // add the rest of the original message
    forged.extend_from_slice(&m[13 * bad_hash::BLOCK_LEN..]);

    assert_eq!(forged.len(), m.len());

    // check that the forged hash matches the target hash
    let forged_hash = bad_hash::BadHash::digest(&forged).unwrap();
    let target_hash = bad_hash::BadHash::digest(&m).unwrap();

    assert_eq!(forged_hash, target_hash);
}

#[test]
fn challenge_fifty_four() {
    // we'll be generating a 2**k tree of collisions up-front
    // leaving only 2**(b-k) = 2**(16-7) = 2**9 work on the backend
    // FIXME: this test doesn't seem to take 2**(b-k) backend work
    //        am I fucking something up?
    let k = 7;
    let tree = bad_hash::generate_initial_tree(k);
    assert_eq!(tree.len(), k);

    // check that the tree was generated correctly
    for (i, branch) in tree.iter().enumerate() {
        let exp_len = 2_usize.pow((k - i - 1) as u32);
        assert_eq!(branch.len(), exp_len);

        for leaf in branch.iter() {
            let bad_hash::BadHashCollision {
                state_one,
                state_two,
                block,
                collision,
            } = leaf;
            let mut s1_hash = bad_hash::BadHash::from_digest(*state_one);
            let mut s2_hash = bad_hash::BadHash::from_digest(*state_two);
            s1_hash.input(block.as_ref()).unwrap();
            s2_hash.input(block.as_ref()).unwrap();
            let s1_dig = s1_hash.finalize();
            let s2_dig = s2_hash.finalize();
            assert_eq!(s1_dig, s2_dig);
            assert_eq!(s1_dig, *collision);
        }
    }

    // generate the prediction by hashing an empty block using the final tree state
    let final_state = tree.last().unwrap()[0].state_one;
    let final_block = tree.last().unwrap()[0].block;
    let mut final_hash = bad_hash::BadHash::from_digest(final_state);

    let msg_len = (2_u64.pow(bad_hash::BLOCK_LEN as u32) - 1) * bad_hash::BLOCK_LEN as u64;
    let total_len = (msg_len + (bad_hash::BLOCK_LEN * 2) as u64) * 8;

    final_hash.input(final_block.as_ref()).unwrap();
    let prediction = final_hash.finalize_insecure(total_len);

    let mut msg: Vec<u8> = Vec::with_capacity(msg_len as usize);
    msg.resize(msg_len as usize, 0);

    let mut rng = thread_rng();
    rng.fill(msg.as_mut_slice());

    let mut msg_hash = bad_hash::BadHash::new();
    msg_hash.input(&msg).unwrap();
    let msg_state = msg_hash.state();

    let mut glue = [0_u8; bad_hash::BLOCK_LEN];
    let mut attempt = 0_usize;
    loop {
        rng.fill(&mut glue);
        let mut glue_hash = bad_hash::BadHash::from_digest(msg_state);
        glue_hash.input(glue.as_ref()).unwrap();
        println!(
            "attempt: {}, glue state: {}, final state: {}",
            attempt,
            glue_hash.state(),
            final_state
        );
        if glue_hash.state() == final_state {
            break;
        };
        attempt += 1;
    }

    // add the glue block to the hashed message
    msg_hash.input(glue.as_ref()).unwrap();
    msg_hash.input(final_block.as_ref()).unwrap();

    assert_eq!(total_len, msg_hash.total_len());

    let msg_digest = msg_hash.finalize();

    assert_eq!(msg_digest, prediction);
}

// Split MD4 message into 32-bit words
// Assume message is 64-bytes long, because challenge
fn split_words(msg: &[u8]) -> [u32; 16] {
    let mut word = [0_u8; 4];
    let mut res = [0_u32; 16];
    for (i, w) in msg.chunks_exact(4).enumerate() {
        word.copy_from_slice(w);
        res[i] = u32::from_be_bytes(word);
    }
    res
}

fn from_words(words: &[u32; 16], msg: &mut [u8; 64]) {
    for (i, word) in words.iter().enumerate() {
        msg[i*4..(i+1)*4].copy_from_slice(&word.to_be_bytes());
    }
}

// Modify a message for corrections in round one
// "Cryptanalysis of the Hash Functions MD4 and RIPEMD", Ss. 4.2
fn single_step_mod(words: &mut [u32]) {
    let init = bmd4::INIT_STATE;
    let a0 = init[0];
    let b0 = init[1];
    let c0 = init[2];
    let d0 = init[3];

    let a1 = bmd4::Md4::ff(a0, b0, c0, d0, words[0], bmd4::S11);
    let mut d1 = bmd4::Md4::ff(d0, a1, b0, c0, words[1], bmd4::S12);

    // d1 <- d1 ^ (d1,7 <<< 6) ^ ((d1,8 ^ a1,8) <<< 7) ^ ((d1,11 ^ a1,11) <<< 10)
    let da8 = ((d1 & (1 << 7)) ^ (a1 & (1 << 7))).rotate_left(7);
    let da11 = ((d1 & (1 << 10)) ^ (a1 & (1 << 10))).rotate_left(10);
    d1 = d1 ^ (d1 & 1 << 6).rotate_left(6) ^ da8 ^ da11;

    // m1 <- (d1 >>> 7) - d0 - F(a1, b0, c0)
    words[1] = d1.rotate_right(7).wrapping_sub(d0).wrapping_sub(bmd4::Md4::f(a1, b0, c0))
}

fn multi_step_mod(words: &mut [u32]) {
    let init = bmd4::INIT_STATE;
    let (mut a, mut b, mut c, mut d) = (init[0], init[1], init[2], init[3]);

    for i in [19, 26, 27, 29, 32].iter() {
        /* 1 */
        a = bmd4::Md4::ff(a, b, c, d, words[0], bmd4::S11); /* 1 */
        d = bmd4::Md4::ff(d, a, b, c, words[1], bmd4::S12); /* 2 */
        c = bmd4::Md4::ff(c, d, a, b, words[2], bmd4::S13); /* 3 */
        b = bmd4::Md4::ff(b, c, d, a, words[3], bmd4::S14); /* 4 */

        let (mut a1, b1, c1, d1) = (a, b, c, d);

        /* 2 */
        a = bmd4::Md4::ff(a, b, c, d, words[4], bmd4::S11); /* 5 */
        d = bmd4::Md4::ff(d, a, b, c, words[5], bmd4::S12); /* 6 */
        c = bmd4::Md4::ff(c, d, a, b, words[6], bmd4::S13); /* 7 */
        b = bmd4::Md4::ff(b, c, d, a, words[7], bmd4::S14); /* 8 */

        let a2 = a;

        /* 3 */
        a = bmd4::Md4::ff(a, b, c, d, words[8], bmd4::S11); /* 9 */
        d = bmd4::Md4::ff(d, a, b, c, words[9], bmd4::S12); /* 10 */
        c = bmd4::Md4::ff(c, d, a, b, words[10], bmd4::S13); /* 11 */
        b = bmd4::Md4::ff(b, c, d, a, words[11], bmd4::S14); /* 12 */

        /* 4 */
        a = bmd4::Md4::ff(a, b, c, d, words[12], bmd4::S11); /* 13 */
        d = bmd4::Md4::ff(d, a, b, c, words[13], bmd4::S12); /* 14 */
        c = bmd4::Md4::ff(c, d, a, b, words[14], bmd4::S13); /* 15 */
        b = bmd4::Md4::ff(b, c, d, a, words[15], bmd4::S14); /* 16 */

        /* 5 */
        a = bmd4::Md4::gg(a, b, c, d, words[0], bmd4::S21); /* 17 */

        let (a5, c4) = ((a & (1 << (i-1))) >> (i-1), (c & (1 << (i-1))) >> (i-1));

        let mut change = false;
        match (a5, c4) {
            (0, 1) => {
                words[0] = words[0].wrapping_add(2_u32.pow(i - 4));
                a1 ^= 1 << (i - 1);
                change = true;
            },
            (1, 0) => {
                words[0] = words[0].wrapping_sub(2_u32.pow(i - 4));
                a1 ^= 1 << (i - 1);
                change = true;
            },
            (0, 0) | (1, 1) => (),
            _ => (),
        }

        if change {
            let (b0, c0, d0) = (init[1], init[2], init[3]);
            words[1] = d1.rotate_right(7).wrapping_sub(d0).wrapping_sub(bmd4::Md4::f(a1, b0, c0));
            words[2] = c1.rotate_right(11).wrapping_sub(c0).wrapping_sub(bmd4::Md4::f(d1, a1, b0)); 
            words[3] = b1.rotate_right(19).wrapping_sub(b0).wrapping_sub(bmd4::Md4::f(c1, d1, a1));
            words[4] = a2.rotate_right(3).wrapping_sub(a1).wrapping_sub(bmd4::Md4::f(b1, c1, d1));
        }
    }

    for i in [26, 27, 29, 32].iter() {
        words[5] = words[5].wrapping_add(2_u32.pow(i-17));
        words[8] = words[8].wrapping_sub(2_u32.pow(i-10));
        words[9] = words[9].wrapping_sub(2_u32.pow(i-10));
    }
}

#[test]
fn challenge_fifty_five() {
    let mut msg = [0_u8; 64];
    let mut collision = [0_u8; 64];
    let mut rng = thread_rng();

    let mut i = 0;

    loop {
        println!("attempt: {}", i);

        rng.fill(&mut msg);

        let mut words = split_words(&msg);

        // correct message values for a5
        single_step_mod(&mut words[..2]);
        multi_step_mod(&mut words);

        from_words(&words, &mut collision);

        let msg_hash = bmd4::Md4::digest(msg.as_ref()).unwrap();
        let col_hash = bmd4::Md4::digest(collision.as_ref()).unwrap();

        if msg != collision && msg_hash == col_hash { break };

        i += 1;
    }

    let msg_hash = bmd4::Md4::digest(msg.as_ref()).unwrap();
    let col_hash = bmd4::Md4::digest(collision.as_ref()).unwrap();

    assert!(msg != collision);
    assert_eq!(msg_hash, col_hash);
}
