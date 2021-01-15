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
    let msg = format!("from={:02x}&to={:02x}&amount={:08x}", from_uid, to_uid, 1_000_000_u32);
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
    xor_assign(&mut forged_sig[29+11..29+13], &xor_bytes);

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
    let msg = format!("from={:02x}&tx_list={:02x}:{:08x};{:02x}:{:08x}",
                      from_uid,
                      to_uid,
                      250_000_u32,
                      attack_uid,
                      500_000_u32);
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
    let mac_block = xor(&signed_msg[sig_len-MAC_LEN..], &signed_msg[..MAC_LEN]);
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
