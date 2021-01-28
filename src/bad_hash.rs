use alloc::vec::Vec;
use core::convert::TryInto;
use rand::rngs::ThreadRng;
use rand::{thread_rng, Rng, RngCore};

/// Inner block length of the hash function
pub const BLOCK_LEN: usize = craes::aes::BLOCK_LEN;

/// Digest byte-length of the BadHash algorithm
pub const DIGEST_LEN: usize = 2;

const INIT_STATE: u16 = 0x420;
const LESS_INIT_STATE: u32 = 0x42069;

#[derive(Debug)]
pub enum Error {
    InvalidLength,
}

/// Collision data for BadHash algorithm
pub struct BadHashCollision {
    pub state_one: u16,
    pub state_two: u16,
    pub block: [u8; BLOCK_LEN],
    pub collision: u16,
}

impl BadHashCollision {
    pub fn new(s1: u16, s2: u16, block: [u8; BLOCK_LEN], collision: u16) -> Self {
        Self {
            state_one: s1,
            state_two: s2,
            block: block,
            collision: collision,
        }
    }
}

/// A terribly broken Merkle-Damgaard hash function for Cryptopals #52
pub struct BadHash {
    /// Inner state H (way too small for real stuff)
    h: u16,
    block: [u8; BLOCK_LEN],
    index: usize,
    total_len: u64,
}

impl BadHash {
    /// Create a new BadHash instance
    pub fn new() -> Self {
        Self {
            h: INIT_STATE,
            block: [0_u8; BLOCK_LEN],
            index: 0,
            total_len: 0,
        }
    }

    /// Initialize BadHash from the given digest
    pub fn from_digest(digest: u16) -> Self {
        Self {
            h: digest,
            block: [0_u8; BLOCK_LEN],
            index: 0,
            total_len: 0,
        }
    }

    /// Provide input to BadHash
    pub fn input(&mut self, msg: &[u8]) -> Result<(), Error> {
        let msg_len = msg.len();
        let msg_bits = (msg_len * 8) as u64;
        if self.total_len + msg_bits > u64::MAX {
            return Err(Error::InvalidLength);
        }

        self.total_len += msg_bits;

        for block in msg.chunks(BLOCK_LEN) {
            let block_len = block.len();
            if self.index + block_len > BLOCK_LEN {
                self.block[self.index..].copy_from_slice(&block[..BLOCK_LEN - self.index]);
                let orig_index = self.index;
                self.process_block();
                self.index = block_len - (BLOCK_LEN - orig_index);
                self.block[..self.index].copy_from_slice(&block[BLOCK_LEN - orig_index..]);
            } else {
                self.block[self.index..self.index + block_len].copy_from_slice(&block);
                self.index += block_len;
            }
            if self.index == BLOCK_LEN {
                self.process_block()
            };
        }

        Ok(())
    }

    fn process_block(&mut self) {
        let mut key = [0_u8; craes::aes::KEY_LEN_128];
        key[14..].copy_from_slice(&self.h.to_be_bytes());
        let out = craes::aes::aes_128(&self.block, &key);
        self.h = u16::from_be_bytes(out[14..].try_into().unwrap());
        self.index = 0;
        // lol, cause who needs to zero the buffer anyway?
        // leaks old block into temp stack variable
        self.block.swap_with_slice(&mut [0_u8; BLOCK_LEN]);
    }

    /// Finalize the BadHash digest
    pub fn finalize(&mut self) -> u16 {
        if self.index < BLOCK_LEN {
            let ob = self.block[..self.index].to_vec();
            // lol, cause who needs to zero the buffer anyway?
            // leaks old block into temp stack variable
            self.block.swap_with_slice(&mut craes::pkcs7::pad(&ob));
        }
        self.process_block();

        // add full padding block
        self.block[8..].swap_with_slice(&mut self.total_len.to_be_bytes());
        self.process_block();

        let res = self.h;
        self.h = INIT_STATE;
        self.total_len = 0;
        res
    }

    /// Insecurely finalize the BadHash digest by setting the given total length
    ///
    /// Technically, this whole thing is insecure as hell, but w/e
    pub fn finalize_insecure(&mut self, total_len: u64) -> u16 {
        if self.index < BLOCK_LEN {
            let ob = self.block[..self.index].to_vec();
            // lol, cause who needs to zero the buffer anyway?
            // leaks old block into temp stack variable
            self.block.swap_with_slice(&mut craes::pkcs7::pad(&ob));
        }
        self.process_block();

        // add full padding block
        // encode supplied total_len as the last eight bytes of the padding block
        self.block[8..].swap_with_slice(&mut total_len.to_be_bytes());
        self.process_block();

        let res = self.h;
        self.h = INIT_STATE;
        self.total_len = 0;
        res
    }

    /// Get the current internal state
    pub fn state(&self) -> u16 {
        self.h
    }

    /// Get the total bit-length of the hashed message
    pub fn total_len(&self) -> u64 {
        self.total_len
    }

    /// Convenience function to calculate a BadHash digest
    pub fn digest(msg: &[u8]) -> Result<u16, Error> {
        let mut hash = Self::new();
        hash.input(msg)?;
        Ok(hash.finalize())
    }
}

/// A slightly less terribly broken Merkle-Damgaard hash function for Cryptopals #52
pub struct LessBadHash {
    /// Inner state H (way too small for real stuff)
    h: u32,
    block: [u8; BLOCK_LEN],
    index: usize,
    total_len: u64,
}

impl LessBadHash {
    /// Create a new LessBadHash instance
    pub fn new() -> Self {
        Self {
            h: LESS_INIT_STATE,
            block: [0_u8; BLOCK_LEN],
            index: 0,
            total_len: 0,
        }
    }

    /// Provide input to LessBadHash
    pub fn input(&mut self, msg: &[u8]) -> Result<(), Error> {
        let msg_len = msg.len();
        let msg_bits = (msg_len * 8) as u64;
        if self.total_len + msg_bits > u64::MAX {
            return Err(Error::InvalidLength);
        }

        self.total_len += msg_bits;

        for block in msg.chunks(BLOCK_LEN) {
            let block_len = block.len();
            if self.index + block_len > BLOCK_LEN {
                self.block[self.index..].copy_from_slice(&block[..BLOCK_LEN - self.index]);
                let orig_index = self.index;
                self.process_block();
                self.index = block_len - (BLOCK_LEN - orig_index);
                self.block[..self.index].copy_from_slice(&block[BLOCK_LEN - orig_index..]);
            } else {
                self.block[self.index..self.index + block_len].copy_from_slice(&block);
                self.index += block_len;
            }
            if self.index == BLOCK_LEN {
                self.process_block()
            };
        }

        Ok(())
    }

    fn process_block(&mut self) {
        let mut key = [0_u8; craes::aes::KEY_LEN_128];
        key[12..].copy_from_slice(&self.h.to_be_bytes());
        let out = craes::aes::aes_128(&self.block, &key);
        self.h = u32::from_be_bytes(out[12..].try_into().unwrap());
        self.index = 0;
        // lol, cause who needs to zero the buffer anyway?
        // leaks old block into temp stack variable
        self.block.swap_with_slice(&mut [0_u8; BLOCK_LEN]);
    }

    /// Finalize the LessBadHash digest
    pub fn finalize(&mut self) -> u32 {
        if self.index < BLOCK_LEN {
            let ob = self.block[..self.index].to_vec();
            // lol, cause who needs to zero the buffer anyway?
            // leaks old block into temp stack variable
            self.block.swap_with_slice(&mut craes::pkcs7::pad(&ob));
        }
        self.process_block();

        // add full padding block
        self.block[8..].swap_with_slice(&mut self.total_len.to_be_bytes());
        self.process_block();

        let res = self.h;
        self.h = LESS_INIT_STATE;
        self.total_len = 0;
        // return lower 20-bits of H
        res & 0x000f_ffff
    }
}

/// Find n-collisions in BadHash
pub fn find_collisions(
    n: u64,
    rng: &mut ThreadRng,
) -> Result<Vec<([u8; BLOCK_LEN], [u8; BLOCK_LEN], u16)>, Error> {
    let msg = (rng.next_u64() as u128).to_be_bytes();
    let mut res: Vec<([u8; BLOCK_LEN], [u8; BLOCK_LEN], u16)> = Vec::with_capacity(n as usize);

    let mut hash = BadHash::new();
    hash.input(&msg)?;
    let digest = hash.finalize();

    let mut i = 0;
    let mut next = u128::from_be_bytes(msg.clone());
    let domain = u16::MAX as u128;
    while i < n {
        let col_msg = find_collision_with_digest(next, digest)?;
        let col_n = u128::from_be_bytes(col_msg.clone());
        next = col_n + (domain - (col_n % domain));
        res.push((msg.clone(), col_msg, digest));
        i += 1;
    }

    Ok(res)
}

/// Find collision in BadHash against a given digest
pub fn find_collision_with_digest(bound: u128, digest: u16) -> Result<[u8; BLOCK_LEN], Error> {
    let mut hash = BadHash::new();
    let mut next_lo = bound + 1;
    let mut next_hi = bound + 32768;
    loop {
        let mut msg = next_lo.to_be_bytes();
        hash.input(&msg)?;
        if hash.finalize() == digest {
            return Ok(msg);
        } else {
            msg = next_hi.to_be_bytes();
            hash.input(&msg)?;
            if hash.finalize() == digest {
                return Ok(msg);
            }
        }
        next_lo += 1;
        next_hi += 1;
    }
}

/// Generate an expandable message for BadHash digests
pub fn generate_expandable_message(k: usize, msg: &[u8; BLOCK_LEN]) -> Vec<(Vec<u8>, u16)> {
    let mut state = 0;
    let mut rng = thread_rng();
    let mut res: Vec<(Vec<u8>, u16)> = Vec::with_capacity(k);

    for i in 1..=k {
        let mut sng_hash = if i == 1 {
            BadHash::new()
        } else {
            BadHash::from_digest(state)
        };
        sng_hash.input(msg.as_ref()).unwrap();
        let sng_digest = sng_hash.finalize();
        let big_len = 2_usize.pow((k - i) as u32) * BLOCK_LEN;
        let mut big_dummy = Vec::with_capacity(big_len);
        big_dummy.resize(big_len, 0);

        // create a dummy message of 2**(k - i) blocks
        rng.fill(big_dummy.as_mut_slice());

        let mut big_hash = if i == 1 {
            BadHash::new()
        } else {
            BadHash::from_digest(state)
        };
        big_hash.input(&big_dummy).unwrap();
        let dummy_state = big_hash.state();

        // initialize the hash state from the digest of the 2**(k - i) blocks
        // to focus on colliding the final block with the single block message
        let mut dummy_block = [0_u8; BLOCK_LEN];

        loop {
            // fill the last block with garbage until a collision is found
            rng.fill(&mut dummy_block);
            let mut dummy_hash = BadHash::from_digest(dummy_state);
            dummy_hash.input(&dummy_block).unwrap();
            let collision = dummy_hash.finalize();
            if collision == sng_digest {
                big_dummy.extend_from_slice(&dummy_block);
                res.push((big_dummy, sng_digest));
                // update the output state with the colliding hash
                state = collision;
                break;
            }
        }
    }

    res
}

/// Map intermediate BadHash internal states to respective message block
pub fn map_intermediate_states(msg: &[u8]) -> Vec<u16> {
    let mut res: Vec<u16> = Vec::with_capacity(msg.len() / BLOCK_LEN);
    let mut hash = BadHash::new();
    for block in msg.chunks_exact(BLOCK_LEN) {
        hash.input(block).unwrap();
        res.push(hash.state());
    }
    res
}

/// Generate initial tree of BadHash collision states
pub fn generate_initial_tree(k: usize) -> Vec<Vec<BadHashCollision>> {
    let mut rng = thread_rng();
    let mut res: Vec<Vec<BadHashCollision>> = Vec::new();

    let mut block = [0_u8; BLOCK_LEN];
    for i in (1..=k).rev() {
        let mut k_res: Vec<BadHashCollision> = Vec::with_capacity(i);
        // generate 2**i initial states
        if i > 1 {
            let n_states = 2_usize.pow((i - 1) as u32);
            for _j in 0..n_states {
                let state = rng.next_u32();
                let hi_state = (state >> 16) as u16;
                let lo_state = (state & 0xffff) as u16;

                loop {
                    let mut hi_hash = BadHash::from_digest(hi_state);
                    let mut lo_hash = BadHash::from_digest(lo_state);
                    rng.fill(&mut block);
                    hi_hash.input(block.as_ref()).unwrap();
                    lo_hash.input(block.as_ref()).unwrap();
                    let hi_digest = hi_hash.finalize();
                    let lo_digest = lo_hash.finalize();
                    if hi_digest == lo_digest {
                        k_res.push(BadHashCollision::new(
                            hi_state,
                            lo_state,
                            block.clone(),
                            hi_digest,
                        ));
                        break;
                    }
                }
            }
        } else {
            let state = (rng.next_u32() & 0xffff) as u16;
            rng.fill(&mut block);
            let mut hash = BadHash::from_digest(state);
            hash.input(block.as_ref()).unwrap();
            let target = hash.finalize();

            loop {
                hash = BadHash::from_digest(state);
                rng.fill(&mut block);
                hash.input(block.as_ref()).unwrap();
                let digest = hash.finalize();
                if digest == target {
                    k_res.push(BadHashCollision::new(state, state, block.clone(), digest));
                    break;
                }
            }
        }
        res.push(k_res);
    }

    res
}
