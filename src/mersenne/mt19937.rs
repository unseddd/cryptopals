/// Implementation of Mersenne Twister MT19937 based on libc++ and Wikipedia pseudo-code:
///
/// https://github.com/llvm/llvm-project/blob/master/libcxx/include/random#L2075
/// https://en.wikipedia.org/wiki/Mersenne_Twister

pub const W: u32 = 32;
pub const N: usize = 624;
pub const M: usize = 397;

#[allow(dead_code)]
pub const R: u32 = 31;

pub const A: u32 = 0x9908_b0df;

pub const U: u32 = 11;
pub const D: u32 = 0xffff_ffff;

pub const S: u32 = 7;
pub const B: u32 = 0x9d2c_5680;

pub const T: u32 = 15;
pub const C: u32 = 0xefc6_0000;

pub const L: u32 = 18;

pub const F: u32 = 1812433253;

pub const LOWER_MASK: u32 = 0x7fff_ffff;
pub const UPPER_MASK: u32 = 0x8000_0000;

/// MT19937 PRNG (32-bit)
pub struct Mt19937 {
    pub(crate) state: [u32; N],
    pub(crate) index: usize,
}

impl Mt19937 {
    /// Create an initialized MT19937 PRNG
    pub fn new(seed: u32) -> Self {
        if seed == 0 {
            // use same default seed as libc++
            // generally, never want to do this, but this is broken crypto anyway
            Self::init(5489)
        } else {
            Self::init(seed)
        }
    }

    // Initialize the generator from a given seed
    fn init(seed: u32) -> Self {
        let mut state = [0_u32; N];
        state[0] = seed;

        for i in 1..N {
            Self::k_distribute(&mut state, i);
        }

        Self {
            state: state,
            index: 0,
        }
    }

    /// Perform k-distribution step to generate initial state from seed value
    pub(crate) fn k_distribute(state: &mut [u32; N], i: usize) {
        // xi = f × (xi−1 ⊕ (xi−1 >> (w−2))) + i
        state[i] = (F as u64 * (state[i - 1] ^ (state[i - 1] >> (W - 2))) as u64 + i as u64
            & 0xffff_ffff) as u32;
    }

    /// Extract a tempered value based on MT[index]
    /// calling twist() every n numbers
    pub fn extract_number(&mut self) -> u32 {
        Self::twist(&mut self.state, self.index);

        let mut z = self.state[self.index] ^ ((self.state[self.index] >> U) & D);

        self.index = (self.index + 1) % N;

        z ^= (z << S) & B;
        z ^= (z << T) & C;

        z ^ (z >> L)
    }

    /// Perform the Twist on a given state at a given index
    pub(crate) fn twist(state: &mut [u32; N], index: usize) {
        let j = (index + 1) % N;
        let y = (state[index] & UPPER_MASK) | (state[j] & LOWER_MASK);
        let k = (index + M) % N;

        state[index] = state[k] ^ (y >> 1) ^ (A * (y & 1));
    }
}
