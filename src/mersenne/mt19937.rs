/// Implementation of Mersenne Twister MT19937 based on libc++ and Wikipedia pseudo-code:
///
/// https://github.com/llvm/llvm-project/blob/master/libcxx/include/random#L2075
/// https://en.wikipedia.org/wiki/Mersenne_Twister

const W: u32 = 32;
const N: usize = 624;
const M: usize = 397;

#[allow(dead_code)]
const R: u32 = 31;

const A: u32 = 0x9908_b0df;

const U: u32 = 11;
const D: u32 = 0xffff_ffff;

const S: u32 = 7;
const B: u32 = 0x9d2c_5680;

const T: u32 = 15;
const C: u32 = 0xefc6_0000;

const L: u32 = 18;

const F: u32 = 1812433253;

const LOWER_MASK: u32 = 0x7fff_ffff;
const UPPER_MASK: u32 = 0x8000_0000;

pub struct Mt19937 {
    state: [u32; N],
    index: usize,
}

impl Mt19937 {
    /// Create an initialized MT19937 PRNG
    pub fn new(seed: u32) -> Self {
        if seed == 0 {
            // use same default seed as Matsumoto-Nishimura's original code
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
            // xi = f × (xi−1 ⊕ (xi−1 >> (w−2))) + i
            state[i] = (F as u64 * (state[i - 1] ^ (state[i - 1] >> (W - 2))) as u64 + i as u64
                & 0xffff_ffff) as u32;
        }

        Self {
            state: state,
            index: 0,
        }
    }

    /// Extract a tempered value based on MT[index]
    /// calling twist() every n numbers
    pub fn extract_number(&mut self) -> u32 {
        let j = self.index + 1 % N;
        let y = (self.state[self.index] & UPPER_MASK) | (self.state[j] & LOWER_MASK);
        let k = (self.index + M) % N;

        self.state[self.index] = self.state[k] ^ (y >> 1) ^ (A * (y & 1));
        let mut z = self.state[self.index] ^ ((self.state[self.index] >> U) & D);

        self.index = j;

        z ^= (z << S) & B;
        z ^= (z << T) & C;

        z ^ (z >> L)
    }
}
