/// Implementation of Mersenne Twister MT19937 based on libc++ and Wikipedia pseudo-code:
///
/// https://github.com/llvm/llvm-project/blob/master/libcxx/include/random#L2075
/// https://en.wikipedia.org/wiki/Mersenne_Twister

const W: u64 = 64;
const N: usize = 312;
const M: usize = 156;

const R: u64 = 31;

const A: u64 = 0xb502_6f5a_a966_19e9;

const U: u64 = 29;
const D: u64 = 0x5555_5555_5555_5555;

const S: u64 = 17;
const B: u64 = 0x71d_67ff_feda_60000;

const T: u64 = 37;
const C: u64 = 0xfff7_eee0_0000_0000;

const L: u64 = 43;

const F: u64 = 6_364_136_223_846_793_005;

const LOWER_MASK: u64 = (1 << R) - 1;
const UPPER_MASK: u64 = !LOWER_MASK;

pub struct Mt19937 {
    state: [u64; N],
    index: usize,
}

impl Mt19937 {
    /// Create an initialized MT19937 PRNG
    pub fn new(seed: u64) -> Self {
        if seed == 0 {
            // use same default seed as Matsumoto-Nishimura's original code
            // generally, never want to do this, but this is broken crypto anyway
            Self::init(5489)
        } else {
            Self::init(seed)
        }
    }

    // Initialize the generator from a given seed
    fn init(seed: u64) -> Self {
        let mut state = [0_u64; N];
        state[0] = seed;

        for i in 1..N {
            // xi = f × (xi−1 ⊕ (xi−1 >> (w−2))) + i
            state[i] = (F as u128 * (state[i - 1] ^ (state[i - 1] >> (W - 2))) as u128 + i as u128
                & 0xffff_ffff_ffff_ffff) as u64;
        }

        Self {
            state: state,
            index: 0,
        }
    }

    /// Extract a tempered value based on MT[index]
    /// calling twist() every n numbers
    pub fn extract_number(&mut self) -> u64 {
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

