use super::mt19937::*;
use super::Error;

/// Clone an MT19937 PRNG
///
/// Output the next N random numbers of an MT19937 PRNG
/// Recover the twisted state based on the outputs
///
/// The PRNG must be at the beginning of a cycle
pub fn clone(rng: &mut Mt19937) -> Result<Mt19937, Error> {
    if rng.index % N != 0 {
        return Err(Error::InvalidIndex);
    }

    let mut state = [0_u32; N];

    // recover the twisted state from the rng outputs
    // the twisted state will be the input state of the next round
    for i in 0..N {
        state[i] = recover_state(rng.extract_number());
    }

    Ok(Mt19937 {
        state: state,
        index: 0,
    })
}

/// Recover an MT19937 seed knowing that it was seeded from a time
/// not too long in the past
///
/// FIXME: inspired by an answer on the cryptanalysis stackexchange:
/// https://crypto.stackexchange.com/questions/29766/is-it-possible-to-find-a-mersenne-twister-seed-given-only-the-first-output
///
/// Had similar ideas before reading the spoiler, but wanted to find a solution without
/// "cheating" using knowledge of how the MT19937 PRNG was seeded.
///
/// One of the comments on the stackexchange mentions being able to solve the problem
/// using a "bit of algebra". Find out how and implement
pub fn recover_seed(rand_num: u32, current_time: u32) -> u32 {
    let untempered = recover_state(rand_num);

    let mut state = [0_u32; N];
    for i in current_time - 100_000..current_time {
        state[0] = i;
        for j in 1..=M {
            Mt19937::k_distribute(&mut state, j);
        }
        Mt19937::twist(&mut state, 0);

        if state[0] == untempered {
            return i;
        }
    }

    // seed can never be zero, so use this as an error value
    0
}

/// Recover seed knowing it is a u16 value
pub fn recover_seed_u16(rand_num: u32) -> u16 {
    let untempered = recover_state(rand_num);

    let mut state = [0_u32; N];
    for i in 1..=65535 {
        state[0] = i;
        for j in 1..=M {
            Mt19937::k_distribute(&mut state, j);
        }
        Mt19937::twist(&mut state, 0);

        if state[0] == untempered {
            return i as u16;
        }
    }

    // seed can never be zero, so use this as an error value
    0
}

/// Recover the MT19937 state used to generate the given random number
pub fn recover_state(rand_num: u32) -> u32 {
    // invert the TEMPER_L transformation
    let mut inv_z = untemper_l(rand_num);

    // invert the TEMPER_T transformation
    inv_z = untemper_t(inv_z);

    // invert the TEMPER_S transformation
    inv_z = untemper_s(inv_z);

    // invert the TEMPER_U transformation
    untemper_u(inv_z)
}

// Invert the TEMPER_L transformation
fn untemper_l(rand_num: u32) -> u32 {
    rand_num ^ (rand_num >> L)
}

// Invert the TEMPER_T transformation
fn untemper_t(rand_num: u32) -> u32 {
    rand_num ^ ((rand_num << T) & C)
}

// Invert the TEMPER_S transformation
fn untemper_s(rand_num: u32) -> u32 {
    // we already know the lower 7 bits of TEMPER_S
    // they are the lower 7 bits of the untempered number XORed with zeros
    // mask them with the next 7 bits of B
    let mut res = ((rand_num & 0x7f) << S) & B;

    // XOR with the lower 14 bits of the tempered number
    // which recovers the next 7 bits of the untempered number
    res ^= rand_num & 0x3fff;

    // mask the lower 14 bits of the untempered number with lower 14 bits of B
    res = (res << S) & B;

    // XOR with the lower 21 bits of the tempered number
    // which recovers the next 7 bits of the untempered number
    res ^= rand_num & 0x1fffff;

    // mask the lower 21 bits of the untempered number with lower 21 bits of B
    res = (res << S) & B;

    // XOR with the lower 28 bits of the tempered number
    // which recovers the next 7 bits of the untempered number
    res ^= rand_num & 0xfffffff;

    // mask the lower 28 bits of the untempered number with lower 28 bits of B
    // need to account for the over-shift from S (only 4 bits remain)
    res = (res << S) & B & 0xfffffffd;

    // XOR with the tempered number to recover the full untempered number
    res ^ rand_num
}

// Invert the TEMPER_U transformation
fn untemper_u(rand_num: u32) -> u32 {
    // XOR the upper 11 bits with ones to recover the lower untempered bits
    let mut res = rand_num & 0xffe00000;

    // XOR with the next 11 bits of the tempered number with ones
    // XOR with the recovered 11 bits to recover the upper 22 bits
    res = (rand_num & 0x001ffd00) ^ ((res >> U) & 0x001ffd00) ^ res;

    // mask and XOR the lower 11 bits of the tempered number
    // combine with the recovered bits of the untempered number to recover the full 32 bits
    (rand_num & 0x7ff) ^ ((res >> U) & 0x7ff) ^ (res & 0x001ff800) ^ (res & 0xffe00000)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{thread_rng, RngCore};

    #[test]
    fn check_untemper_l() {
        let rand_num = thread_rng().next_u32();
        let temper_l = rand_num ^ (rand_num >> L);

        assert_eq!(untemper_l(temper_l), rand_num);
    }

    #[test]
    fn check_untemper_t() {
        let rand_num = thread_rng().next_u32();
        let temper_t = rand_num ^ ((rand_num << T) & C);

        assert_eq!(untemper_t(temper_t), rand_num);
    }

    #[test]
    fn check_untemper_s() {
        let rand_num = thread_rng().next_u32();
        let temper_s = rand_num ^ ((rand_num << S) & B);

        assert_eq!(untemper_s(temper_s), rand_num);
    }

    #[test]
    fn check_untemper_u() {
        let rand_num = thread_rng().next_u32();
        let temper_u = rand_num ^ ((rand_num >> U) & D);

        let untemper_u = untemper_u(temper_u);

        assert_eq!(untemper_u, rand_num);
    }

    #[test]
    fn check_recover_state() {
        let seed = 5489;

        let mut generator = Mt19937::new(seed);
        let rand_num = generator.extract_number();

        let twisted_seed = generator.state[0];

        assert_eq!(recover_state(rand_num), twisted_seed);
    }
}
