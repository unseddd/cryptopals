use alloc::vec::Vec;

/// Constant-time comparison of two byte slices
/// 
/// Returns true if slice lengths and bytes are equal
/// Returns false otherwise
pub fn constant_eq(el: &[u8], ar: &[u8]) -> bool {
    let el_len = el.len() as u64;
    let ar_len = ar.len() as u64;
    let mut res = 0_u8;

    for (ebl, abl) in el_len.to_le_bytes().iter().zip((ar_len).to_le_bytes().iter()) {
        res |= ebl ^ abl;
    }

    let len = core::cmp::min(el_len, ar_len) as usize;

    for (eb, ab) in el[..len].iter().zip(ar[..len].iter()) {
        res |= eb ^ ab;
    }

    res == 0
}

/// XOR two byte slices
///
/// Returns the bitwise XOR of the two byte slices
///
/// If lengths are unequal, XOR of the min length
pub fn xor(el: &[u8], ar: &[u8]) -> Vec<u8> {
    let len = core::cmp::min(el.len(), ar.len());
    let mut res: Vec<u8> = Vec::with_capacity(len);
    for (eb, ab) in el[..len].iter().zip(ar[..len].iter()) {
        res.push(eb ^ ab);
    }
    res
}

/// XOR assign two byte slices
///
/// Computes bitwise XOR of the two bytes slices
/// Assigns the result into the left byte slice
///
/// If lengths are unequal, XOR of the min length
pub fn xor_assign(el: &mut [u8], ar: &[u8]) {
    let len = core::cmp::min(el.len(), ar.len());
    for (eb, ab) in el[..len].iter_mut().zip(ar[..len].iter()) {
        *eb ^= ab;
    }
}
