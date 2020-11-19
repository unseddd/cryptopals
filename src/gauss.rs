pub const MATRIX_LEN: usize = 8;
pub const AUG_MATRIX_LEN: usize = 9;
pub const SUM_IDX: usize = 8;

#[derive(Debug, PartialEq)]
pub enum Error {
    MatrixLength,
    NoSolutions([u8; AUG_MATRIX_LEN]),
    InfiniteSolutions([u8; AUG_MATRIX_LEN]),
}

pub fn to_column(bytes: &[u8], idx: u8) -> Result<u8, Error> {
    if bytes.len() != MATRIX_LEN {
        return Err(Error::MatrixLength);
    }

    let mut res = 0_u8;

    for i in 0_u8..8_u8 {
        res ^= (bytes[i as usize] & (1 << 7 - idx)) >> (7 - idx) << i;
    }

    Ok(res)
}

/// Convert a slice of eight bytes into an 8x8 matrix
///
/// Each input byte is converted to a matrix column, and the row sums
/// are appended as a final column.
pub fn to_matrix(bytes: &[u8]) -> Result<[u8; AUG_MATRIX_LEN], Error> {
    if bytes.len() != MATRIX_LEN {
        return Err(Error::MatrixLength);
    }

    let mut matrix = [0u8; AUG_MATRIX_LEN];

    for b in 0_u8..8_u8 {
        // convert the bytes to matrix columns
        matrix[b as usize] = to_column(bytes, b)?;

        // treat last index as the augmented column (i.e. the sum of bits in the row)
        matrix[SUM_IDX] ^= (matrix[b as usize].count_ones() as u8 % 2) << b;
    }

    Ok(matrix)
}

/// Swap matrix row sums in the bitvector
///
/// Row indices are zero-indexed, row_i must be less than row_j
fn swap_sums(sum: u8, row_i: u8, row_j: u8) -> u8 {
    if row_i > 7 || row_j > 7 || row_j <= row_i {
        panic!(
            "out-of-bounds row(s) for bitvector sum (row_i: {}, row_j: {})",
            row_i, row_j
        );
    }

    let lo = sum & (1 << row_i);
    let hi = sum & (1 << row_j);

    // pseudo-code as bitvectors
    // b[i] ^= b[j]
    // b[j] ^= b[i]
    // b[i] ^= b[j]
    let dist = (row_j as i8 - row_i as i8).abs() as u8;

    sum ^ lo ^ (hi >> dist) ^ hi ^ (lo << dist)
}

/// XOR row i's sum with row j, updating row j with the result
fn xor_sums(sum: u8, row_i: u8, row_j: u8) -> u8 {
    if row_i > 7 || row_j > 7 {
        panic!(
            "out-of-bounds row(s) for bitvector sum (row_i: {}, row_j: {})",
            row_i, row_j
        );
    }

    let i_sum = sum & (1 << row_i);

    sum ^ if row_i < row_j {
        i_sum << (row_j - row_i)
    } else {
        i_sum >> (row_i - row_j)
    }
}

/// Perform Gauss-Jordan reduction on a matrix
pub fn reduction(bytes: &[u8]) -> Result<[u8; AUG_MATRIX_LEN], Error> {
    let mut matrix = to_matrix(bytes)?;

    for bit in 0..MATRIX_LEN {
        for row in bit..MATRIX_LEN {
            let bitmask = 1 << (7 - bit);
            // if pivot bit is zero, search for a row with a non-zero pivot bit
            if matrix[row] & bitmask == 0 {
                for j in row + 1..MATRIX_LEN {
                    if matrix[j] & bitmask != 0 {
                        // xor-swap the bitvectors
                        matrix[row] ^= matrix[j];
                        matrix[j] ^= matrix[row];
                        matrix[row] ^= matrix[j];

                        // xor-swap the sums
                        matrix[8] = swap_sums(matrix[SUM_IDX], row as u8, j as u8);
                        break;
                    }
                }
            }

            // test pivot bit in current row (after a potential swap)
            // if still zero, nothing to do
            if matrix[row] & bitmask != 0 {
                for j in row + 1..MATRIX_LEN {
                    // if later row has leading bit set, xor with the current row
                    if matrix[j] & bitmask != 0 {
                        matrix[8] = xor_sums(matrix[SUM_IDX], row as u8, j as u8);
                        matrix[j] ^= matrix[row];
                    }
                }
            }
        }
    }

    check_impossible(&matrix)?;

    full_reduction(matrix)
}

fn full_reduction(mut matrix: [u8; AUG_MATRIX_LEN]) -> Result<[u8; AUG_MATRIX_LEN], Error> {
    for bit in 1..MATRIX_LEN {
        for row in bit..MATRIX_LEN {
            let bitmask = 1 << (7 - bit);

            for prev_row in 0..row {
                if matrix[prev_row] & bitmask != 0 {
                    matrix[SUM_IDX] = xor_sums(matrix[SUM_IDX], row as u8, prev_row as u8);
                    matrix[prev_row] ^= matrix[row];
                }
            }
        }
    }

    check_impossible(&matrix)?;

    // check if matrix row has multiple bits turned on after full reduction
    for row in 0..MATRIX_LEN {
        if matrix[row] & !(1 << (7 - row)) != 0 {
            return Err(Error::InfiniteSolutions(matrix));
        }
    }

    Ok(matrix)
}

fn check_impossible(matrix: &[u8; AUG_MATRIX_LEN]) -> Result<(), Error> {
    for row in 0..MATRIX_LEN {
        if matrix[row].count_ones() == 0 && matrix[SUM_IDX] & (1 << row) != 0 {
            return Err(Error::NoSolutions(matrix.clone()));
        }
    }
    Ok(())
}

pub fn swap_if_more_distant(guess: &mut [u8], byte: &u8) {
    if guess.len() != 8 {
        panic!("invalid guess length");
    }

    for i in 0..8 {
        for j in 0..8 {
            if i != j {
                let dist1 = ((guess[i] ^ byte) as u8).count_ones();
                let dist2 = ((guess[j] ^ byte) as u8).count_ones();
                let distg = ((guess[i] ^ guess[j]) as u8).count_ones();

                if dist1 > distg {
                    if dist1 > dist2 {
                        guess[j] = *byte;
                        return;
                    } else {
                        guess[i] = *byte;
                        return;
                    }
                } else if dist2 > distg {
                    guess[i] = *byte;
                    return;
                } else {
                    continue;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_full_reduction() {
        let mut res = full_reduction([
            0b1000_0000,
            0b0100_0000,
            0b0010_0000,
            0b0001_0000,
            0b0000_1000,
            0b0000_0100,
            0b0000_0011,
            0b0000_0000,
            0b1111_1110,
        ]);
        assert!(res.is_err());

        res = full_reduction([
            0b1000_0000,
            0b0100_0000,
            0b0010_0000,
            0b0001_0000,
            0b0000_1000,
            0b0000_0100,
            0b0000_0010,
            0b0000_0000,
            0b1111_1111,
        ]);
        assert!(res.is_err());

        res = full_reduction([
            0b1000_0000,
            0b0100_0000,
            0b0010_0000,
            0b0001_0000,
            0b0000_1000,
            0b0000_0100,
            0b0000_0010,
            0b0000_0001,
            0b1111_1111,
        ]);
        assert!(res.is_ok());

        res = full_reduction([
            0b1000_0000,
            0b0100_0000,
            0b0010_0000,
            0b0001_0000,
            0b0000_1000,
            0b0000_0100,
            0b0000_0010,
            0b0000_0001,
            0b1010_1010,
        ]);
        assert!(res.is_ok());
    }
}
