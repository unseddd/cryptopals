mod common;

use cryptopals::gauss::*;

fn print_matrix(matrix: &[u8]) {
    println!("[");
    for (i, row) in matrix[..8].iter().enumerate() {
        print!("{} {} {} {} {} {} {} {}",
                 (row & (1 << 7)) >> 7,
                 (row & (1 << 6)) >> 6,
                 (row & (1 << 5)) >> 5,
                 (row & (1 << 4)) >> 4,
                 (row & (1 << 3)) >> 3,
                 (row & (1 << 2)) >> 2,
                 (row & (1 << 1)) >> 1,
                 row & 1,
        );
        print!(" | {}\n", (matrix[8] & (1 << i)) >> i);
    }
    println!("]");
}

fn print_matrix_result(res: &Result<[u8; 9], Error>) {
    match res {
        Ok(m) => {
            println!("Reduced matrix: ");
            print_matrix(m);
        },
        Err(Error::NoSolutions(m)) => {
            println!("No solutions possible for the matrix:");
            print_matrix(m);
        }, 
        Err(Error::InfiniteSolutions(m)) => {
            println!("Infinite solutions possible for the matrix:");
            print_matrix(m);
        }, 
        Err(e) => println!("Error: {:?}", e),
    };
}

#[test]
fn check_reduction() {
    assert_eq!(to_column(&[0b0000_0001, 0b0000_0011, 0b0000_00101, 0b0000_1001, 0b0001_0001, 0b0010_0001, 0b0100_0001, 0b1000_0001], 7).unwrap(), 0b1111_1111);

    let mut res = reduction(&[0x47, 0x4d, 0x12, 0x49, 0x14, 0x2b, 0x11, 0x07]);
    print_matrix_result(&res);

    res = reduction(&[0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80]);
    print_matrix_result(&res);
}

#[test]
fn check_solvable() {
    //let in_block = [
    //    0xd, 0xf, 0xe, 0xf, 0x3, 0xb, 0xe, 0x4, 0x3, 0x7, 0xd, 0x2, 0x9, 0x4, 0xb, 0x1,
    //    0x7, 0xc, 0x1, 0x0, 0xf, 0xe, 0x8, 0xa, 0x9, 0x6, 0xd, 0xb, 0xe, 0x1, 0x9, 0x9,
    //    0xf, 0xa, 0xb, 0x1, 0x6, 0xb, 0x9, 0xb, 0x7, 0xe, 0x7, 0x8, 0x8, 0x9, 0x2, 0x9,
    //    0xb, 0x3, 0xd, 0xf, 0x9, 0x9, 0x3, 0x8, 0x9, 0xb, 0xc, 0x4, 0xf, 0xc, 0xe, 0xd,
    //    0xd, 0x5, 0xc, 0xd, 0xa, 0xf, 0x7, 0xa, 0x2, 0x1, 0x4, 0x6, 0xb, 0x1, 0x7, 0xc,
    //    0xa, 0x9, 0x5, 0x3, 0xc, 0x9, 0x6, 0x3, 0xe, 0xb, 0x4, 0x0, 0xe, 0xc, 0x7, 0xa,
    //    0x6, 0x5, 0x1, 0x7, 0x9, 0xb, 0xa, 0x2, 0xf, 0xb, 0xd, 0x8, 0x9, 0x5, 0x3, 0xd,
    //    0xf, 0x9, 0x6, 0xb, 0x2, 0xb, 0x4, 0x8, 0xe, 0x6, 0x8, 0x5, 0x2, 0x4, 0x4, 0x2,
    //    0x4, 0xb, 0xe, 0x1, 0x5, 0x0, 0x3, 0xb, 0x4, 0xd, 0x4, 0x4, 0xa, 0xb, 0x7, 0x4,
    //    0x7, 0x1, 0x3, 0xb, 0x0, 0xf, 0x1, 0x9, 0xc, 0x3, 0x0, 0xf, 0xe, 0x8, 0xd, 0xa,
    //    0x6, 0x4, 0x9, 0x1, 0x0, 0xf, 0xd, 0x1, 0x0, 0x2, 0x3, 0xa, 0x0, 0x6, 0x1, 0x8,
    //    0x5, 0x2, 0xa, 0xe, 0x6, 0x1, 0xa, 0x3, 0x2, 0x7, 0x1, 0xe, 0x3, 0x6, 0xe, 0x3,
    //    0xa, 0xd, 0x8, 0xc, 0x5, 0x1, 0x6, 0xb, 0x2, 0x3, 0xc, 0x4, 0xe, 0x1, 0x5, 0x8,
    //    0xd, 0xd, 0x2, 0xe, 0x6, 0xb, 0x7, 0x7, 0xa, 0xd, 0x3, 0x9, 0x3, 0x9, 0x7, 0x7,
    //    0x5, 0xf, 0x5, 0x6, 0x7, 0x7, 0xa, 0xd, 0x1, 0xa, 0x7, 0xe, 0xa, 0x9, 0x2, 0x0,
    //    0xd, 0x6, 0xb, 0x4, 0xd, 0x7, 0xd, 0xa, 0xa, 0xd, 0x6, 0xd, 0xf, 0x4, 0x8, 0xf,
    //    0x7, 0x7, 0xb, 0xe, 0x4, 0x8, 0x6, 0x7, 0xc, 0xf, 0xf, 0x6, 0x2, 0x5, 0x1, 0x8,
    //    0x9, 0x8, 0x7, 0x6, 0x8, 0xa, 0x7, 0x6, 0xc, 0x2, 0x4, 0x8, 0xe, 0x1, 0xe, 0xe,
    //    0x1, 0x4, 0xb, 0x7, 0x1, 0x5, 0x9, 0xd, 0x4, 0xe, 0x6, 0xe, 0x9, 0xd, 0xa, 0xe,
    //    0xd, 0x5, 0xb, 0x2, 0x3, 0x5, 0x9, 0x6, 0x1, 0x1, 0xe, 0xc, 0x9, 0xd, 0x6, 0xd,
    //    0x9, 0x4, 0x0, 0x6, 0xb, 0x9, 0x7, 0x4, 0xf, 0x7, 0x1, 0x0, 0xb, 0x4, 0x2, 0xd,
    //    0x7, 0x2, 0x2, 0x8, 0x8, 0x1, 0xf, 0xb, 0x2, 0xe, 0x5, 0xb, 0xe, 0xc, 0xa, 0x1,
    //    0x2, 0x6, 0x9, 0xc, 0x5, 0xf, 0x6, 0x6, 0xa, 0xe, 0x3, 0x0, 0xa, 0x5, 0x3, 0xd,
    //    0x7, 0x7, 0x2, 0xe, 0x4, 0x7, 0x9, 0x5, 0x8, 0x0, 0x3, 0x7, 0x7, 0xd, 0xa, 0xd,
    //    0x0, 0xe, 0xb, 0x7, 0xa, 0x1, 0x1, 0x6, 0x9, 0x7, 0x3, 0x9, 0xd, 0x3, 0xf, 0x4,
    //    0xe, 0xf, 0xd, 0x3, 0x4, 0x2, 0x7, 0x6, 0x4, 0x9, 0x1, 0x9, 0xe, 0x0, 0x9, 0xb,
    //    0xf, 0x1, 0x7, 0x3, 0xa, 0x1, 0x2, 0xd, 0xa, 0xb, 0x9, 0x2, 0xc, 0x4, 0x1, 0x4,
    //    0xb, 0xe, 0x3, 0x6, 0x3, 0xf, 0x7, 0xe, 0x6, 0x8, 0x8, 0x4, 0x6, 0x4, 0x2, 0x4,
    //    0x5, 0xd, 0x8, 0x5, 0x7, 0x2, 0xc, 0x6, 0x3, 0xa, 0xd, 0xa, 0x5, 0xd, 0x6, 0x2,
    //    0x4, 0xf, 0xc, 0x1, 0x2, 0xb, 0x8, 0x3, 0xd, 0x7, 0x2, 0xf, 0xa, 0xd, 0x4, 0xc,
    //    0xf, 0x8, 0xa, 0x5, 0xd, 0x7, 0xe, 0xf, 0xa, 0x0, 0xc, 0x0, 0x8, 0x9, 0x6, 0x2,
    //    0xa, 0x7, 0x7, 0xc, 0x8, 0x1, 0x9, 0x5, 0x6, 0x6, 0xd, 0xe, 0x4, 0x1, 0xc, 0xe,
    //    0x9, 0x3, 0x6, 0x6, 0x1, 0x9, 0x2, 0xc, 0x8, 0x3, 0xa, 0x3, 0x7, 0xc, 0x0, 0x6,
    //    0x9, 0xa, 0xe, 0xc, 0x1, 0x0, 0xd, 0xe, 0x3, 0x8, 0xb, 0xa, 0x2, 0x4, 0x6, 
    //];

    let in_block = [
        0x2, 0x2, 0xc, 0x9, 0x1, 0x1, 0x1, 0xd, 0xe, 0x4, 0x7, 0xc, 0xa, 0xc, 0x5, 0x4,
        0x3, 0xa, 0x2, 0x3, 0x2, 0x5, 0x5, 0x6, 0x8, 0xc, 0x8, 0xd, 0x1, 0x2, 0x8, 0xa,
        0xd, 0x1, 0x1, 0xf, 0x7, 0x7, 0x9, 0x1, 0xf, 0x8, 0xc, 0x1, 0x4, 0x2, 0x0, 0x2,
        0x7, 0x1, 0x2, 0xb, 0x6, 0x4, 0xe, 0xb, 0xf, 0xa, 0x9, 0x2, 0x5, 0x6, 0x3, 0xe,
        0x8, 0x4, 0x5, 0x9, 0x5, 0x2, 0x3, 0x5, 0xe, 0x2, 0x6, 0xf, 0x8, 0x3, 0xe, 0xe,
        0x4, 0x6, 0x7, 0x7, 0x7, 0x2, 0xd, 0x1, 0x9, 0xe, 0xa, 0x3, 0x4, 0xe, 0x5, 0x1,
        0x7, 0xa, 0x8, 0x7, 0x1, 0x3, 0x6, 0x7, 0xe, 0x5, 0xb, 0x0, 0x7, 0xf, 0xd, 0x3,
        0x5, 0x7, 0xd, 0x6, 0x2, 0x2, 0x2, 0xb, 0xa, 0x5, 0x2, 0xc, 0xd, 0x9, 0x7, 0xd,
        0x5, 0x7, 0xa, 0xe, 0xb, 0xf, 0xe, 0xa, 0xc, 0x4, 0xb, 0x7, 0x3, 0x3, 0x5, 0x9,
        0x7, 0xd, 0x5, 0x1, 0x5, 0xf, 0x3, 0xd, 0x5, 0xf, 0xa, 0xf, 0xd, 0xe, 0xb, 0x0,
        0xc, 0x8, 0x5, 0xe, 0x3, 0x8, 0x3, 0x2, 0x1, 0xe, 0xc, 0x8, 0x1, 0x6, 0xb, 0x4,
        0x7, 0xf, 0x4, 0xe, 0x1, 0x4, 0xf, 0xb, 0x4, 0xd, 0xd, 0x7, 0x4, 0xa, 0x3, 0xd,
        0x5, 0x9, 0xe, 0x2, 0xa, 0x3, 0xe, 0x9, 0xb, 0x5, 0x6, 0xd, 0xb, 0x5, 0xe, 0x5,
        0x2, 0xe, 0xb, 0x7, 0x1, 0x9, 0xe, 0xb, 0xd, 0x7, 0x5, 0x7, 0x6, 0x2, 0x0, 0xc,
        0xc, 0xd, 0x2, 0x6, 0xb, 0x5, 0x6, 0xd, 0x3, 0x7, 0xa, 0xe, 0xc, 0x9, 0x8, 0xd,
        0x7, 0x1, 0xd, 0x5, 0x8, 0x7, 0xf, 0xb, 0x1, 0xe, 0x2, 0xc, 0xa, 0xc, 0xe, 0xb,
        0x9, 0x8, 0x8, 0x9, 0x3, 0xe, 0xa, 0xa, 0xd, 0x1, 0x7, 0x7, 0x6, 0x5, 0x1, 0xf,
        0xd, 0x1, 0x4, 0xd, 0xf, 0x1, 0x4, 0x5, 0x1, 0x4, 0x3, 0x3, 0xa, 0x5, 0x3, 0xf,
        0x8, 0xf, 0x1, 0x7, 0x5, 0x3, 0x7, 0xd, 0x2, 0xb, 0xd, 0x2, 0x8, 0xc, 0xe, 0xf,
        0x7, 0x4, 0xc, 0x9, 0x7, 0x5, 0xa, 0x6, 0x7, 0xf, 0x7, 0x9, 0x8, 0x3, 0x5, 0xf,
        0x3, 0xd, 0x7, 0xb, 0xa, 0x5, 0xb, 0x6, 0x3, 0x6, 0x6, 0xf, 0x4, 0x7, 0x6, 0xe,
        0x2, 0xc, 0xd, 0x9, 0xb, 0xd, 0x3, 0x3, 0xa, 0x6, 0x9, 0x6, 0xf, 0xe, 0x2, 0x5,
        0x6, 0xb, 0xb, 0xe, 0xf, 0x7, 0xe, 0x8, 0x7, 0xc, 0x8, 0xb, 0x7, 0x3, 0x1, 0x8,
        0xe, 0x2, 0x4, 0x5, 0xc, 0x1, 0xa, 0xe, 0xc, 0x3, 0x9, 0x7, 0x8, 0x6, 0x7, 0xc,
        0xf, 0x2, 0xd, 0xc, 0x6, 0x3, 0x4, 0xa, 0xd, 0x4, 0x4, 0xc, 0x9, 0xc, 0x4, 0xc,
        0xa, 0x1, 0x7, 0xb, 0x9, 0x4, 0x4, 0xe, 0x5, 0x0, 0xc, 0xa, 0x8, 0x2, 0xa, 0x3,
        0x7, 0xf, 0x2, 0xf, 0xf, 0x7, 0x4, 0xa, 0x6, 0x1, 0xa, 0x9, 0xa, 0x3, 0x7, 0xc,
        0x8, 0x1, 0xd, 0x9, 0xc, 0xa, 0x7, 0x1, 0x4, 0xa, 0x8, 0x3, 0x4, 0xe, 0x5, 0xd,
        0x4, 0x0, 0xa, 0x1, 0x3, 0xb, 0x4, 0x8, 0xd, 0xa, 0x8, 0xe, 0x6, 0x7, 0xb, 0xd,
        0xb, 0x3, 0x2, 0x8, 0x1, 0x9, 0x5, 0x6, 0xe, 0xb, 0xd, 0x4, 0xa, 0x5, 0x1, 0x2,
        0xb, 0x8, 0x3, 0x5, 0xd, 0xd, 0x4, 0x7, 0x4, 0xe, 0x9, 0x6, 0x4, 0xf, 0x5, 0xa,
        0xd, 0x4, 0xc, 0xd, 0xe, 0x6, 0xb, 0xd, 0xb, 0xd, 0xd, 0x9, 0x5, 0x5, 0x0, 0x6,
        0xb, 0xd, 0x6, 0xa, 0x4, 0x8, 0xa, 0x5, 0xa, 0x9, 0x4, 0xb, 0xc, 0xb, 0x0, 0x4,
        0x3, 0x7, 0x9, 0x7, 0x7, 0xf, 0xf, 0x8, 0xa, 0x5, 0x1, 0x8, 0xd, 0xe, 0x9, 
    ];

    let mut guess = Vec::with_capacity(8);

    for byte in in_block.iter() {
        if guess.contains(byte) {
            continue
        }

        if guess.len() < 8 {
            guess.push(*byte);
        } else {
            swap_if_more_distant(&mut guess, byte);
        }
    }

    println!("guess: {}", common::to_hex(&guess));

    let res = reduction(&guess);
    print_matrix_result(&res);
}
