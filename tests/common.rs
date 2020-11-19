#[allow(dead_code)]
pub fn to_hex(hex: &[u8]) -> String {
    hex.iter().map(|x| format!("{:02x}", x)).collect()
}

// read lines from a file into a buffer
#[allow(dead_code)]
pub fn read_lines(path: &str) -> Vec<u8> {
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    let file = File::open(path).unwrap();

    let mut res = Vec::new();

    for line in BufReader::new(file).lines() {
        res.extend_from_slice(&line.unwrap().as_bytes());
    }

    res
}

// read lines from a file into a collection of buffers
#[allow(dead_code)]
pub fn read_multi_lines(path: &str) -> Vec<Vec<u8>> {
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    let file = File::open(path).unwrap();

    let mut res: Vec<Vec<u8>> = Vec::new();

    for line in BufReader::new(file).lines() {
        res.push(line.unwrap().as_bytes().to_vec());
    }

    res
}
