pub fn to_hex(hex: &[u8]) -> String {
    hex.iter().map(|x| format!("{:02x}", x)).collect()
}

// read lines from a file into a buffer
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
