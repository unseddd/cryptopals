///!  Ported from the [C implementation](../ext/D_SGT_sampson_dennis.c):
///!
///!
///!  Simple Good-Turing Frequency Estimator
///!  
///!  
///!  Geoffrey Sampson, with help from Miles Dennis
///!  
///!  Department of Informatics
///!  Sussex University
///!  
///!  www.grsampson.net
///!  
///!  
///!  First release:  27 June 1995
///!  Revised release:  24 July 2000
///!  This header information revised:  23 March 2005
///!  Further revised release:  8 April 2008
///!  Further revised release:  11 July 2008
///!  
///!  
///!  Takes a set of (frequency, frequency-of-frequency) pairs, and
///!  applies the "Simple Good-Turing" technique for estimating
///!  the probabilities corresponding to the observed frequencies,
///!  and P.0, the joint probability of all unobserved species.
///!  The Simple Good-Turing technique was devised by the late William
///!  A. Gale of AT&T Bell Labs, and described in Gale & Sampson,
///!  "Good-Turing Frequency Estimation Without Tears" (JOURNAL
///!  OF QUANTITATIVE LINGUISTICS, vol. 2, pp. 217-37 -- reprinted in
///!  Geoffrey Sampson, EMPIRICAL LINGUISTICS, Continuum, 2001).
///!  
///!  Anyone is welcome to take copies of this program and use it
///!  for any purpose, at his or her own risk.  If it is used in
///!  connexion with published work, acknowledgment of Sampson and
///!  the University of Sussex would be a welcome courtesy.
///!  
///!  The program is written to take input from "stdin" and send output
///!  to "stdout"; redirection can be used to take input from and
///!  send output to permanent files.  The code is in ANSI standard C.
///!  
///!  The input file should be a series of lines separated by newline
///!  characters, where all nonblank lines contain two positive integers
///!  (an observed frequency, followed by the frequency of that frequency)
///!  separated by whitespace.  (Blank lines are ignored.)
///!  The lines should be in ascending order of frequency, and must
///!  begin with frequency 1.
///!  
///!  No checks are made for linearity; the program simply assumes that the
///!  requirements for using the SGT estimator are met.
///!  
///!  The output is a series of lines each containing an integer followed  
///!  by a probability (a real number between zero and one), separated by a
///!  tab.  In the first line, the integer is 0 and the real number is the
///!  estimate for P.0.  In subsequent lines, the integers are the  
///!  successive observed frequencies, and the reals are the estimated  
///!  probabilities corresponding to those frequencies.
///!  
///!  Later releases cure bugs to which my attention has kindly been
///!  drawn at different times by Martin Jansche of Ohio State University
///!  and Steve Arons of New York City.  No warranty is given
///!  as to absence of further bugs.
///!  
///!  Fan Yang of Next IT Inc., Spokane, Washington, has suggested to me
///!   that in the light of his experience with the SGT technique, for some
///!  data-sets it could be preferable to use the 0.1 significance criterion
///!  actually used in the experiments reported in the Gale & Sampson
///!  paper, rather than the 0.05 criterion suggested in that paper
///!  for the sake of conformity with standard statistical convention.
///!  (See note 8 of the paper.)  Neither Fan Yang nor I have pursued
///!  this far enough to formulate a definite recommendation; but, in
///!  order to make it easier for users of the software to experiment
///!  with alternative confidence levels, the July 2008 release moves
///!  the relevant "magic number" out of the middle of the program into
///!  a #define line near the beginning where it is given the constant
///!  name CONFID_FACTOR.  The value 1.96 corresponds to the p < 0.05
///!  criterion; in order to use the p < 0.1 criterion, 1.96 in the
///!  #define line should be changed to 1.65.
use alloc::vec::Vec;
use libm::{exp, fabs, log, sqrt};

pub const MAX_LINE: usize = 20_480_000;
pub const MAX_ROWS: usize = 20_480_000;
pub const MIN_INPUT: usize = 5;
pub const CONFID_FACTOR_P_LT_05: f64 = 1.96;
pub const CONFID_FACTOR_P_LT_10: f64 = 1.65;

pub trait Square {
    fn sq(self) -> Self;
}

impl Square for f64 {
    fn sq(self) -> Self {
        self * self
    }
}

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidFrequencyFrequency(u64),
    InvalidOrder,
    MinInput,
    MaxRows,
}

#[derive(Debug, PartialEq)]
pub struct Estimator {
    r: Vec<u64>,
    n: Vec<u64>,
    z: Vec<f64>,
    log_r: Vec<f64>,
    log_z: Vec<f64>,
    r_star: Vec<f64>,
    p: Vec<f64>,
    big_n: u64,
    p_zero: f64,
    big_n_prime: f64,
    slope: f64,
    intercept: f64,
}

impl Estimator {
    /// Create a default Estimator
    pub fn new() -> Self {
        Self {
            r: Default::default(),
            n: Default::default(),
            z: Default::default(),
            log_r: Default::default(),
            log_z: Default::default(),
            r_star: Default::default(),
            p: Default::default(),
            big_n: 0,
            p_zero: 0.0,
            big_n_prime: 0.0,
            slope: 0.0,
            intercept: 0.0,
        }
    }

    /// Create an Estimator from list of input frequencies and
    /// the frequency of input frequencies
    pub fn from_input(input: &[(u64, u64)]) -> Result<Self, Error> {
        let input_len = input.len();

        if input_len > MAX_ROWS {
            return Err(Error::MaxRows);
        }

        if input_len < MIN_INPUT {
            return Err(Error::MinInput);
        }

        let mut r: Vec<u64> = Vec::with_capacity(input.len());
        let mut n: Vec<u64> = Vec::with_capacity(input.len());

        for (row, &(hz, hz_hz)) in input.iter().enumerate() {
            if row > 0 && hz <= r[row - 1] {
                return Err(Error::InvalidOrder);
            }

            r.push(hz);

            if hz_hz < 1 {
                return Err(Error::InvalidFrequencyFrequency(hz_hz));
            }

            n.push(hz_hz);
        }

        Ok(Self {
            r: r,
            n: n,
            z: Default::default(),
            log_r: Default::default(),
            log_z: Default::default(),
            r_star: Default::default(),
            p: Default::default(),
            big_n: 0,
            p_zero: 0.0,
            big_n_prime: 0.0,
            slope: 0.0,
            intercept: 0.0,
        })
    }

    /// Analyse inputs and smooth frequencies using simplified Good-Turing technique
    pub fn analyse_input(&mut self) {
        let mut next_n: i64;
        let mut k: f64;
        let mut x: f64;
        let mut y: f64;
        let mut indiff_vals_seen = false;

        self.big_n = 0;

        let entry_len = self.r.len();
        for (&r, &n) in self.r.iter().zip(self.n.iter()) {
            self.big_n += r * n;
        }

        next_n = self.row(1);
        self.p_zero = if next_n < 0 {
            0.0
        } else {
            self.n[next_n as usize] as f64 / self.big_n as f64
        };

        self.z = Vec::with_capacity(entry_len);
        self.log_r = Vec::with_capacity(entry_len);
        self.log_z = Vec::with_capacity(entry_len);

        for row in 0..entry_len {
            let i = if row == 0 { 0 } else { self.r[row - 1] };
            k = if row == entry_len - 1 {
                2.0 * self.r[row] as f64 - i as f64
            } else {
                self.r[row + 1] as f64
            };
            self.z.push(2.0 * self.n[row] as f64 / (k - i as f64));
            self.log_r.push(log(self.r[row] as f64));
            self.log_z.push(log(self.z[row]));
        }

        self.find_best_fit();

        self.r_star = Vec::with_capacity(entry_len);
        for row in 0..entry_len {
            y = (self.r[row] + 1) as f64 * self.smoothed(self.r[row] + 1)
                / self.smoothed(self.r[row]);
            if self.row(self.r[row] + 1) < 0 {
                indiff_vals_seen = true;
            }

            if !indiff_vals_seen {
                next_n = self.n[self.row(self.r[row] + 1) as usize] as i64;
                x = (self.r[row] + 1) as f64 * next_n as f64 / self.n[row] as f64;
                let diff_cmp =
                    CONFID_FACTOR_P_LT_05 * sqrt((self.r[row] as f64 + 1.0).sq()) * next_n as f64
                        / (self.n[row] as f64).sq()
                        * (1.0 + next_n as f64)
                        / self.n[row] as f64;
                if fabs(x - y) <= diff_cmp {
                    indiff_vals_seen = true;
                } else {
                    self.r_star.push(x);
                }
            }
            if indiff_vals_seen {
                self.r_star.push(y);
            }
        }

        self.big_n_prime = 0.0;
        for (&n, &r_star) in self.n.iter().zip(self.r_star.iter()) {
            self.big_n_prime += n as f64 * r_star;
        }

        self.p = Vec::with_capacity(entry_len);
        for r_star in self.r_star.iter() {
            self.p.push((1.0 - self.p_zero) * r_star / self.big_n_prime);
        }
    }

    fn find_best_fit(&mut self) {
        let (mut xys, mut x_squares, mut mean_x, mut mean_y) = (0_f64, 0_f64, 0_f64, 0_f64);

        for (&log_r, &log_z) in self.log_r.iter().zip(self.log_z.iter()) {
            mean_x += log_r as f64;
            mean_y += log_z as f64;
        }

        let rows = self.log_r.len() as f64;
        mean_x /= rows;
        mean_y /= rows;

        for (&log_r, &log_z) in self.log_r.iter().zip(self.log_z.iter()) {
            xys += (log_r as f64 - mean_x) * (log_z as f64 - mean_y);
            x_squares += (log_r as f64 - mean_x).sq();
        }

        self.slope = xys / x_squares;
        self.intercept = mean_y - self.slope * mean_x;
    }

    fn row(&self, i: u64) -> i64 {
        for (idx, &item) in self.r.iter().enumerate() {
            if item == i {
                return idx as i64;
            }
        }
        -1_i64
    }

    fn smoothed(&self, i: u64) -> f64 {
        exp(log(self.intercept + self.slope * (i as f64)))
    }

    pub fn get_estimates(&self) -> Vec<(u64, f64)> {
        self.r
            .iter()
            .zip(self.p.iter())
            .map(|(&r, &p)| (r, p))
            .collect()
    }

    /// Get frequencies
    pub fn r(&self) -> &[u64] {
        self.r.as_ref()
    }

    /// Get smoothed frequency-of-frequencies
    pub fn p(&self) -> &[f64] {
        self.p.as_ref()
    }

    /// Get P.0, the joint probability of all unobserved species
    pub fn p_zero(&self) -> f64 {
        self.p_zero
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_sq() {
        assert_eq!(2_f64.sq(), 4.0);
    }

    #[test]
    fn sgt_from_input() {
        let mut input: Vec<(u64, u64)> = Vec::with_capacity(5);
        for i in 0..5 {
            input.push((i + 1, i + 1));
        }
        let mut sgt = Estimator::from_input(&input).unwrap();
        sgt.analyse_input();

        let exp_hz_hz = [
            0.04363636363636363,
            0.04909090909090908,
            0.05818181818181819,
            0.06818181818181819,
            0.07854545454545454,
        ];

        let est = sgt.get_estimates();
        for (i, (hz, hz_hz)) in est.iter().enumerate() {
            assert_eq!(*hz as usize, i + 1);
            assert_eq!(*hz_hz, exp_hz_hz[i]);
        }
    }

    #[test]
    fn sgt_bad_rows() {
        let mut input: Vec<(u64, u64)> = Vec::with_capacity(MAX_ROWS + 1);
        for i in 0..input.capacity() {
            input.push((i as u64 + 1, i as u64 + 1));
        }
        let err = Estimator::from_input(&input);
        assert!(err.is_err());
        assert_eq!(err, Err(Error::MaxRows));
    }

    #[test]
    fn sgt_min_input() {
        let mut input: Vec<(u64, u64)> = Vec::with_capacity(MIN_INPUT - 1);
        for i in 0..input.capacity() {
            input.push((i as u64 + 1, i as u64 + 1));
        }
        let err = Estimator::from_input(&input);
        assert!(err.is_err());
        assert_eq!(err, Err(Error::MinInput));
    }
}
