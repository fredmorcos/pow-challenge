use std::time::Instant;

use rand::distributions::{DistIter, Standard};
use rand::prelude::StdRng;
use rand::{Rng, SeedableRng};
use sha1::{Digest, Sha1};

fn random_string(s: &mut Vec<u8>, len: usize, rng: &mut DistIter<Standard, StdRng, u8>) {
    fn pred(&c: &u8) -> bool {
        c != b'\r' && c != b'\t' && c != b'\n' && c != b' '
    }

    s.clear();
    s.extend(rng.by_ref().filter(pred).take(len));
}

// fn hash(hasher: &mut Sha1, suffix: &str, hash: &mut [u8]) {
// }

fn matches_difficulty(authdata: &str, suffix: &[u8], difficulty: u8, hex_hash: &mut [u8]) -> bool {
    static DIFFICULTY_TABLE: [&[u8]; 9] = [
        b"0",
        b"00",
        b"000",
        b"0000",
        b"00000",
        b"000000",
        b"0000000",
        b"00000000",
        b"000000000",
    ];

    let mut hasher = Sha1::default();
    hasher.update(authdata);
    hasher.update(suffix);
    let hashed = &hasher.finalize()[..];
    hex::encode_to_slice(hashed, hex_hash).unwrap();

    let matches = hex_hash.starts_with(DIFFICULTY_TABLE[usize::from(difficulty - 1)]);
    if matches {
        println!(
            "Found string with authentication hash `{}` that matches difficulty {}",
            std::str::from_utf8(hex_hash).unwrap(),
            difficulty
        );
    }
    matches
}

fn main() {
    const LEN: usize = 32;
    const HEX_HASH_LEN: usize = 40;
    let diff = 7;

    let mut rng: DistIter<Standard, StdRng, u8> = StdRng::from_entropy().sample_iter(Standard);
    let authdata = "kHtMDdVrTKHhUaNusVyBaJybfNMWjfxnaIiAYqgfmCTkNKFvYGloeHDHdsksfFla";
    let mut suffix = Vec::with_capacity(LEN);
    let mut hex_hash = [0u8; HEX_HASH_LEN];
    let start = Instant::now();
    let mut iters = 0;
    for _ in 0..10_000_000 {
        iters += 1;
        random_string(&mut suffix, LEN, &mut rng);
        if matches_difficulty(authdata, &suffix, diff, &mut hex_hash) {
            break;
        }
    }
    let duration = Instant::now().duration_since(start);
    let iters_per_micro = f64::from(iters) / f64::from(duration.as_micros() as i32);
    let iters_per_sec = iters_per_micro * 1_000_000.0;
    println!(
        "{}: {} iterations: {} iterations/s",
        humantime::format_duration(duration),
        iters,
        iters_per_sec
    );
}
