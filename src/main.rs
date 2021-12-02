#![warn(clippy::all)]

use rand::distributions::{DistIter, Standard};
use rand::prelude::StdRng;
use rand::{Rng, SeedableRng};
use sha1::{Digest, Sha1};
use std::error::Error;
use std::time::Instant;

pub type Res<T> = Result<T, Box<dyn Error>>;

fn random_string(s: &mut String, len: usize, rng: &mut DistIter<Standard, StdRng, char>) {
    fn pred(&c: &char) -> bool {
        c != '\r' && c != '\t' && c != '\n' && c != ' '
    }

    s.clear();
    s.extend(rng.by_ref().filter(pred).take(len));
}

fn hash(mut hasher: Sha1, suffix: &str, hash: &mut [u8]) -> Res<()> {
    hasher.update(suffix);
    let hashed = &hasher.finalize()[..];
    hex::encode_to_slice(hashed, hash)?;
    Ok(())
}

fn matches_difficulty(hash: &[u8], difficulty: u8) -> bool {
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

    hash.starts_with(DIFFICULTY_TABLE[usize::from(difficulty - 1)])
}

fn main() -> Res<()> {
    const LEN: usize = 32;
    const HEX_HASH_LEN: usize = 40;
    let diff = 7;

    let mut rng: DistIter<Standard, StdRng, char> = StdRng::from_entropy().sample_iter(Standard);
    let authdata = "kHtMDdVrTKHhUaNusVyBaJybfNMWjfxnaIiAYqgfmCTkNKFvYGloeHDHdsksfFla";
    let mut suffix = String::with_capacity(LEN);
    let mut hex_hash = [0u8; HEX_HASH_LEN];

    let mut base_hasher = Sha1::default();
    base_hasher.update(authdata);

    let start = Instant::now();

    let mut iters = 0;
    for _ in 0..100_000_000 {
        iters += 1;

        let hasher = base_hasher.clone();
        random_string(&mut suffix, LEN, &mut rng);
        hash(hasher, &suffix, &mut hex_hash)?;

        if matches_difficulty(&hex_hash, diff) {
            println!(
                "Found string with authentication hash `{}` that matches difficulty {}",
                std::str::from_utf8(&hex_hash).unwrap(),
                diff
            );

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

    Ok(())
}