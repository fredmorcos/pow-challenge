#![warn(clippy::all)]

use rand::distributions::Standard;
use rand::{thread_rng, Rng};
use sha1::{Digest, Sha1};
use std::error::Error;
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::sync::Arc;
use std::time::Instant;

pub type Res<T> = Result<T, Box<dyn Error>>;

const HEX_HASH_LEN: usize = 40;

fn random_string(s: &mut Vec<u8>, len: usize, rng: &mut impl Iterator<Item = u8>) {
    fn pred(&c: &u8) -> bool {
        c != b'\r' && c != b'\t' && c != b'\n' && c != b' '
    }

    s.clear();
    s.extend(rng.filter(pred).take(len));
}

fn hash(mut hasher: Sha1, suffix: &[u8], hash: &mut [u8; HEX_HASH_LEN]) -> Res<()> {
    hasher.update(suffix);
    let hashed = &hasher.finalize()[..];
    hex::encode_to_slice(hashed, hash)?;
    Ok(())
}

#[rustfmt::skip]
fn matches_difficulty<const N: usize>(hash: &[u8]) -> bool {
    if N == 0 {
        true
    } else if N == 1 {
        *unsafe { hash.get_unchecked(0) } < 16
    } else if N == 2 {
        *unsafe { hash.get_unchecked(0) } == 0
    } else if N == 3 {
        *unsafe { hash.get_unchecked(0) } == 0 &&
        *unsafe { hash.get_unchecked(1) } < 16
    } else if N == 4 {
        *unsafe { hash.get_unchecked(0) } == 0 &&
        *unsafe { hash.get_unchecked(1) } == 0
    } else if N == 5 {
        *unsafe { hash.get_unchecked(0) } == 0 &&
        *unsafe { hash.get_unchecked(1) } == 0 &&
        *unsafe { hash.get_unchecked(2) } < 16
    } else if N == 6 {
        *unsafe { hash.get_unchecked(0) } == 0 &&
        *unsafe { hash.get_unchecked(1) } == 0 &&
        *unsafe { hash.get_unchecked(2) } == 0
    } else if N == 7 {
        *unsafe { hash.get_unchecked(0) } == 0 &&
        *unsafe { hash.get_unchecked(1) } == 0 &&
        *unsafe { hash.get_unchecked(2) } == 0 &&
        *unsafe { hash.get_unchecked(3) } < 16
    } else if N == 8 {
        *unsafe { hash.get_unchecked(0) } == 0 &&
        *unsafe { hash.get_unchecked(1) } == 0 &&
        *unsafe { hash.get_unchecked(2) } == 0 &&
        *unsafe { hash.get_unchecked(3) } == 0
    } else if N == 9 {
        *unsafe{ hash.get_unchecked(0) } == 0 &&
        *unsafe{ hash.get_unchecked(1) } == 0 &&
        *unsafe{ hash.get_unchecked(2) } == 0 &&
        *unsafe{ hash.get_unchecked(3) } == 0 &&
        *unsafe{ hash.get_unchecked(4) } < 16
    } else {
        panic!("Unsupported difficulty level");
    }
}

fn main() -> Res<()> {
    let len: usize = 8;
    const ITERS: usize = 100_000_000;

    let diff = 7;
    let diff_func_table = &[
        matches_difficulty::<0>,
        matches_difficulty::<1>,
        matches_difficulty::<2>,
        matches_difficulty::<3>,
        matches_difficulty::<4>,
        matches_difficulty::<5>,
        matches_difficulty::<6>,
        matches_difficulty::<7>,
        matches_difficulty::<8>,
        matches_difficulty::<9>,
    ];
    let matches_difficulty_func = diff_func_table[diff];

    let authdata = "kHtMDdVrTKHhUaNusVyBaJybfNMWjfxnaIiAYqgfmCTkNKFvYGloeHDHdsksfFla";
    let mut base_hasher = Sha1::default();
    base_hasher.update(authdata);

    let total_iters = Arc::new(AtomicUsize::new(0));
    let nthreads = rayon::current_num_threads();

    let stop = Arc::new(AtomicBool::new(false));
    let result_suffix = Arc::new(parking_lot::const_mutex(None));

    let start = Instant::now();
    rayon::scope(|scope| {
        for thread_i in 0..nthreads {
            let base_hasher = &base_hasher;
            let total_iters = total_iters.clone();
            let stop = stop.clone();
            let result_suffix = result_suffix.clone();

            scope.spawn(move |_| {
                let mut rng = thread_rng().sample_iter(Standard);
                let mut suffix = Vec::with_capacity(len);
                let mut hex_hash = [0u8; HEX_HASH_LEN];

                let mut iters = 0;
                for i in 0..ITERS {
                    random_string(&mut suffix, len, &mut rng);
                    // hash(base_hasher.clone(), &suffix, &mut hex_hash).unwrap();

                    let mut hasher = base_hasher.clone();
                    hasher.update(&suffix);
                    let hashed = &hasher.finalize()[..];

                    if matches_difficulty_func(hashed) {
                        stop.store(true, std::sync::atomic::Ordering::Release);

                        let mut result_suffix =
                            if let Some(result_suffix) = result_suffix.try_lock() {
                                result_suffix
                            } else {
                                // Another thread is writing a result they've found, the
                                // current thread can give up.
                                iters = i;
                                break;
                            };

                        *result_suffix = Some(suffix);

                        println!(
                            "Thread {}: Found string ({}) {:?}",
                            thread_i,
                            hashed.len(),
                            hashed
                        );

                        if let Err(e) = hex::encode_to_slice(hashed, &mut hex_hash) {
                            println!("Thread {}: Failed to encode hash to hex: {}", thread_i, e);
                        } else if let Ok(hex_hash) = std::str::from_utf8(&hex_hash) {
                            println!(
                                "Thread {}: Found string with \
                                      authentication hash `{}` \
                                      that matches difficulty {}",
                                thread_i, hex_hash, diff
                            );
                        } else {
                            println!(
                                "Thread {}: Found string that \
                                      matches difficulty {}",
                                thread_i, diff
                            );
                        }

                        iters = i;
                        break;
                    }

                    if i % 10_000 == 0 && stop.load(std::sync::atomic::Ordering::Acquire) {
                        println!("Thread {}: stopping", thread_i);
                        iters = i;
                        break;
                    }
                }

                if iters == 0 {
                    iters = ITERS;
                }

                total_iters.fetch_add(iters, std::sync::atomic::Ordering::Release);
            })
        }
    });
    let duration = Instant::now().duration_since(start);

    if let Some(result_suffix) = &*result_suffix.lock() {
        let mut hex_hash = [0u8; HEX_HASH_LEN];
        hash(base_hasher, result_suffix, &mut hex_hash).unwrap();
        if let Ok(hex_hash) = std::str::from_utf8(&hex_hash) {
            println!("Result = {}", hex_hash);
        }
    } else {
        println!("NO RESULT FOUND");
    }
    let total_iters = total_iters.load(std::sync::atomic::Ordering::SeqCst);
    let iters_per_micro = f64::from(total_iters as u32) / f64::from(duration.as_micros() as u32);
    let iters_per_sec = iters_per_micro * 1_000_000.0;
    println!(
        "{}: {} iterations: {} iterations/s",
        humantime::format_duration(duration),
        total_iters,
        iters_per_sec
    );

    Ok(())
}
