#![warn(clippy::all)]

use humantime::format_duration as humantime;
use rand::distributions::{DistIter, Uniform};
use rand::{thread_rng, Rng, SeedableRng};
use rand_xoshiro::Xoshiro128PlusPlus;
use sha1::digest::consts::U20;
use sha1::digest::generic_array::GenericArray;
use sha1::digest::FixedOutput;
use sha1::{Digest, Sha1};
use std::error::Error;
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::sync::Arc;
use std::time::Instant;

#[cfg(feature = "stats")]
use std::time::Duration;

pub type Res<T> = Result<T, Box<dyn Error>>;

type Distribution = rand::distributions::Uniform<u8>;
type BytesRng = DistIter<Distribution, Xoshiro128PlusPlus, u8>;

// Create a PRNG seeded from a CSRNG. PRNGs are ~3 times faster and we can re-seed every
// once in a while.
fn create_rng(thread_idx: usize) -> BytesRng {
  Xoshiro128PlusPlus::from_rng(thread_rng())
    .unwrap_or_else(|_| panic!("Thread {}: Could not create RNG", thread_idx))
    .sample_iter(Uniform::from(33..127))
}

fn random_string<const LEN: usize>(s: &mut Vec<u8>, rng: &mut BytesRng) {
  s.clear();
  s.extend(rng.take(LEN));
}

// We use the sha-1 crate instead of OpenSSL because it's faster, see
// https://github.com/fredmorcos/sha1_rs_vs_openssl
fn hash(mut hasher: Sha1, suffix: &[u8], hash: &mut GenericArray<u8, U20>) {
  hasher.update(suffix);
  hasher.finalize_into(hash);
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

#[cfg(feature = "stats")]
fn check_suffix(suffix: &[u8]) {
  assert!(!suffix.contains(&b'\t'));
  assert!(!suffix.contains(&b'\n'));
  assert!(!suffix.contains(&b'\r'));
  assert!(!suffix.contains(&b' '));
}

macro_rules! timeit {
  ($e:expr => $var:ident) => {{
    #[cfg(feature = "stats")]
    let start = Instant::now();
    let res = $e;
    #[cfg(feature = "stats")]
    {
      $var += Instant::now().duration_since(start);
    }
    res
  }};
}

#[cfg(feature = "stats")]
fn setup_duration_counters() -> (Duration, Duration, Duration, Duration) {
  let time_gen = Duration::ZERO;
  let time_hashing = Duration::ZERO;
  let time_matching = Duration::ZERO;
  let time_stop = Duration::ZERO;
  (time_gen, time_hashing, time_matching, time_stop)
}

fn get_matches_difficulty_pred(difficulty: usize) -> fn(&[u8]) -> bool {
  const DIFF_FUNC_TABLE: &[fn(&[u8]) -> bool] = &[
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

  DIFF_FUNC_TABLE[difficulty]
}

fn main() -> Res<()> {
  const LEN: usize = 8;

  let authdata = "kHtMDdVrTKHhUaNusVyBaJybfNMWjfxnaIiAYqgfmCTkNKFvYGloeHDHdsksfFla";
  let difficulty = 8;

  let matches_difficulty_pred = get_matches_difficulty_pred(difficulty);

  let mut base_hasher = Sha1::default();
  base_hasher.update(authdata.as_bytes());

  let total_iters = Arc::new(AtomicUsize::new(0));
  let nthreads = rayon::current_num_threads();

  let stop = Arc::new(AtomicBool::new(false));
  let pow_result = Arc::new(parking_lot::const_mutex(None));

  let start = Instant::now();
  rayon::scope(|scope| {
    for thread_idx in 0..nthreads {
      let base_hasher = &base_hasher;
      let total_iters = total_iters.clone();
      let stop = stop.clone();
      let pow_result = pow_result.clone();

      scope.spawn(move |_| {
        let mut rng = create_rng(thread_idx);
        let mut suffix = Vec::with_capacity(LEN);
        let mut hashed = Default::default();

        #[cfg(feature = "stats")]
        let (mut time_gen, mut time_hashing, mut time_matching, mut time_stop) = setup_duration_counters();

        let mut iterations = 0;
        loop {
          iterations += 1;

          timeit!(random_string::<LEN>(&mut suffix, &mut rng) => time_gen);
          timeit!(hash(base_hasher.clone(), &suffix, &mut hashed) => time_hashing);
          let matches = timeit!(matches_difficulty_pred(&hashed) => time_matching);

          #[cfg(feature = "stats")]
          check_suffix(&suffix);

          if matches {
            // Threads check the stop flag every X iterations. This is obviously race-y
            // but it's okay (i.e. it's still correct). The race happens when the current
            // thread sets stop to true, stores the result and exits. Meanwhile, another
            // thread could find a solution before its next scheduled stop check (which
            // happens each X iterations), sets stop to true, stores its result and exits.

            stop.store(true, std::sync::atomic::Ordering::Release);

            let mut pow_result = if let Some(pow_result) = pow_result.try_lock() {
              pow_result
            } else {
              // Another thread is writing a result they've found, the current thread can
              // give up.
              break;
            };

            *pow_result = Some(suffix);

            println!(
              "Thread {}: Found string hash ({} - {:?}) `{}` that matches difficulty {}",
              thread_idx,
              hashed.len(),
              hashed,
              hex::encode(hashed),
              difficulty
            );

            break;
          }

          let do_stop = iterations % 10_000 == 0;
          let do_stop = do_stop && timeit!(stop.load(std::sync::atomic::Ordering::Acquire) => time_stop);
          if do_stop {
            println!("Thread {}: Stopping", thread_idx);
            break;
          }

          // Re-seed with a CSRNG every Y iterations to search a different area in the
          // search space.
          if iterations % 100_000_000 == 0 {
            println!("Thread {}: Reseeding", thread_idx);
            rng = create_rng(thread_idx);
          }
        }

        #[cfg(feature = "stats")]
        println!(
          "Thread {}: Gen({})  Hash({})  MatchCheck({})  StopCheck({})",
          thread_idx,
          humantime(time_gen),
          humantime(time_hashing),
          humantime(time_matching),
          humantime(time_stop),
        );

        total_iters.fetch_add(iterations, std::sync::atomic::Ordering::Release);
      })
    }
  });
  let duration = Instant::now().duration_since(start);

  if let Ok(suffix) = Arc::try_unwrap(pow_result) {
    if let Some(suffix) = suffix.into_inner() {
      let mut hashed = Default::default();
      hash(base_hasher, &suffix, &mut hashed);
      println!("POW suffix = {:?}", suffix);
      println!("POW hash = {}", hex::encode(hashed));
    } else {
      println!("No result found");
    }
  } else {
    println!("No result found");
  }

  let total_iters = total_iters.load(std::sync::atomic::Ordering::SeqCst);
  let iters_per_micro = f64::from(total_iters as u32) / f64::from(duration.as_micros() as u32);
  let iters_per_sec = iters_per_micro * 1_000_000.0;
  println!("{}: {} iterations: {} iterations/s", humantime(duration), total_iters, iters_per_sec);

  Ok(())
}
