#![warn(clippy::all)]

use rand::distributions::{DistIter, Uniform};
use rand::prelude::ThreadRng;
use rand::{thread_rng, Rng};
use sha1::digest::consts::U20;
use sha1::digest::generic_array::GenericArray;
use sha1::digest::FixedOutput;
use sha1::{Digest, Sha1};
use std::error::Error;
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::sync::Arc;
#[cfg(feature = "timeit")]
use std::time::Duration;
use std::time::Instant;

pub type Res<T> = Result<T, Box<dyn Error>>;

type Distribution = rand::distributions::Uniform<u8>;
type BytesRng = DistIter<Distribution, ThreadRng, u8>;

fn random_string<const LEN: usize>(s: &mut Vec<u8>, rng: &mut BytesRng) {
  s.clear();
  s.extend(rng.take(LEN));
}

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

fn main() -> Res<()> {
  const LEN: usize = 8;

  let diff = 8;
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
  let matches_difficulty_func = DIFF_FUNC_TABLE[diff];

  let authdata = "kHtMDdVrTKHhUaNusVyBaJybfNMWjfxnaIiAYqgfmCTkNKFvYGloeHDHdsksfFla";
  let mut base_hasher = Sha1::default();
  base_hasher.update(authdata.as_bytes());

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
        let mut rng = thread_rng().sample_iter(Uniform::from(33..127));
        let mut suffix = Vec::with_capacity(LEN);
        let mut hashed = Default::default();

        #[cfg(feature = "timeit")]
        let mut time_gen = Duration::ZERO;
        #[cfg(feature = "timeit")]
        let mut time_hashing = Duration::ZERO;
        #[cfg(feature = "timeit")]
        let mut time_checking_match = Duration::ZERO;
        #[cfg(feature = "timeit")]
        let mut time_stop_checking = Duration::ZERO;

        let mut iters = 0;
        loop {
          iters += 1;

          #[cfg(feature = "timeit")]
          let start = Instant::now();
          random_string::<LEN>(&mut suffix, &mut rng);
          #[cfg(feature = "timeit")]
          {
            time_gen += Instant::now().duration_since(start);
          }

          #[cfg(feature = "check")]
          {
            assert!(!suffix.contains(&b'\t'));
            assert!(!suffix.contains(&b'\n'));
            assert!(!suffix.contains(&b'\r'));
            assert!(!suffix.contains(&b' '));
          }

          #[cfg(feature = "timeit")]
          let start = Instant::now();
          hash(base_hasher.clone(), &suffix, &mut hashed);
          #[cfg(feature = "timeit")]
          {
            time_hashing += Instant::now().duration_since(start);
          }

          #[cfg(feature = "timeit")]
          let start = Instant::now();
          let matches = matches_difficulty_func(&hashed);
          #[cfg(feature = "timeit")]
          {
            time_checking_match += Instant::now().duration_since(start);
          }

          if matches {
            stop.store(true, std::sync::atomic::Ordering::Release);

            let mut result_suffix = if let Some(result_suffix) = result_suffix.try_lock() {
              result_suffix
            } else {
              // Another thread is writing a result they've found, the
              // current thread can give up.
              break;
            };

            *result_suffix = Some(suffix);

            println!("Thread {}: Found string ({}) {:?}", thread_i, hashed.len(), hashed);

            println!(
              "Thread {}: Found string with authentication hash `{}` that matches difficulty {}",
              thread_i,
              hex::encode(hashed),
              diff
            );

            break;
          }

          #[cfg(feature = "timeit")]
          let start = Instant::now();
          let should_stop = iters % 10_000 == 0 && stop.load(std::sync::atomic::Ordering::Acquire);
          #[cfg(feature = "timeit")]
          {
            time_stop_checking += Instant::now().duration_since(start);
          }

          if should_stop {
            println!("Thread {}: stopping", thread_i);
            break;
          }
        }

        #[cfg(feature = "timeit")]
        {
          println!(
            "Thread {}: Gen({})  Hash({})  MatchCheck({})  StopCheck({})",
            thread_i,
            humantime::format_duration(time_gen),
            humantime::format_duration(time_hashing),
            humantime::format_duration(time_checking_match),
            humantime::format_duration(time_stop_checking),
          );
        }

        total_iters.fetch_add(iters, std::sync::atomic::Ordering::Release);
      })
    }
  });
  let duration = Instant::now().duration_since(start);

  if let Some(result_suffix) = &*result_suffix.lock() {
    let mut hashed = Default::default();
    hash(base_hasher, result_suffix, &mut hashed);
    println!("Result = {}", hex::encode(hashed));
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
