//! Token bucket pacing with jitter. The bucket caps short bursts at one tenth
//! of the configured rate; the instantaneous rate is resampled inside
//! `±jitter_pct` every few hundred probes so the traffic profile is not a
//! metronome.

use rand::Rng;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::sleep;
use std::time::{Duration, Instant};

pub struct TokenBucket {
    base_rate: f64,
    jitter: f64,
    burst: f64,
    tokens: f64,
    current_rate: f64,
    resample_in: u64,
    last: Instant,
    rng: ChaCha8Rng,
}

impl TokenBucket {
    pub fn new(rate_pps: u64, jitter_pct: u32) -> Self {
        let base_rate = rate_pps.max(1) as f64;
        Self {
            base_rate,
            jitter: f64::from(jitter_pct) / 100.0,
            burst: (base_rate / 10.0).max(1.0),
            tokens: 0.0,
            current_rate: base_rate,
            resample_in: 0,
            last: Instant::now(),
            rng: ChaCha8Rng::from_entropy(),
        }
    }

    fn resample(&mut self) {
        let j = self.jitter;
        self.current_rate = if j > 0.0 {
            self.base_rate * self.rng.gen_range(1.0 - j..=1.0 + j)
        } else {
            self.base_rate
        };
        self.burst = (self.current_rate / 10.0).max(1.0);
        self.resample_in = 512;
    }

    /// Blocks until one token is available. Returns false when `abort` flips.
    pub fn wait_take(&mut self, abort: &AtomicBool) -> bool {
        loop {
            if abort.load(Ordering::Relaxed) {
                return false;
            }
            let now = Instant::now();
            let dt = now.duration_since(self.last).as_secs_f64();
            self.last = now;
            if dt > 1.0 {
                // Long stall (cooldown wait, machine suspend): never dump a
                // full burst accumulated while nobody was probing.
                self.tokens = 0.0;
            }
            self.tokens = (self.tokens + dt * self.current_rate).min(self.burst);
            if self.tokens >= 1.0 {
                self.tokens -= 1.0;
                if self.resample_in == 0 {
                    self.resample();
                }
                self.resample_in -= 1;
                return true;
            }
            // Sleep until the next token instead of a fixed spin — keeps ^C
            // latency low (≤20 ms) without waking hundreds of times a second.
            sleep(Duration::from_millis(
                self.ms_until_token().clamp(1, 20) as u64
            ));
        }
    }

    /// Milliseconds until the next token, for poll() timeouts.
    pub fn ms_until_token(&self) -> i32 {
        if self.tokens >= 1.0 {
            0
        } else {
            let need = (1.0 - self.tokens) / self.current_rate;
            (need * 1000.0).clamp(1.0, 50.0) as i32
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn paces_at_rate() {
        let abort = Arc::new(AtomicBool::new(false));
        let mut b = TokenBucket::new(20_000, 0); // 1000 probes ≈ 50 ms
        let start = Instant::now();
        for _ in 0..1000 {
            assert!(b.wait_take(&abort));
        }
        let ms = start.elapsed().as_millis();
        assert!((25..=200).contains(&ms), "pacing off: {ms} ms");
    }

    #[test]
    fn aborts_promptly() {
        let abort = Arc::new(AtomicBool::new(true));
        let mut b = TokenBucket::new(10_000, 0);
        assert!(!b.wait_take(&abort));
    }
}
