//! Seeded 2-level host permutation (plan: shuffled blocks of `block` IPs,
//! shuffled inside each block). Deterministic in the seed: a persisted seed
//! plus a cursor resumes the exact stream, and both shuffle levels are
//! reproducible regardless of visit order.

use rand::seq::SliceRandom;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

pub struct HostPerm {
    host_total: u64,
    block: u32,
    /// Level-1 shuffle: visit order of the blocks.
    block_order: Vec<u32>,
    seed: [u8; 32],
}

impl HostPerm {
    /// Panics if `host_total` is 0 — callers check before building.
    pub fn new(seed: [u8; 32], host_total: u64, block: u32) -> Self {
        assert!(host_total > 0);
        let block = block.max(1);
        let n_blocks = host_total.div_ceil(u64::from(block));
        let mut order: Vec<u32> = (0..n_blocks as u32).collect();
        order.shuffle(&mut ChaCha8Rng::from_seed(seed));
        Self {
            host_total,
            block,
            block_order: order,
            seed,
        }
    }

    pub fn block_order(&self) -> &[u32] {
        &self.block_order
    }

    /// Level-2 shuffle: host positions inside `block_id`, deterministic per
    /// (seed, block_id) so resume works even with blocks visited out of order.
    pub fn shuffle_block(&self, block_id: u32) -> Vec<u32> {
        let start = u64::from(block_id) * u64::from(self.block);
        let count = (self.host_total - start).min(u64::from(self.block)) as u32;
        let mut v: Vec<u32> = (0..count).collect();
        let block_seed = splitmix(
            u64::from_le_bytes(self.seed[0..8].try_into().expect("8 bytes"))
                ^ u64::from(block_id).wrapping_mul(0x9E37_79B9_7F4A_7C15),
        );
        v.shuffle(&mut ChaCha8Rng::seed_from_u64(block_seed));
        v
    }
}

fn splitmix(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn perm(seed: u64, total: u64, block: u32) -> HostPerm {
        let mut s = [0u8; 32];
        s[..8].copy_from_slice(&seed.to_le_bytes());
        HostPerm::new(s, total, block)
    }

    #[test]
    fn covers_every_host_exactly_once() {
        let p = perm(42, 10_000, 512);
        let mut seen = HashSet::new();
        for &bid in p.block_order() {
            for local in p.shuffle_block(bid) {
                let host = u64::from(bid) * 512 + u64::from(local);
                assert!(seen.insert(host), "duplicate host {host}");
                assert!(host < 10_000);
            }
        }
        assert_eq!(seen.len(), 10_000);
    }

    #[test]
    fn deterministic_per_seed() {
        let a = perm(7, 5_000, 256);
        let b = perm(7, 5_000, 256);
        assert_eq!(a.block_order(), b.block_order());
        for &bid in a.block_order() {
            assert_eq!(a.shuffle_block(bid), b.shuffle_block(bid));
        }
        let c = perm(8, 5_000, 256);
        assert_ne!(a.block_order(), c.block_order());
    }

    #[test]
    fn last_partial_block() {
        // 1001 hosts / 512 = full block of 512 + partial block of 477
        let p = perm(1, 1_001, 512);
        let last = *p.block_order().iter().max().unwrap();
        assert_eq!(p.shuffle_block(last).len(), 1_001 - 512);
    }

    #[test]
    fn really_permutes() {
        // not the identity order
        let p = perm(3, 4_096, 4_096);
        let inner = p.shuffle_block(0);
        assert!(inner.iter().enumerate().any(|(i, &v)| i as u32 != v));
    }
}
