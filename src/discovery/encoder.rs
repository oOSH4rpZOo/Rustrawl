//! Stateless probe encoding: the TCP sequence number carries the probe index.
//! A reply echoes `seq + 1` in its acknowledgement field, so the index is
//! recovered with plain arithmetic — no in-flight table to maintain or lose
//! on a crash (plan: source-port encoder + seq cookie).
//!
//! `encode(i) = (i+1) * GOLDEN mod 2^32` with `GOLDEN` odd, so the mapping is
//! a bijection on `Z/2^32`; `decode` is the multiplicative inverse. Random
//! garbage in the ack field decodes to a valid-looking index with probability
//! 2^-32, and the engine additionally checks the decoded host against the
//! reply's source address.

const GOLDEN: u32 = 0x9E37_79B1;

/// Newton-Raphson modular inverse modulo 2^32 (valid for odd `a`).
const fn inv32(a: u32) -> u32 {
    let mut x: u32 = 1;
    let mut i = 0;
    while i < 5 {
        x = x.wrapping_mul(2u32.wrapping_sub(a.wrapping_mul(x)));
        i += 1;
    }
    x
}

const INV: u32 = inv32(GOLDEN);

/// Highest encodable probe index (index+1 must fit in a u32).
pub const MAX_PROBES: u64 = u32::MAX as u64 - 1;

pub fn encode(index: u64) -> u32 {
    // Callers gate on MAX_PROBES before encoding; wrapping past u32::MAX+1
    // would alias two probes onto one seq, silently corrupting replies.
    debug_assert!(
        index < MAX_PROBES,
        "probe index {index} overflows the 32-bit cookie"
    );
    ((index + 1) as u32).wrapping_mul(GOLDEN)
}

/// Recovers the probe index from the echoed `ack - 1` value.
pub fn decode(echoed: u32) -> u64 {
    echoed.wrapping_mul(INV).wrapping_sub(1) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inverse_is_correct() {
        assert_eq!(GOLDEN.wrapping_mul(INV), 1);
    }

    #[test]
    fn roundtrip() {
        for i in 0..10_000u64 {
            assert_eq!(decode(encode(i)), i);
        }
        assert_eq!(decode(encode(0)), 0);
        assert_eq!(decode(encode(MAX_PROBES - 1)), MAX_PROBES - 1);
    }

    #[test]
    fn injective() {
        // bijection on a dense sample: no two nearby indexes share a seq
        let mut seen = std::collections::HashSet::new();
        for i in 0..50_000u64 {
            assert!(seen.insert(encode(i)));
        }
    }

    #[test]
    fn garbage_rarely_decodes_in_range() {
        // a fixed pseudo-random sample decodes somewhere, but the engine's
        // `idx < total` bound catches it; here we just assert the invariant
        let mut hits = 0;
        for k in 0..100_000u32 {
            let idx = decode(k.wrapping_mul(0x85EB_CA6B));
            if idx < 10_000 {
                hits += 1;
            }
        }
        // ~100_000 * 10_000 / 2^32 ≈ 0.23 expected false hits
        assert!(hits < 10, "too many false decodes: {hits}");
    }
}
