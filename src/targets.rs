//! Resolves includes/excludes into merged IPv4 ranges, with lazy iteration.
//! Never a Vec of 16.7M addresses: ranges, and an iterator.

use std::net::Ipv4Addr;

use anyhow::{bail, Context, Result};

/// Inclusive IPv4 range `[start, end]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpRange {
    pub start: u32,
    pub end: u32,
}

impl IpRange {
    /// Accepts `10.0.0.7`, `10.0.0.0/24` (strict: host bits must be zero)
    /// or `a.b.c.d-e.f.g.h`.
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        if let Some((ip, suffix)) = s.split_once('/') {
            let bits: u8 = suffix
                .trim()
                .parse()
                .with_context(|| format!("invalid CIDR prefix: {s}"))?;
            if bits > 32 {
                bail!("invalid CIDR prefix: {s} (> 32)");
            }
            let raw = ip_parse(ip, s)?;
            let mask = if bits == 0 {
                0
            } else {
                u32::MAX << (32 - bits)
            };
            if raw & !mask != 0 {
                bail!(
                    "{s}: host bits set under /{bits} - write {}",
                    Ipv4Addr::from(raw & mask)
                );
            }
            Ok(IpRange {
                start: raw & mask,
                end: raw | !mask,
            })
        } else if let Some((a, b)) = s.split_once('-') {
            let start = ip_parse(a.trim(), s)?;
            let end = ip_parse(b.trim(), s)?;
            if start > end {
                bail!("inverted range: {s}");
            }
            Ok(IpRange { start, end })
        } else {
            let v = ip_parse(s, s)?;
            Ok(IpRange { start: v, end: v })
        }
    }

    pub fn len(self) -> u64 {
        u64::from(self.end - self.start) + 1
    }

    /// `len`/`is_empty` convention — a range is never empty.
    #[allow(dead_code)] // consumed by the scan engine
    pub fn is_empty(self) -> bool {
        false
    }

    pub fn intersects(self, other: IpRange) -> bool {
        self.start <= other.end && other.start <= self.end
    }
}

fn ip_parse(ip: &str, context: &str) -> Result<u32> {
    ip.parse::<Ipv4Addr>()
        .map(u32::from)
        .with_context(|| format!("invalid IPv4 address: {context}"))
}

/// Perimeter targets: merged includes, subtracted excludes. Sorted, disjoint.
#[derive(Clone)]
pub struct Targets {
    ranges: Vec<IpRange>,
    /// `cum[k]` = number of hosts before range `k` — `nth` is a binary search
    /// (the engines call it per host and per decoded reply, and the expand
    /// stage can hold ~65k /24 ranges).
    cum: Vec<u64>,
}

impl Targets {
    /// Canonical constructor: sorts, merges, precomputes cumulative counts.
    fn new(mut ranges: Vec<IpRange>) -> Targets {
        ranges.sort_by_key(|r| r.start);
        let ranges = merge(ranges);
        let mut cum = Vec::with_capacity(ranges.len() + 1);
        cum.push(0u64);
        let mut total = 0u64;
        for r in &ranges {
            total += r.len();
            cum.push(total);
        }
        Targets { ranges, cum }
    }

    pub fn build(includes: &[String], excludes: &[String]) -> Result<Self> {
        let mut inc = sorted_ranges(includes)?;
        if inc.is_empty() {
            bail!("includes: at least one range required");
        }
        inc = merge(inc);
        let exc = merge(sorted_ranges(excludes)?);
        Ok(Self::new(subtract(&inc, &exc)))
    }

    pub fn total(&self) -> u64 {
        self.ranges.iter().map(|r| r.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    pub fn ranges(&self) -> &[IpRange] {
        &self.ranges
    }

    /// Lazy iteration — works with /8-sized ranges without materializing them.
    #[allow(dead_code)] // consumed by the scan engine
    pub fn iter(&self) -> impl Iterator<Item = Ipv4Addr> + '_ {
        self.ranges
            .iter()
            .flat_map(|r| r.start..=r.end)
            .map(Ipv4Addr::from)
    }

    pub fn intersects(&self, range: IpRange) -> bool {
        self.ranges.iter().any(|r| r.intersects(range))
    }

    /// Host at flat index `n` (0-based over the merged ranges) — binary search
    /// over the cumulative counts. Inverse of the `iter()` order.
    pub fn nth(&self, n: u64) -> Option<Ipv4Addr> {
        let i = self.cum.partition_point(|&c| c <= n).checked_sub(1)?;
        let r = self.ranges.get(i)?;
        let within = n - self.cum[i];
        (within < r.len()).then(|| Ipv4Addr::from(r.start + within as u32))
    }

    /// Removes target ranges (e.g. passive zones) — sorted, disjoint result.
    pub fn subtract(&self, cuts: &[IpRange]) -> Targets {
        let mut cs = cuts.to_vec();
        cs.sort_by_key(|r| r.start);
        let cs = merge(cs);
        Self::new(subtract(&self.ranges, &cs))
    }

    /// Builds from pre-merged, sorted, disjoint ranges (expand derivation).
    pub fn from_ranges(ranges: Vec<IpRange>) -> Targets {
        Self::new(ranges)
    }

    /// Hosts of `self` that also belong to `other` — the expand stage clamps
    /// the /24
    /// union to the contracted perimeter, so an up host at an include edge can
    /// never pull a probe outside it.
    pub fn intersect(&self, other: &Targets) -> Targets {
        Self::new(intersect_ranges(&self.ranges, &other.ranges))
    }

    /// The set as a bitmap — one-shot clamps (finalize ip-list generation),
    /// not a hot path. Dense ranges become roaring bitmap containers.
    pub fn as_bitmap(&self) -> roaring::RoaringBitmap {
        let mut bm = roaring::RoaringBitmap::new();
        for r in &self.ranges {
            bm.insert_range(r.start..=r.end);
        }
        bm
    }

    /// Removes individually skipped hosts (fresh DB verdicts) from the set.
    /// The bitmap becomes merged cut ranges, then the regular subtraction.
    pub fn subtract_bitmap(&self, skip: &roaring::RoaringBitmap) -> Targets {
        if skip.is_empty() {
            return self.clone();
        }
        let mut cuts = Vec::new();
        let mut it = skip.iter();
        if let Some(mut start) = it.next() {
            let mut end = start;
            for v in it {
                if v == end + 1 {
                    end = v;
                } else {
                    cuts.push(IpRange { start, end });
                    start = v;
                    end = v;
                }
            }
            cuts.push(IpRange { start, end });
        }
        self.subtract(&cuts)
    }
}

/// The /24 neighborhoods (network and broadcast excluded) of the up hosts,
/// clamped to the contracted perimeter. One range per distinct /24 — a
/// RoaringBitmap of /24 prefixes dedupes before any range exists.
pub fn expand_neighborhoods(up: &roaring::RoaringBitmap, clamp: &Targets) -> Targets {
    let mut bases = roaring::RoaringBitmap::new();
    for ip in up.iter() {
        bases.insert(ip >> 8);
    }
    let parts: Vec<IpRange> = bases
        .iter()
        .map(|b| {
            let base = b << 8;
            IpRange {
                start: base + 1,
                end: base + 254,
            }
        })
        .collect();
    Targets::from_ranges(parts).intersect(clamp)
}

/// Two-pointer intersection of sorted, disjoint ranges.
fn intersect_ranges(a: &[IpRange], b: &[IpRange]) -> Vec<IpRange> {
    let mut out = Vec::new();
    let (mut i, mut j) = (0usize, 0usize);
    while i < a.len() && j < b.len() {
        let start = a[i].start.max(b[j].start);
        let end = a[i].end.min(b[j].end);
        if start <= end {
            out.push(IpRange { start, end });
        }
        if a[i].end < b[j].end {
            i += 1;
        } else {
            j += 1;
        }
    }
    out
}

fn sorted_ranges(entries: &[String]) -> Result<Vec<IpRange>> {
    let mut v = entries
        .iter()
        .map(|s| IpRange::parse(s))
        .collect::<Result<Vec<_>>>()?;
    v.sort_by_key(|r| r.start);
    Ok(v)
}

/// Merges adjacent or overlapping ranges (sorted input).
fn merge(mut ranges: Vec<IpRange>) -> Vec<IpRange> {
    let mut out: Vec<IpRange> = Vec::with_capacity(ranges.len());
    for r in ranges.drain(..) {
        match out.last_mut() {
            Some(last) if r.start <= last.end.saturating_add(1) => {
                last.end = last.end.max(r.end);
            }
            _ => out.push(r),
        }
    }
    out
}

/// Subtracts the cuts (sorted, merged) from each base range.
fn subtract(base: &[IpRange], cuts: &[IpRange]) -> Vec<IpRange> {
    let mut out = Vec::new();
    for r in base {
        let mut pieces = vec![*r];
        for c in cuts {
            let mut next = Vec::new();
            for p in pieces {
                if !p.intersects(*c) {
                    next.push(p);
                    continue;
                }
                if c.start > p.start {
                    next.push(IpRange {
                        start: p.start,
                        end: c.start - 1,
                    });
                }
                if c.end < p.end {
                    next.push(IpRange {
                        start: c.end + 1,
                        end: p.end,
                    });
                }
            }
            pieces = next;
        }
        out.extend(pieces);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(s: &str) -> IpRange {
        IpRange::parse(s).unwrap()
    }

    #[test]
    fn parse_forms() {
        assert_eq!(
            r("10.0.0.7"),
            IpRange {
                start: 0x0A00_0007,
                end: 0x0A00_0007
            }
        );
        assert_eq!(
            r("10.0.0.0/24"),
            IpRange {
                start: 0x0A00_0000,
                end: 0x0A00_00FF
            }
        );
        assert_eq!(
            r("0.0.0.0/0"),
            IpRange {
                start: 0,
                end: u32::MAX
            }
        );
        assert!(IpRange::parse("10.0.0.2-10.0.0.1").is_err());
    }

    #[test]
    fn strict_cidr() {
        assert!(IpRange::parse("10.0.0.1/24").is_err());
        assert!(IpRange::parse("10.0.0.0/33").is_err());
    }

    #[test]
    fn merge_and_excludes() {
        let t = Targets::build(
            &[
                "10.0.0.0/24".into(),
                "10.0.0.128/25".into(),
                "192.168.1.5".into(),
            ],
            &["10.0.0.0/25".into()],
        )
        .unwrap();
        // 10.0.0.0/24 ∪ 10.0.0.128/25 = 10.0.0.0-10.0.0.255 ; minus 10.0.0.0-10.0.0.127
        assert_eq!(t.total(), 128 + 1);
        assert_eq!(t.ranges().len(), 2);
    }

    #[test]
    fn all_excluded() {
        let t = Targets::build(&["10.0.0.0/24".into()], &["10.0.0.0/16".into()]).unwrap();
        assert!(t.total() == 0);
        assert!(t.is_empty());
    }

    #[test]
    fn subtract_zones() {
        let t = Targets::build(&["10.0.0.0/16".into()], &[]).unwrap();
        let scan = t.subtract(&[r("10.0.50.0/24"), r("10.0.60.0/24")]);
        assert_eq!(t.total() - scan.total(), 512);
        // a zone outside the perimeter is a no-op
        let scan2 = t.subtract(&[r("192.168.0.0/24")]);
        assert_eq!(scan2.total(), t.total());
    }

    #[test]
    fn nth_is_iter_inverse() {
        let t = Targets::build(&["10.0.0.0/24".into(), "192.168.1.5".into()], &[]).unwrap();
        for (n, ip) in t.iter().enumerate() {
            assert_eq!(t.nth(n as u64), Some(ip));
        }
        assert_eq!(t.nth(t.total()), None);
        // scattered ranges: boundaries hold
        let t2 = Targets::build(
            &["10.0.0.5-10.0.0.9".into(), "10.0.1.5-10.0.1.6".into()],
            &[],
        )
        .unwrap();
        assert_eq!(t2.nth(0), Some("10.0.0.5".parse().unwrap()));
        assert_eq!(t2.nth(4), Some("10.0.0.9".parse().unwrap()));
        assert_eq!(t2.nth(5), Some("10.0.1.5".parse().unwrap()));
        assert_eq!(t2.nth(6), Some("10.0.1.6".parse().unwrap()));
    }

    #[test]
    fn intersect_clamps() {
        let scope = Targets::build(&["10.0.0.5-10.0.0.10".into()], &[]).unwrap();
        let wide = Targets::build(&["10.0.0.0/24".into(), "10.0.5.0/24".into()], &[]).unwrap();
        let got = wide.intersect(&scope);
        assert_eq!(got.total(), 6);
        assert_eq!(got.ranges(), &[r("10.0.0.5-10.0.0.10")]);
        // disjoint inputs → empty
        assert!(Targets::build(&["192.168.0.0/24".into()], &[])
            .unwrap()
            .intersect(&scope)
            .is_empty());
    }

    #[test]
    fn expand_neighborhoods_shape() {
        let clamp = Targets::build(&["10.0.0.0/16".into()], &["10.0.9.0/24".into()]).unwrap();
        let mut up = roaring::RoaringBitmap::new();
        up.insert(r("10.0.0.7").start);
        up.insert(r("10.0.0.200").start); // same /24, deduped
        up.insert(r("10.0.9.3").start); // excluded /24 — clamped away
        up.insert(r("192.168.5.1").start); // outside the perimeter
        let got = expand_neighborhoods(&up, &clamp);
        assert_eq!(got.total(), 254, "one /24, network+broadcast excluded");
        assert_eq!(got.ranges(), &[r("10.0.0.1-10.0.0.254")]);
        // adjacent /24s stay split: network and broadcast of the seam are not probed
        let mut two = roaring::RoaringBitmap::new();
        two.insert(r("10.0.0.1").start);
        two.insert(r("10.0.1.254").start);
        let got2 =
            expand_neighborhoods(&two, &Targets::build(&["10.0.0.0/16".into()], &[]).unwrap());
        assert_eq!(got2.total(), 508);
        assert_eq!(got2.ranges().len(), 2);
    }

    #[test]
    fn subtract_bitmap_removes_hosts() {
        let t = Targets::build(&["10.0.0.0/24".into()], &[]).unwrap();
        let mut skip = roaring::RoaringBitmap::new();
        skip.insert(r("10.0.0.0").start);
        skip.insert(r("10.0.0.255").start);
        skip.insert(r("10.0.0.7").start);
        let got = t.subtract_bitmap(&skip);
        assert_eq!(got.total(), 256 - 3);
        assert_eq!(got.ranges().len(), 2);
        assert_eq!(
            got.ranges(),
            &[
                IpRange {
                    start: r("10.0.0.1").start,
                    end: r("10.0.0.6").start
                },
                IpRange {
                    start: r("10.0.0.8").start,
                    end: r("10.0.0.254").start
                }
            ]
        );
        // everything skipped → empty; nothing skipped → identity
        let full = t.subtract_bitmap(&{
            let mut bm = roaring::RoaringBitmap::new();
            bm.insert_range(r("10.0.0.0").start..=r("10.0.0.255").start);
            bm
        });
        assert!(full.is_empty());
        assert_eq!(
            t.subtract_bitmap(&roaring::RoaringBitmap::new()).total(),
            256
        );
    }
}
