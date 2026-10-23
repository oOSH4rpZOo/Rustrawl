//! Small cross-cutting utilities (durations, formatting).

use std::time::Duration;

use anyhow::{bail, Context, Result};

/// Parses "7d", "12h", "30m", "45s" (positive integers, a single unit).
pub fn parse_duration(s: &str) -> Result<Duration> {
    let s = s.trim();
    let Some(idx) = s.char_indices().next_back().map(|(i, _)| i) else {
        bail!("empty duration");
    };
    let (digits, unit) = s.split_at(idx);
    if !digits.chars().all(|c| c.is_ascii_digit()) {
        bail!("invalid duration: {s} (expected a positive integer followed by s/m/h/d)");
    }
    let n: u64 = digits
        .parse()
        .with_context(|| format!("invalid duration: {s}"))?;
    let seconds = match unit {
        "s" => n,
        "m" => n
            .checked_mul(60)
            .with_context(|| format!("unreasonable duration: {s}"))?,
        "h" => n
            .checked_mul(3600)
            .with_context(|| format!("unreasonable duration: {s}"))?,
        "d" => n
            .checked_mul(86_400)
            .with_context(|| format!("unreasonable duration: {s}"))?,
        _ => bail!("unknown duration unit: {s} (expected s/m/h/d)"),
    };
    Ok(Duration::from_secs(seconds))
}

pub fn format_duration(d: Duration) -> String {
    let total = d.as_secs();
    let h = total / 3600;
    let m = (total % 3600) / 60;
    let s = total % 60;
    if h > 0 {
        format!("{h}h {m:02}m {s:02}s")
    } else if m > 0 {
        format!("{m}m {s:02}s")
    } else {
        format!("{s}s")
    }
}

/// 1625575 → "1,625,575" (comma thousands separator).
pub fn fmt_count(n: u64) -> String {
    let raw = n.to_string();
    let mut out = String::with_capacity(raw.len() + raw.len() / 3);
    let digits = raw.len();
    for (i, c) in raw.chars().enumerate() {
        if i > 0 && (digits - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// Unix seconds → "YYYY-MM-DD HH:MM:SS UTC" (Howard Hinnant's civil_from_days
/// — no time crate needed). Display only, UTC.
pub fn fmt_ts(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146_096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let mth = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let y = if mth <= 2 { y + 1 } else { y };
    format!("{y:04}-{mth:02}-{d:02} {h:02}:{m:02}:{s:02} UTC")
}

/// Best-effort RLIMIT_NOFILE raise to ≥20k soft (bounded by the hard limit).
/// Both engines fan out thousands of sockets/fds; a low soft limit (often
/// 1024) would surface as spurious "too many open files" mid-scan. Errors
/// are ignored on purpose: whatever the platform grants is enough.
pub fn raise_nofile() {
    // SAFETY: getrlimit/setrlimit with owned structs.
    unsafe {
        let mut rl = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) != 0 {
            return;
        }
        if rl.rlim_cur < 20_000 {
            rl.rlim_cur = if rl.rlim_max == libc::RLIM_INFINITY {
                20_000
            } else {
                rl.rlim_max.min(20_000)
            };
            libc::setrlimit(libc::RLIMIT_NOFILE, &rl);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(parse_duration("7d").unwrap(), Duration::from_secs(604_800));
        assert_eq!(parse_duration("12h").unwrap(), Duration::from_secs(43_200));
        assert_eq!(parse_duration("90s").unwrap(), Duration::from_secs(90));
        assert!(parse_duration("7x").is_err());
        assert!(parse_duration("").is_err());
        assert!(parse_duration("+7d").is_err());
        assert!(parse_duration("-7d").is_err());
        assert!(parse_duration("7 d").is_err());
        assert!(parse_duration("9999999999999999d").is_err()); // overflow → error, no panic
    }

    #[test]
    fn numbers() {
        assert_eq!(fmt_count(0), "0");
        assert_eq!(fmt_count(999), "999");
        assert_eq!(fmt_count(1_000), "1,000");
        assert_eq!(fmt_count(1_631_975), "1,631,975");
    }

    #[test]
    fn timestamps() {
        assert_eq!(fmt_ts(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(fmt_ts(1_000_000_000), "2001-09-09 01:46:40 UTC");
        assert_eq!(fmt_ts(1_767_225_600), "2026-01-01 00:00:00 UTC");
        // leap-year day: 2024-02-29 is 1709164800
        assert_eq!(fmt_ts(1_709_164_800), "2024-02-29 00:00:00 UTC");
        // pre-epoch (a corrupt clock) must not panic
        assert_eq!(fmt_ts(-1), "1969-12-31 23:59:59 UTC");
    }
}
