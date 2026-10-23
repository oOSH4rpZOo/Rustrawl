//! A hand-rolled DNS client — just enough of the wire format for the
//! `names` collector: PTR lookups (each name verified by a forward A at the
//! same resolver), A lookups for LDAP host names, and one-shot AXFR attempts
//! over TCP. No DNS crate: the build is musl-static and the only allowed C
//! is the bundled sqlite (project rule), so this rides std's `UdpSocket` and
//! `TcpStream`.
//!
//! Scope cuts, each deliberate: no EDNS, no DNSSEC, no TCP retry for a
//! truncated UDP reply (TC=1 is reported and the next resolver tried — a
//! resolver that truncates a PTR answer is rare), no CNAME chain following
//! (the first PTR record in the answer section wins), A records only in
//! AXFR streams (the collector maps names to known assets; nothing else in
//! the zone feeds the registry).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};

const TYPE_A: u16 = 1;
const TYPE_SOA: u16 = 6;
const TYPE_PTR: u16 = 12;
const TYPE_AXFR: u16 = 252;

/// `ip` or `ip:port` (default 53) — one `--dns` entry. IPv6 literals need
/// the bracket form only when a port follows; the registry's resolvers are
/// IPv4, this is a courtesy.
pub(crate) fn parse_resolver(spec: &str) -> Result<SocketAddr> {
    match spec.rsplit_once(':') {
        Some((ip, port)) => {
            let port: u16 = port
                .parse()
                .with_context(|| format!("resolver port in {spec:?}"))?;
            let ip: IpAddr = ip
                .parse()
                .with_context(|| format!("resolver address in {spec:?}"))?;
            Ok(SocketAddr::new(ip, port))
        }
        None => {
            let ip: IpAddr = spec.parse().with_context(|| format!("resolver {spec:?}"))?;
            Ok(SocketAddr::new(ip, 53))
        }
    }
}

/// `4.3.2.1.in-addr.arpa` for 1.2.3.4.
fn reverse_name(ip: Ipv4Addr) -> String {
    let o = ip.octets();
    format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
}

/// One wire-format question: header (recursion desired), QNAME labels,
/// QTYPE, IN class. `txid` is a parameter so tests can pin exact bytes;
/// production passes a fresh `rand::random::<u16>()`. The name is validated
/// here as the last resort — callers sanitize first.
pub(crate) fn encode_query(txid: u16, qtype: u16, name: &str) -> Result<Vec<u8>> {
    if name.is_empty() || name.ends_with('.') {
        bail!("bad query name {name:?}");
    }
    let mut labels: Vec<&str> = Vec::new();
    let mut wire_len = 0usize;
    for label in name.split('.') {
        let b = label.as_bytes();
        if b.is_empty() || b.len() > 63 || !b.iter().all(u8::is_ascii_graphic) {
            bail!("bad label {label:?} in query name {name:?}");
        }
        wire_len += b.len() + 1;
        labels.push(label);
    }
    if wire_len + 1 > 255 {
        bail!("query name {name:?} exceeds 255 bytes on the wire");
    }
    let mut out = Vec::with_capacity(12 + wire_len + 1 + 4);
    out.extend_from_slice(&txid.to_be_bytes());
    out.extend_from_slice(&[0x01, 0x00]); // flags: RD=1, opcode 0
    out.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]); // QDCOUNT 1, rest 0
    for label in labels {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0); // root
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&[0, 1]); // IN
    Ok(out)
}

/// Decodes a (possibly compressed) domain name at `pos`. Compression
/// pointers must point strictly backwards — a forward pointer is either a
/// loop or an attacker walking us off the packet, and both are rejections,
/// never panics. Returns the name and the offset just past the name in the
/// original stream (past the pointer itself when one was followed).
fn decode_name(msg: &[u8], pos: usize) -> Result<(String, usize)> {
    let mut labels: Vec<&str> = Vec::new();
    let mut total = 0usize;
    let mut jumps = 0usize;
    let mut cur = pos;
    let mut end: Option<usize> = None;
    loop {
        let len = *msg
            .get(cur)
            .ok_or_else(|| anyhow!("name runs off the packet"))?;
        match len {
            0 => {
                if end.is_none() {
                    end = Some(cur + 1);
                }
                break;
            }
            0xC0..=0xFF => {
                let hi = (len & 0x3F) as usize;
                let lo = *msg
                    .get(cur + 1)
                    .ok_or_else(|| anyhow!("truncated compression pointer"))?;
                if end.is_none() {
                    end = Some(cur + 2);
                }
                let target = (hi << 8) | lo as usize;
                if target >= cur {
                    bail!("compression pointer does not point backwards");
                }
                jumps += 1;
                if jumps > 128 {
                    bail!("too many compression jumps");
                }
                cur = target;
            }
            _ => {
                if len > 63 {
                    bail!("label length {len} exceeds 63");
                }
                let start = cur + 1;
                let stop = start + len as usize;
                let raw = msg
                    .get(start..stop)
                    .ok_or_else(|| anyhow!("label runs off the packet"))?;
                total += len as usize + 1;
                if total > 255 {
                    bail!("decoded name exceeds 255 bytes");
                }
                let s = std::str::from_utf8(raw).map_err(|_| anyhow!("label is not UTF-8"))?;
                labels.push(s);
                cur = stop;
            }
        }
    }
    let end = end.ok_or_else(|| anyhow!("unterminated name"))?;
    Ok((labels.join("."), end))
}

/// The parts of a reply the collector reads. `soa`/`rr` only matter to the
/// AXFR loop (end marker and the runaway-stream cap); PTR collectors read
/// `ptrs`, A collectors read `addrs` (owner name paired with each address —
/// an AXFR stream is exactly that mapping).
#[derive(Debug)]
pub(crate) struct Reply {
    pub(crate) rcode: u8,
    pub(crate) truncated: bool,
    pub(crate) ptrs: Vec<String>,
    pub(crate) addrs: Vec<(String, Ipv4Addr)>,
    pub(crate) soa: usize,
    pub(crate) rr: usize,
}

/// Decodes the header, skips the question section and walks the answer
/// section collecting PTR names / A addresses. Authority and additional
/// sections are ignored: a PTR answer's records live in ANCOUNT, and glue
/// in ARCOUNT is not this collector's data.
fn decode_reply(msg: &[u8], qtype: u16) -> Result<Reply> {
    if msg.len() < 12 {
        bail!("reply shorter than a DNS header");
    }
    let flags = u16::from_be_bytes([msg[2], msg[3]]);
    if flags & 0x8000 == 0 {
        bail!("not a response (QR clear)");
    }
    if flags & 0x7800 != 0 {
        bail!("not a standard query (opcode {})", (flags >> 11) & 0xF);
    }
    let mut out = Reply {
        rcode: (flags & 0x000F) as u8,
        truncated: flags & 0x0200 != 0,
        ptrs: Vec::new(),
        addrs: Vec::new(),
        soa: 0,
        rr: 0,
    };

    let mut pos = 12usize;
    let qd = u16::from_be_bytes([msg[4], msg[5]]);
    for _ in 0..qd {
        let (_name, next) = decode_name(msg, pos)?;
        pos = next + 4; // QTYPE + QCLASS
        if pos > msg.len() {
            bail!("question section runs off the packet");
        }
    }

    let an = u16::from_be_bytes([msg[6], msg[7]]);
    for _ in 0..an {
        let (owner, next) = decode_name(msg, pos)?;
        pos = next;
        let hdr = msg
            .get(pos..pos + 10)
            .ok_or_else(|| anyhow!("record header runs off the packet"))?;
        let rtype = u16::from_be_bytes([hdr[0], hdr[1]]);
        let rdlen = u16::from_be_bytes([hdr[8], hdr[9]]) as usize;
        pos += 10;
        let rdata = msg
            .get(pos..pos + rdlen)
            .ok_or_else(|| anyhow!("rdata runs off the packet"))?;
        out.rr += 1;
        match (rtype, qtype) {
            (t, q) if t == q && q == TYPE_PTR => {
                // rdata is itself a name, possibly compressed against the
                // message (the pointer target sits before this record).
                let (name, _) = decode_name(msg, pos)?;
                out.ptrs.push(name);
            }
            (t, q) if t == q && q == TYPE_A => {
                if rdata.len() != 4 {
                    bail!("A rdata is {} bytes, not 4", rdata.len());
                }
                let addr = Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]);
                out.addrs.push((owner, addr));
            }
            (t, _) if t == TYPE_SOA => out.soa += 1,
            _ => {}
        }
        pos += rdlen;
    }
    Ok(out)
}

/// True for the rcodes meaning "this resolver will not answer" — SERVFAIL,
/// format-error, not-implemented, refused: another resolver might. NXDOMAIN
/// (3) and NOERROR are definitive at this resolver.
fn rcode_is_retryable(rcode: u8) -> bool {
    matches!(rcode, 1 | 2 | 4 | 5)
}

/// Sends one query over UDP and collects the first reply carrying the
/// queried transaction id — a late stray datagram from an earlier lookup
/// must not end the exchange (three reads, then give up).
fn udp_exchange(
    resolver: SocketAddr,
    query: &[u8],
    txid: u16,
    timeout: Duration,
) -> Result<Vec<u8>> {
    let bind = if resolver.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let sock = std::net::UdpSocket::bind(bind)?;
    sock.connect(resolver)?;
    sock.set_read_timeout(Some(timeout))?;
    sock.set_write_timeout(Some(timeout))?;
    sock.send(query)?;
    let mut buf = vec![0u8; 16 * 1024];
    let want = txid.to_be_bytes();
    for _ in 0..3 {
        let n = sock.recv(&mut buf)?;
        if n >= 2 && buf[0] == want[0] && buf[1] == want[1] {
            buf.truncate(n);
            return Ok(buf);
        }
    }
    bail!("no reply with the queried transaction id");
}

/// What one resolver said about one IP's PTR records.
pub(crate) enum PtrOutcome {
    /// A definitive answer at this resolver. `verified` names also resolve
    /// forward — to this very IP — at the same resolver (only those are
    /// stored); `dropped` names had a PTR record the forward A did not
    /// confirm (stale, or pointing elsewhere): logged, never stored.
    Answer {
        verified: Vec<String>,
        dropped: Vec<String>,
    },
    /// TC=1: the answer does not fit in UDP. Skipped here, the next
    /// resolver gets its chance.
    Truncated,
    /// Transport trouble or a retryable rcode — the next resolver may know.
    Unreachable(String),
}

/// The PTR lookup plus its verification, in one call: every name that comes
/// back is re-asked as an A query **at the same resolver**, and kept only
/// when the answer contains the IP we started from. A hostile resolver can
/// still lie consistently — a resolver cannot make a stale PTR pass.
pub(crate) fn query_ptr(resolver: SocketAddr, ip: Ipv4Addr, timeout: Duration) -> PtrOutcome {
    let name = reverse_name(ip);
    let txid: u16 = rand::random();
    let raw = match encode_query(txid, TYPE_PTR, &name)
        .and_then(|q| udp_exchange(resolver, &q, txid, timeout))
        .and_then(|raw| decode_reply(&raw, TYPE_PTR))
    {
        Ok(r) => r,
        Err(e) => return PtrOutcome::Unreachable(format!("{e:#}")),
    };
    if raw.truncated {
        return PtrOutcome::Truncated;
    }
    if raw.rcode != 0 {
        return if rcode_is_retryable(raw.rcode) {
            PtrOutcome::Unreachable(format!("rcode {}", raw.rcode))
        } else {
            PtrOutcome::Answer {
                verified: Vec::new(),
                dropped: Vec::new(),
            }
        };
    }
    let mut verified = Vec::new();
    let mut dropped = Vec::new();
    for ptr in raw.ptrs {
        let clean = super::sanitize_name(&ptr);
        if clean.is_empty() {
            continue;
        }
        match query_a(resolver, &clean, timeout) {
            Ok(addrs) if addrs.contains(&ip) => verified.push(clean),
            _ => dropped.push(clean),
        }
    }
    PtrOutcome::Answer { verified, dropped }
}

/// The A records for `name` at one resolver. `Ok(vec![])` is a definitive
/// negative (NXDOMAIN or no A records); `Err` is transport trouble or a
/// retryable rcode — the caller logs and moves on.
pub(crate) fn query_a(
    resolver: SocketAddr,
    name: &str,
    timeout: Duration,
) -> Result<Vec<Ipv4Addr>> {
    let txid: u16 = rand::random();
    let query = encode_query(txid, TYPE_A, name)?;
    let raw = udp_exchange(resolver, &query, txid, timeout)?;
    let reply = decode_reply(&raw, TYPE_A)?;
    if reply.truncated {
        // An A answer that truncates is pathological; shipping half the
        // records would be worse than reporting none.
        return Ok(Vec::new());
    }
    if reply.rcode != 0 && rcode_is_retryable(reply.rcode) {
        return Err(anyhow!("rcode {}", reply.rcode));
    }
    Ok(reply.addrs.into_iter().map(|(_, a)| a).collect())
}

/// The end of one AXFR attempt. Each (resolver, zone) pair gets exactly one
/// attempt — a refused transfer is a policy answer, not a flaky link.
#[derive(Debug)]
pub(crate) enum AxfrOutcome {
    /// The zone came through: (name, address) pairs, A records only.
    Records(Vec<(String, Ipv4Addr)>),
    /// The server answered but said no — the rcode for the log.
    Refused(u8),
    /// Transport trouble or a malformed stream; reason for the log.
    Failed(String),
}

enum AxfrError {
    Rcode(u8),
    Other(String),
}

impl From<anyhow::Error> for AxfrError {
    fn from(e: anyhow::Error) -> Self {
        AxfrError::Other(format!("{e:#}"))
    }
}

impl From<std::io::Error> for AxfrError {
    fn from(e: std::io::Error) -> Self {
        AxfrError::Other(format!("tcp: {e}"))
    }
}

/// Pulls the zone over TCP: one length-prefixed DNS message after another
/// until the second SOA or the end of the stream. Two runaway caps — 4 MiB
/// of wire bytes, 100k resource records — bound a malicious or miscon-
/// figured server; hitting one aborts the attempt (logged, never fatal).
pub(crate) fn try_axfr(resolver: SocketAddr, zone: &str, timeout: Duration) -> AxfrOutcome {
    const MAX_STREAM: usize = 4 * 1024 * 1024;
    const MAX_RRS: usize = 100_000;
    match axfr_inner(resolver, zone, timeout, MAX_STREAM, MAX_RRS) {
        Ok(records) => AxfrOutcome::Records(records),
        Err(AxfrError::Rcode(rc)) => AxfrOutcome::Refused(rc),
        Err(AxfrError::Other(m)) => AxfrOutcome::Failed(m),
    }
}

fn axfr_inner(
    resolver: SocketAddr,
    zone: &str,
    timeout: Duration,
    max_stream: usize,
    max_rrs: usize,
) -> Result<Vec<(String, Ipv4Addr)>, AxfrError> {
    use std::io::{Read, Write};

    let txid: u16 = rand::random();
    let query = encode_query(txid, TYPE_AXFR, zone)?;
    let mut sock = std::net::TcpStream::connect_timeout(&resolver, timeout)?;
    sock.set_read_timeout(Some(timeout))?;
    sock.set_write_timeout(Some(timeout))?;
    let mut framed = Vec::with_capacity(2 + query.len());
    framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
    framed.extend_from_slice(&query);
    sock.write_all(&framed)?;

    let mut wire_total = 0usize;
    let mut rr_seen = 0usize;
    let mut soa_seen = 0usize;
    let mut records: Vec<(String, Ipv4Addr)> = Vec::new();
    let mut first = true;
    loop {
        // Frame length; a clean EOF before the first byte is the normal end
        // of a transfer, anything mid-frame is a broken stream.
        let mut lb = [0u8; 2];
        match sock.read_exact(&mut lb) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }
        let len = u16::from_be_bytes(lb) as usize;
        if len == 0 {
            return Err(AxfrError::Other("zero-length message".to_string()));
        }
        wire_total += len + 2;
        if wire_total > max_stream {
            return Err(AxfrError::Other(format!(
                "stream exceeds the {max_stream}-byte cap"
            )));
        }
        let mut msg = vec![0u8; len];
        sock.read_exact(&mut msg)?;
        let reply = decode_reply(&msg, TYPE_A)?;
        if first {
            first = false;
            if reply.rcode != 0 {
                return Err(AxfrError::Rcode(reply.rcode));
            }
            if reply.soa == 0 {
                return Err(AxfrError::Other(
                    "first message carries no SOA - not a transfer".to_string(),
                ));
            }
        }
        rr_seen += reply.rr;
        if rr_seen > max_rrs {
            return Err(AxfrError::Other(format!(
                "stream exceeds the {max_rrs}-record cap"
            )));
        }
        soa_seen += reply.soa;
        for (name, addr) in reply.addrs {
            let clean = super::sanitize_name(&name);
            if !clean.is_empty() {
                records.push((clean, addr));
            }
        }
        if soa_seen >= 2 {
            break;
        }
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_bytes_pin_the_wire_shape() {
        let q = encode_query(0x1234, TYPE_PTR, "4.3.2.1.in-addr.arpa").unwrap();
        let mut want = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in ["4", "3", "2", "1", "in-addr", "arpa"] {
            want.push(label.len() as u8);
            want.extend_from_slice(label.as_bytes());
        }
        want.push(0);
        want.extend_from_slice(&12u16.to_be_bytes());
        want.extend_from_slice(&[0, 1]);
        assert_eq!(q, want);
    }

    #[test]
    fn encode_query_rejects_bad_names() {
        for bad in [
            "",
            ".corp.example.com",
            "corp.example.com.",
            "a..b",
            "with space",
            "under\u{7}score",
        ] {
            assert!(encode_query(1, TYPE_A, bad).is_err(), "{bad:?} rejected");
        }
        let long = "a".repeat(64);
        assert!(
            encode_query(1, TYPE_A, &long).is_err(),
            "label > 63 rejected"
        );
        let wide = [
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(63),
            "e".repeat(63),
        ]
        .join(".");
        assert!(
            encode_query(1, TYPE_A, &wide).is_err(),
            "name over 255 wire bytes rejected"
        );
        let fits = ["b".repeat(63), "c".repeat(63), "d".repeat(63)].join(".");
        assert!(encode_query(1, TYPE_A, &fits).is_ok(), "189 wire bytes fit");
    }

    /// A reply skeleton: header + question (reused via compression pointer)
    /// + one record appended by the caller.
    fn reply_with(record: &[u8]) -> Vec<u8> {
        let mut m = vec![0x33, 0x22, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        m.extend(encode_query(0, TYPE_PTR, "4.3.2.1.in-addr.arpa").unwrap()[12..].iter());
        // answer owner name = compression pointer at the question name
        m.extend_from_slice(&[0xC0, 0x0C]);
        m.extend_from_slice(record);
        m
    }

    #[test]
    fn ptr_reply_with_compression_decodes() {
        // type PTR, class IN, ttl 3600, rdlen, rdata = "host.example.com"
        let rdata = [
            4, b'h', b'o', b's', b't', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o',
            b'm', 0,
        ];
        let mut rec = 12u16.to_be_bytes().to_vec();
        rec.extend_from_slice(&1u16.to_be_bytes());
        rec.extend_from_slice(&3600u32.to_be_bytes());
        rec.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        rec.extend_from_slice(&rdata);
        let msg = reply_with(&rec);
        let reply = decode_reply(&msg, TYPE_PTR).unwrap();
        assert_eq!(reply.rcode, 0);
        assert!(!reply.truncated);
        assert_eq!(reply.ptrs, vec!["host.example.com"]);
        assert_eq!(reply.rr, 1);
    }

    #[test]
    fn a_reply_requires_four_byte_rdata() {
        let mut rec = 1u16.to_be_bytes().to_vec(); // type A
        rec.extend_from_slice(&1u16.to_be_bytes()); // class IN
        rec.extend_from_slice(&60u32.to_be_bytes()); // ttl
        rec.extend_from_slice(&4u16.to_be_bytes()); // rdlen
        rec.extend_from_slice(&[10, 1, 2, 3]);
        let msg = reply_with(&rec);
        let reply = decode_reply(&msg, TYPE_A).unwrap();
        assert_eq!(
            reply.addrs,
            vec![(
                "4.3.2.1.in-addr.arpa".to_string(),
                Ipv4Addr::new(10, 1, 2, 3)
            )]
        );

        let mut short = 1u16.to_be_bytes().to_vec();
        short.extend_from_slice(&1u16.to_be_bytes());
        short.extend_from_slice(&60u32.to_be_bytes());
        short.extend_from_slice(&3u16.to_be_bytes()); // rdlen 3
        short.extend_from_slice(&[10, 1, 2]); // 3 bytes
        let msg = reply_with(&short);
        assert!(
            decode_reply(&msg, TYPE_A).is_err(),
            "short A rdata rejected"
        );
    }

    #[test]
    fn truncated_and_nxdomain_flags_read() {
        let mut m = vec![0x33, 0x22, 0x81, 0x83, 0, 1, 0, 0, 0, 0, 0, 0]; // rcode 3
        m.extend(encode_query(0, TYPE_PTR, "4.3.2.1.in-addr.arpa").unwrap()[12..].iter());
        let reply = decode_reply(&m, TYPE_PTR).unwrap();
        assert_eq!(reply.rcode, 3);
        assert!(reply.ptrs.is_empty());

        let mut t = vec![0x33, 0x22, 0x83, 0x80, 0, 0, 0, 0, 0, 0, 0, 0]; // TC set
        assert!(decode_reply(&t, TYPE_PTR).unwrap().truncated);
        t[2] = 0x81; // TC clear
        assert!(!decode_reply(&t, TYPE_PTR).unwrap().truncated);
    }

    #[test]
    fn hostile_pointers_and_short_frames_reject() {
        // A self-pointing name (0xC0 0x0C at offset 12) never terminates.
        let m = vec![0x33, 0x22, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0, 0xC0, 0x0C];
        assert!(decode_reply(&m, TYPE_PTR).is_err(), "pointer loop rejected");

        // A forward pointer (target after the pointer itself) too.
        let mut f = vec![0x33, 0x22, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0, 0xC0, 0x20];
        f.extend(encode_query(0, TYPE_PTR, "a.b").unwrap()[12..].iter());
        assert!(
            decode_reply(&f, TYPE_PTR).is_err(),
            "forward pointer rejected"
        );

        assert!(
            decode_reply(&[0x33, 0x22], TYPE_PTR).is_err(),
            "short frame"
        );
        // QR clear — a query, not a response.
        let q = encode_query(1, TYPE_PTR, "a.b").unwrap();
        assert!(decode_reply(&q, TYPE_PTR).is_err());
    }

    #[test]
    fn retryable_rcodes_are_typed() {
        for rc in [1u8, 2, 4, 5] {
            assert!(
                rcode_is_retryable(rc),
                "rcode {rc} retries the next resolver"
            );
        }
        for rc in [0u8, 3, 6] {
            assert!(!rcode_is_retryable(rc), "rcode {rc} is definitive");
        }
    }

    #[test]
    fn resolver_specs_parse() {
        assert_eq!(
            parse_resolver("10.0.0.1").unwrap(),
            "10.0.0.1:53".parse().unwrap()
        );
        assert_eq!(
            parse_resolver("10.0.0.1:5353").unwrap(),
            "10.0.0.1:5353".parse().unwrap()
        );
        assert!(parse_resolver("10.0.0.1:x").is_err());
        assert!(parse_resolver("10.0.0:53").is_err());
        assert!(parse_resolver("").is_err());
    }

    /// One AXFR message: SOA first when `soa`, then the given A records.
    fn axfr_msg(soa: bool, records: &[(&str, [u8; 4])]) -> Vec<u8> {
        // Owner names on the wire: labels + root only (a question's
        // type/class tail must not leak into a record's owner name).
        let wire = |name: &str| -> Vec<u8> {
            let mut w = Vec::new();
            for label in name.split('.') {
                w.push(label.len() as u8);
                w.extend_from_slice(label.as_bytes());
            }
            w.push(0);
            w
        };
        let n = records.len() + usize::from(soa);
        let mut m = vec![0x33, 0x22, 0x81, 0x80, 0, 0, 0, 0, 0, 0, 0, 0];
        m[6..8].copy_from_slice(&(n as u16).to_be_bytes());
        let mut rec = |rtype: u16, name: &str, rdata: &[u8]| {
            m.extend(wire(name));
            m.extend_from_slice(&rtype.to_be_bytes());
            m.extend_from_slice(&1u16.to_be_bytes()); // IN
            m.extend_from_slice(&0u32.to_be_bytes()); // ttl
            m.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            m.extend_from_slice(rdata);
        };
        if soa {
            // SOA rdata is never parsed by our decoder — minimal bytes.
            rec(TYPE_SOA, "corp.example.com", &[0u8; 10]);
        }
        for (name, addr) in records {
            rec(TYPE_A, name, addr);
        }
        m
    }

    fn frame(msg: &[u8]) -> Vec<u8> {
        let mut out = (msg.len() as u16).to_be_bytes().to_vec();
        out.extend_from_slice(msg);
        out
    }

    /// A one-shot TCP fake: reads the query frame, writes `stream`, closes.
    fn serve_axfr(stream: Vec<u8>) -> SocketAddr {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            sock.set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut lb = [0u8; 2];
            if std::io::Read::read_exact(&mut sock, &mut lb).is_err() {
                return;
            }
            let mut skip = vec![0u8; u16::from_be_bytes(lb) as usize];
            let _ = std::io::Read::read_exact(&mut sock, &mut skip);
            use std::io::Write;
            let _ = sock.write_all(&stream);
            // close: drop
        });
        addr
    }

    #[test]
    fn axfr_pulls_records_until_the_second_soa() {
        let mut stream = frame(&axfr_msg(
            true,
            &[
                ("a.corp.example.com", [10, 0, 0, 1]),
                ("b.corp.example.com", [10, 0, 0, 2]),
            ],
        ));
        stream.extend(frame(&axfr_msg(true, &[])));
        let addr = serve_axfr(stream);
        match try_axfr(addr, "corp.example.com", Duration::from_secs(5)) {
            AxfrOutcome::Records(records) => {
                assert_eq!(
                    records,
                    vec![
                        ("a.corp.example.com".to_string(), Ipv4Addr::new(10, 0, 0, 1)),
                        ("b.corp.example.com".to_string(), Ipv4Addr::new(10, 0, 0, 2)),
                    ]
                );
            }
            other => panic!("expected records, got {other:?}"),
        }
    }

    #[test]
    fn axfr_refusal_reads_the_first_rcode() {
        let mut m = vec![0x33, 0x22, 0x81, 0x85, 0, 0, 0, 0, 0, 0, 0, 0]; // REFUSED
        m.extend(encode_query(0, 0, "corp.example.com").unwrap()[12..].iter());
        let addr = serve_axfr(frame(&m));
        match try_axfr(addr, "corp.example.com", Duration::from_secs(5)) {
            AxfrOutcome::Refused(5) => {}
            other => panic!("expected Refused(5), got {other:?}"),
        }
    }

    #[test]
    fn axfr_without_an_soa_is_not_a_transfer() {
        // An answer section of A records only: some servers answer AXFR
        // queries with garbage — reject rather than harvest.
        let msg = axfr_msg(false, &[("a.example.com", [10, 0, 0, 9])]);
        let addr = serve_axfr(frame(&msg));
        match try_axfr(addr, "example.com", Duration::from_secs(5)) {
            AxfrOutcome::Failed(reason) => {
                assert!(reason.contains("no SOA"), "{reason}");
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }
}
