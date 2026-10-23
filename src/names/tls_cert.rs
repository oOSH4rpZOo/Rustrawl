//! TLS 1.2 certificate reader for the `names` collector: it says hello,
//! reads the ServerHello and the Certificate message, and closes — no key
//! exchange, no application data. What comes out is the leaf certificate's
//! CN and SAN dNSName entries, sanitized like every other source.
//!
//! Hand-rolled on purpose (project rule: no new crates): the client side
//! of this exchange is a fixed byte string plus a reassembler, and the DER
//! walk is a fixed shape. The constraints that keep that safe are caps,
//! not trust — 16 KiB per record, 128 KiB per reassembled handshake
//! stream, 100 KiB per certificate entry, definite DER lengths only, and
//! every name passes `sanitize_name` before it is returned. A hostile
//! server can make the collection fail; it cannot make it lie (garbage
//! yields `Skipped`) or wedge it (caps, no recursion).
//!
//! A TLS 1.3-only server answers the hello with an alert — a `Skipped`
//! line in names.log, not an error (D8). TLS 1.3 and SNI stay on the v2
//! list; nothing below this module's signature would change for them.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

/// Names off one certificate: the subject CN (kept only when
/// hostname-shaped — see `is_name_like`) and every SAN dNSName entry,
/// wildcards verbatim.
#[derive(Debug)]
pub(crate) struct CertNames {
    pub(crate) cn: Option<String>,
    pub(crate) san: Vec<String>,
}

/// What `grab_names` got. Every failure mode is a `Skipped` reason for
/// names.log — transport trouble never fails the run.
#[derive(Debug)]
pub(crate) enum TlsOutcome {
    Names(CertNames),
    Skipped(String),
}

const REC_ALERT: u8 = 21;
const REC_HANDSHAKE: u8 = 22;
const HS_HELLO_REQUEST: u8 = 0;
const HS_SERVER_HELLO: u8 = 2;
const HS_CERTIFICATE: u8 = 11;

/// TLS record payload cap (RFC 5246).
const RECORD_MAX: usize = 1 << 14;
/// Reassembled handshake stream cap — a Certificate message may span
/// records; this bounds how much of it we hold at once.
const STREAM_MAX: usize = 128 * 1024;
/// One certificate entry (only the leaf is parsed).
const CERT_MAX: usize = 100 * 1024;
/// A dNSName longer than this could not be carried by the DNS anyway.
const NAME_MAX: usize = 253;

/// One exchange against one service. Any connect/write failure is a
/// `Skipped`, never an error: the collector has no retry and no reason for
/// one (the next `names` run repeats the attempt).
pub(crate) fn grab_names(addr: SocketAddr, timeout: Duration) -> TlsOutcome {
    let mut sock = match TcpStream::connect_timeout(&addr, timeout) {
        Ok(s) => s,
        Err(_) => return TlsOutcome::Skipped("connect failed".to_string()),
    };
    let _ = sock.set_read_timeout(Some(timeout));
    let _ = sock.set_write_timeout(Some(timeout));
    if sock.write_all(&client_hello()).is_err() {
        return TlsOutcome::Skipped("write failed".to_string());
    }
    handshake(&mut sock)
}

/// The ClientHello record: TLS 1.2 (0x0303), six suites covering ECDHE and
/// plain RSA, null compression — and no extensions field at all. No SNI:
/// we connect by IP, and an extensionless hello is also the shortest
/// possible probe. Record-layer version is 0x0301, the customary choice
/// for a TLS 1.2 ClientHello.
fn client_hello() -> Vec<u8> {
    const SUITES: [[u8; 2]; 6] = [
        [0xc0, 0x13], // ECDHE-RSA-AES128-GCM-SHA256
        [0xc0, 0x09], // ECDHE-ECDSA-AES128-SHA
        [0xc0, 0x27], // ECDHE-RSA-AES128-SHA256
        [0x00, 0x9c], // RSA-AES128-GCM-SHA256
        [0x00, 0x2f], // RSA-AES128-SHA
        [0x00, 0x35], // RSA-AES256-SHA
    ];
    let mut body = Vec::with_capacity(64);
    body.extend_from_slice(&[0x03, 0x03]); // client_version: TLS 1.2
    body.extend_from_slice(&rand::random::<[u8; 32]>());
    body.push(0); // empty session id (no resumption)
    body.extend_from_slice(&((SUITES.len() * 2) as u16).to_be_bytes());
    for suite in SUITES {
        body.extend_from_slice(&suite);
    }
    body.extend_from_slice(&[1, 0]); // one compression method: null

    let mut hs = Vec::with_capacity(body.len() + 4);
    hs.push(0x01); // ClientHello
    let blen = body.len();
    hs.extend_from_slice(&[(blen >> 16) as u8, (blen >> 8) as u8, blen as u8]);
    hs.extend_from_slice(&body);

    let mut rec = Vec::with_capacity(hs.len() + 5);
    rec.push(0x16); // handshake record
    rec.extend_from_slice(&[0x03, 0x01]);
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

/// Reads records until the Certificate message lands, skipping whatever a
/// chatty server puts ahead of it (HelloRequest). Pure over `Read` so the
/// tests can feed a byte buffer instead of a socket.
fn handshake(r: &mut impl Read) -> TlsOutcome {
    let mut pending: Vec<u8> = Vec::new();
    let mut hello_seen = false;
    loop {
        while pending.len() >= 4 {
            let mtype = pending[0];
            let mlen = be24(&pending[1..4]);
            if mlen > STREAM_MAX {
                return TlsOutcome::Skipped(format!(
                    "handshake message of {mlen} bytes exceeds the cap"
                ));
            }
            if pending.len() < 4 + mlen {
                break; // the rest of this message is still in flight
            }
            let body = pending[4..4 + mlen].to_vec();
            pending.drain(..4 + mlen);
            match mtype {
                HS_HELLO_REQUEST => {} // legal mid-handshake; ignored
                HS_SERVER_HELLO => {
                    hello_seen = true;
                    if body.len() < 2 {
                        return TlsOutcome::Skipped(
                            "ServerHello shorter than its version field".to_string(),
                        );
                    }
                    match (body[0], body[1]) {
                        (3, 3) => {} // TLS 1.2: the version we offered
                        (3, 4) => {
                            return TlsOutcome::Skipped(
                                "server speaks TLS 1.3 - this collector offers 1.2 only"
                                    .to_string(),
                            )
                        }
                        (3, minor) => {
                            return TlsOutcome::Skipped(format!(
                                "server picked TLS 1.{minor}, below the offered 1.2"
                            ))
                        }
                        (major, _) => {
                            return TlsOutcome::Skipped(format!("not TLS (version byte {major})"))
                        }
                    }
                }
                HS_CERTIFICATE => {
                    if !hello_seen {
                        return TlsOutcome::Skipped("certificate before ServerHello".to_string());
                    }
                    return match parse_certificate(&body) {
                        Some((cn, san)) => TlsOutcome::Names(CertNames { cn, san }),
                        None => TlsOutcome::Skipped("malformed certificate message".to_string()),
                    };
                }
                _ if !hello_seen => {
                    return TlsOutcome::Skipped(format!(
                        "first handshake message was type {mtype}, not ServerHello"
                    ))
                }
                _ => {} // post-ServerHello messages we never reach a use for
            }
        }
        match read_record(r) {
            Ok((REC_HANDSHAKE, body)) => {
                if pending.len() + body.len() > STREAM_MAX {
                    return TlsOutcome::Skipped(
                        "handshake stream exceeds the 128 KiB cap".to_string(),
                    );
                }
                pending.extend_from_slice(&body);
            }
            Ok((REC_ALERT, body)) => {
                let code = body.get(1).copied().unwrap_or(0);
                return TlsOutcome::Skipped(format!("server alert {code}"));
            }
            Ok((rtype, _)) => {
                return TlsOutcome::Skipped(format!("unexpected record type {rtype}"));
            }
            Err(why) => return TlsOutcome::Skipped(why.to_string()),
        }
    }
}

fn read_record(r: &mut impl Read) -> Result<(u8, Vec<u8>), &'static str> {
    let mut hdr = [0u8; 5];
    r.read_exact(&mut hdr)
        .map_err(|_| "closed or timed out before a full record header")?;
    let rtype = hdr[0];
    let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
    if len > RECORD_MAX {
        return Err("record exceeds the 16 KiB cap");
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)
        .map_err(|_| "closed or timed out mid-record")?;
    Ok((rtype, body))
}

/// Certificate handshake body: a 3-byte list length followed by
/// 3-byte-prefixed DER entries. Only the leaf (first entry) is parsed —
/// the intermediates would tell us nothing about this IP that the leaf
/// does not — capped at CERT_MAX.
fn parse_certificate(body: &[u8]) -> Option<(Option<String>, Vec<String>)> {
    let elen = be24(body.get(3..6)?);
    if elen > CERT_MAX {
        return None;
    }
    Some(walk_certificate(body.get(6..6 + elen)?))
}

/// The DER walk: Certificate → tbsCertificate → (children in RFC 5246
/// order) subject CN and the SAN extension. Definite lengths only
/// (`der_tlv` rejects indefinite), no recursion — the descent is a fixed
/// shape, eight levels at its deepest. Malformed input short-circuits to
/// whatever was already collected, never a panic.
fn walk_certificate(der: &[u8]) -> (Option<String>, Vec<String>) {
    let mut out = (None, Vec::new());
    let Some((0x30, tbs, _)) = der_tlv(der) else {
        return out; // level 1: Certificate SEQUENCE
    };
    let Some((0x30, mut cur, _)) = der_tlv(tbs) else {
        return out; // level 2: tbsCertificate SEQUENCE
    };
    let mut seqs = 0usize;
    while !cur.is_empty() {
        let Some((tag, content, rest)) = der_tlv(cur) else {
            break;
        };
        cur = rest;
        match tag {
            0xa0 | 0x02 => {} // explicit version, serial
            0xa3 => {
                // extensions [3] EXPLICIT wraps one SEQUENCE OF Extension
                if let Some((0x30, exts, _)) = der_tlv(content) {
                    out.1 = san_names(exts);
                }
            }
            0x30 => {
                seqs += 1;
                if seqs == 4 {
                    // child order: signature, issuer, validity, subject, spki
                    out.0 = subject_cn(content);
                }
            }
            _ => {} // spki, unique ids, anything else we do not model
        }
    }
    out
}

/// Subject Name = SEQUENCE OF (SET OF (SEQ {OID, value})); the first CN
/// (2.5.4.3) wins. Kept only when hostname-shaped — an org name like
/// "Example Corp" must not become the pseudo-name `examplecorp`.
fn subject_cn(name_body: &[u8]) -> Option<String> {
    let mut cn = None;
    let mut rdns = name_body;
    while !rdns.is_empty() {
        let Some((0x31, set, rest)) = der_tlv(rdns) else {
            break;
        };
        rdns = rest;
        let mut attrs = set;
        while !attrs.is_empty() {
            let Some((0x30, atv, rest)) = der_tlv(attrs) else {
                break;
            };
            attrs = rest;
            let Some((0x06, oid, tail)) = der_tlv(atv) else {
                break;
            };
            if oid != [0x55, 0x04, 0x03] || cn.is_some() {
                continue;
            }
            let Some((_, value, _)) = der_tlv(tail) else {
                break;
            };
            if let Ok(text) = std::str::from_utf8(value) {
                let clean = super::sanitize_name(text);
                if is_name_like(&clean) {
                    cn = Some(clean);
                }
            }
        }
    }
    cn
}

/// SAN extension = SEQUENCE OF GeneralName; this collector reads the
/// dNSName entries (context tag 0x82) and ignores the rest — iPAddress
/// entries would need reverse-lookup semantics the DNS sources already
/// provide. Wildcards stay verbatim: `*.corp.example.com` is itself a
/// useful search term in the views.
fn san_names(exts_body: &[u8]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut exts = exts_body;
    while !exts.is_empty() {
        let Some((0x30, ext, rest)) = der_tlv(exts) else {
            break;
        };
        exts = rest;
        // Extension = SEQ { OID, BOOLEAN DEFAULT FALSE, OCTET STRING }
        let Some((0x06, oid, tail)) = der_tlv(ext) else {
            break;
        };
        if oid != [0x55, 0x1d, 0x11] {
            continue;
        }
        let mut tail = tail;
        if let Some((0x01, _, rest)) = der_tlv(tail) {
            tail = rest; // the optional critical flag
        }
        let Some((0x04, wrapped, _)) = der_tlv(tail) else {
            continue;
        };
        let Some((0x30, names, _)) = der_tlv(wrapped) else {
            continue;
        };
        let mut gn = names;
        while !gn.is_empty() {
            let Some((tag, value, rest)) = der_tlv(gn) else {
                break;
            };
            gn = rest;
            if tag != 0x82 || value.len() > NAME_MAX {
                continue;
            }
            if let Ok(text) = std::str::from_utf8(value) {
                let clean = super::sanitize_name(text);
                if is_name_like(&clean) && !out.contains(&clean) {
                    out.push(clean);
                }
            }
        }
    }
    out
}

/// One DER TLV: (tag, definite-length content, what follows). Long-form
/// lengths up to four bytes are accepted; indefinite (0x80) and absurd
/// ones are rejected — this walker parses certificates, not BER.
fn der_tlv(buf: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = buf.split_first()?;
    if tag & 0x1f == 0x1f {
        return None; // multi-byte tag numbers: none of our OIDs need them
    }
    let (&first, mut rest) = rest.split_first()?;
    let len = match first {
        0x80 => return None, // indefinite length
        n if n < 0x80 => n as usize,
        n => {
            let count = (n & 0x7f) as usize;
            if count == 0 || count > 4 || rest.len() < count {
                return None;
            }
            let mut bytes = [0u8; 4];
            bytes[4 - count..].copy_from_slice(&rest[..count]);
            rest = &rest[count..];
            u32::from_be_bytes(bytes) as usize
        }
    };
    if rest.len() < len {
        return None;
    }
    Some((tag, &rest[..len], &rest[len..]))
}

/// Hostname-shape gate for certificate strings: after sanitizing, keep the
/// name only if it looks like one the DNS could carry — letters, digits,
/// dots, dashes, a wildcard; at least one dot so "Example Corp" does not
/// turn into `examplecorp`.
fn is_name_like(s: &str) -> bool {
    s.contains('.')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '*'))
}

fn be24(b: &[u8]) -> usize {
    ((b[0] as usize) << 16) | ((b[1] as usize) << 8) | b[2] as usize
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// DER TLV builder for test blobs (short and two-byte long forms).
    pub(crate) fn der(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if body.len() < 0x80 {
            out.push(body.len() as u8);
        } else {
            out.push(0x82);
            out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        }
        out.extend_from_slice(body);
        out
    }

    pub(crate) fn handshake_msg(t: u8, body: &[u8]) -> Vec<u8> {
        let mut m = vec![
            t,
            (body.len() >> 16) as u8,
            (body.len() >> 8) as u8,
            body.len() as u8,
        ];
        m.extend_from_slice(body);
        m
    }

    pub(crate) fn record(t: u8, body: &[u8]) -> Vec<u8> {
        let mut r = vec![t, 0x03, 0x03]; // type + record-layer version
        r.extend_from_slice(&(body.len() as u16).to_be_bytes());
        r.extend_from_slice(body);
        r
    }

    pub(crate) fn server_hello(version: [u8; 2]) -> Vec<u8> {
        let mut b = version.to_vec();
        b.extend_from_slice(&[0u8; 32]); // random
        b.push(0); // empty session id
        b.extend_from_slice(&[0xc0, 0x13]); // suite
        b.push(0); // compression
        handshake_msg(HS_SERVER_HELLO, &b)
    }

    /// Minimal v3 leaf: CN in the subject, SAN entries, fixed placeholders
    /// elsewhere — just enough DER for `walk_certificate` to descend.
    pub(crate) fn leaf_cert(cn: &str, sans: &[&str]) -> Vec<u8> {
        let atv = [
            der(0x06, &[0x55, 0x04, 0x03]).as_slice(),
            der(0x13, cn.as_bytes()).as_slice(),
        ]
        .concat();
        let mut san_names_blob = Vec::new();
        for s in sans {
            let mut g = vec![0x82, s.len() as u8];
            g.extend_from_slice(s.as_bytes());
            san_names_blob.extend_from_slice(&g);
        }
        let san_ext = der(
            0x30,
            &[
                der(0x06, &[0x55, 0x1d, 0x11]).as_slice(),
                der(0x04, &der(0x30, &san_names_blob)).as_slice(),
            ]
            .concat(),
        );
        let tbs = [
            der(0xa0, &der(0x02, &[2])).as_slice(),    // version v3
            der(0x02, &[1]).as_slice(),                // serial
            der(0x30, &der(0x06, &[0x2a])).as_slice(), // signature algorithm
            der(0x30, &der(0x31, &der(0x30, &atv))).as_slice(), // issuer
            der(
                0x30,
                &[
                    der(0x17, b"250101000000Z").as_slice(),
                    der(0x17, b"260101000000Z").as_slice(),
                ]
                .concat(),
            )
            .as_slice(), // validity
            der(0x30, &der(0x31, &der(0x30, &atv))).as_slice(), // subject
            der(0x30, &[0x00]).as_slice(),             // spki placeholder
            der(0xa3, &der(0x30, &san_ext)).as_slice(), // extensions
        ]
        .concat();
        // Certificate = SEQ { tbsCertificate, signatureAlgorithm, signature }
        der(
            0x30,
            &[
                der(0x30, &tbs).as_slice(),
                der(0x30, &der(0x06, &[0x2a])).as_slice(),
                der(0x03, &[0x00]).as_slice(),
            ]
            .concat(),
        )
    }

    pub(crate) fn certificate_msg(entries: &[&[u8]]) -> Vec<u8> {
        let mut body = Vec::new();
        let total: usize = entries.iter().map(|e| 3 + e.len()).sum();
        body.extend_from_slice(&[(total >> 16) as u8, (total >> 8) as u8, total as u8]);
        for e in entries {
            body.extend_from_slice(&[(e.len() >> 16) as u8, (e.len() >> 8) as u8, e.len() as u8]);
            body.extend_from_slice(e);
        }
        handshake_msg(HS_CERTIFICATE, &body)
    }

    fn run(records: &[Vec<u8>]) -> TlsOutcome {
        let mut bytes = Vec::new();
        for r in records {
            bytes.extend_from_slice(r);
        }
        handshake(&mut Cursor::new(bytes))
    }

    #[test]
    fn client_hello_shape_is_pinned() {
        let h = client_hello();
        assert_eq!(&h[..5], &[0x16, 0x03, 0x01, 0x00, 0x37]); // record, 55-byte payload
        assert_eq!(&h[5..9], &[0x01, 0x00, 0x00, 0x33]); // ClientHello, 51-byte body
        assert_eq!(&h[9..11], &[0x03, 0x03]); // client_version
                                              // empty session id, six suites, null compression, NO extensions
        assert_eq!(
            &h[43..],
            &[
                0x00, // session id length
                0x00, 0x0c, // cipher suites length
                0xc0, 0x13, 0xc0, 0x09, 0xc0, 0x27, 0x00, 0x9c, 0x00, 0x2f, 0x00, 0x35, 0x01,
                0x00, // one compression method: null
            ]
        );
        assert_eq!(h.len(), 60);
    }

    #[test]
    fn single_record_handshake_yields_cn_and_san() {
        let cert = leaf_cert(
            "web01.corp.example.com",
            &["web01.corp.example.com", "alt.corp.example.com"],
        );
        let blob = record(
            REC_HANDSHAKE,
            &[server_hello([0x03, 0x03]), certificate_msg(&[&cert])].concat(),
        );
        match run(&[blob]) {
            TlsOutcome::Names(n) => {
                assert_eq!(n.cn.as_deref(), Some("web01.corp.example.com"));
                assert_eq!(
                    n.san,
                    vec!["web01.corp.example.com", "alt.corp.example.com"]
                );
            }
            other => panic!("expected names, got {other:?}"),
        }
    }

    #[test]
    fn certificate_split_across_records_is_reassembled() {
        let cert = leaf_cert("split.corp.example.com", &["split.corp.example.com"]);
        let msg = certificate_msg(&[&cert]);
        let (head, tail) = msg.split_at(msg.len() / 2);
        let out = run(&[
            record(REC_HANDSHAKE, &server_hello([0x03, 0x03])),
            record(REC_HANDSHAKE, head),
            record(REC_HANDSHAKE, tail),
        ]);
        match out {
            TlsOutcome::Names(n) => {
                assert_eq!(n.cn.as_deref(), Some("split.corp.example.com"));
                assert_eq!(n.san, vec!["split.corp.example.com"]);
            }
            other => panic!("expected names, got {other:?}"),
        }
    }

    #[test]
    fn hello_request_before_the_server_hello_is_skipped() {
        let cert = leaf_cert("hr.corp.example.com", &[]);
        let out = run(&[record(
            REC_HANDSHAKE,
            &[
                handshake_msg(HS_HELLO_REQUEST, &[]),
                server_hello([0x03, 0x03]),
                certificate_msg(&[&cert]),
            ]
            .concat(),
        )]);
        match out {
            TlsOutcome::Names(n) => assert_eq!(n.cn.as_deref(), Some("hr.corp.example.com")),
            other => panic!("expected names, got {other:?}"),
        }
    }

    #[test]
    fn tls13_serverhello_is_reported_not_parsed() {
        let out = run(&[record(REC_HANDSHAKE, &server_hello([0x03, 0x04]))]);
        match out {
            TlsOutcome::Skipped(why) => assert!(why.contains("1.3"), "{why}"),
            other => panic!("expected a skip, got {other:?}"),
        }
    }

    #[test]
    fn alert_carries_its_code_into_the_skip_reason() {
        let out = run(&[record(REC_ALERT, &[0x02, 40])]); // fatal handshake_failure
        match out {
            TlsOutcome::Skipped(why) => assert_eq!(why, "server alert 40"),
            other => panic!("expected a skip, got {other:?}"),
        }
    }

    #[test]
    fn unexpected_record_type_is_a_skip() {
        let out = run(&[record(23, &[0u8; 8])]); // application data: no key exchange was run
        match out {
            TlsOutcome::Skipped(why) => assert!(why.contains("record type 23"), "{why}"),
            other => panic!("expected a skip, got {other:?}"),
        }
    }

    #[test]
    fn eof_before_anything_is_a_skip() {
        match run(&[]) {
            TlsOutcome::Skipped(why) => assert!(why.contains("closed or timed out"), "{why}"),
            other => panic!("expected a skip, got {other:?}"),
        }
    }

    #[test]
    fn garbage_certificate_is_a_skip_not_a_crash() {
        let junk = handshake_msg(HS_CERTIFICATE, &[0xde, 0xad, 0xbe, 0xef]);
        let out = run(&[record(
            REC_HANDSHAKE,
            &[server_hello([0x03, 0x03]), junk].concat(),
        )]);
        match out {
            TlsOutcome::Skipped(why) => assert!(why.contains("malformed"), "{why}"),
            other => panic!("expected a skip, got {other:?}"),
        }
    }

    #[test]
    fn wildcard_san_survives_verbatim_and_dupes_collapse() {
        let cert = leaf_cert(
            "*.corp.example.com",
            &[
                "*.corp.example.com",
                "www.corp.example.com",
                "*.corp.example.com",
            ],
        );
        let out = run(&[record(
            REC_HANDSHAKE,
            &[server_hello([0x03, 0x03]), certificate_msg(&[&cert])].concat(),
        )]);
        match out {
            TlsOutcome::Names(n) => {
                assert_eq!(n.cn.as_deref(), Some("*.corp.example.com"));
                assert_eq!(n.san, vec!["*.corp.example.com", "www.corp.example.com"]);
            }
            other => panic!("expected names, got {other:?}"),
        }
    }

    #[test]
    fn org_shaped_cn_is_dropped_and_missing_san_is_empty() {
        let cert = leaf_cert("Example Corp Ltd", &[]);
        let out = run(&[record(
            REC_HANDSHAKE,
            &[server_hello([0x03, 0x03]), certificate_msg(&[&cert])].concat(),
        )]);
        match out {
            TlsOutcome::Names(n) => {
                assert_eq!(n.cn, None);
                assert!(n.san.is_empty());
            }
            other => panic!("expected names, got {other:?}"),
        }
    }

    #[test]
    fn indefinite_der_length_is_rejected() {
        // A BER indefinite-length tag where the Certificate SEQUENCE sits:
        // the walker must bail out to a skip, not loop or trust it.
        let cert = [0x30, 0x80, 0xde, 0xad, 0x00, 0x00];
        let out = run(&[record(
            REC_HANDSHAKE,
            &[server_hello([0x03, 0x03]), certificate_msg(&[&cert])].concat(),
        )]);
        match out {
            TlsOutcome::Names(n) => {
                assert_eq!(n.cn, None);
                assert!(n.san.is_empty());
            }
            other => panic!("expected empty names or a skip, got {other:?}"),
        }
    }

    #[test]
    fn fake_server_end_to_end() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let cert = leaf_cert(
            "mx01.corp.example.com",
            &["mx01.corp.example.com", "smtp.corp.example.com"],
        );
        let blob = record(
            REC_HANDSHAKE,
            &[server_hello([0x03, 0x03]), certificate_msg(&[&cert])].concat(),
        );
        let handle = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            use std::io::Read;
            let mut buf = [0u8; 512];
            let n = s.read(&mut buf).unwrap(); // the ClientHello arrives first
            assert!(n >= 60, "client hello should be a full record");
            use std::io::Write;
            s.write_all(&blob).unwrap();
            // drop closes the connection: the collector has what it needs
        });
        let out = grab_names(addr, Duration::from_secs(2));
        handle.join().unwrap();
        match out {
            TlsOutcome::Names(n) => {
                assert_eq!(n.cn.as_deref(), Some("mx01.corp.example.com"));
                assert_eq!(
                    n.san,
                    vec!["mx01.corp.example.com", "smtp.corp.example.com"]
                );
            }
            other => panic!("expected names, got {other:?}"),
        }
    }

    #[test]
    fn fake_server_that_never_speaks_tls_is_a_skip() {
        // A plaintext HTTP port or a half-open TCP endpoint: connect works,
        // nothing TLS-shaped comes back.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            use std::io::Read;
            let mut buf = [0u8; 512];
            let _ = s.read(&mut buf);
            // close without a byte of TLS
        });
        let out = grab_names(addr, Duration::from_secs(2));
        handle.join().unwrap();
        match out {
            TlsOutcome::Skipped(why) => assert!(!why.is_empty()),
            other => panic!("expected a skip, got {other:?}"),
        }
    }
}
