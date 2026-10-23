//! LDAP machine-account reader for the `names` collector: bind (anonymous
//! or simple), rootDSE for the default naming context, then a paged
//! `(objectClass=computer)` search collecting `sAMAccountName` and
//! `dNSHostName`. Cleartext on 389 by design for v1 — the caller prints a
//! loud warning before any simple bind; Kerberos/GSSAPI is v2 and slots in
//! as an `LdapAuth::Gssapi` variant the query code never needs to know
//! about (the bind builder is the only match site).
//!
//! Hand-rolled BER, definite lengths only, like the TLS module: caps, not
//! trust — 256 KiB per message, 64 KiB per attribute value, depth bounded
//! by a fixed descent shape. A hostile server can fail the collection (an
//! `Err` the caller logs) but not lie (garbage never parses into names) or
//! wedge it (round cap on the paging loop).
//!
//! Deviation worth naming: the paging fallback. Some servers reject the
//! paged-results control outright (protocolError); on that answer the
//! search is re-issued once without the control — the first 1000 computers
//! only — and the returned flag tells the caller so names.log can say so.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use anyhow::{bail, Context, Result};

/// How the collector authenticates. `Anonymous` is the default when
/// `RUSTRAWL_LDAP_BIND` is unset; the env var parses into `Simple`.
/// Kerberos/GSSAPI lands here as a future variant.
#[derive(Debug, Clone)]
pub(crate) enum LdapAuth {
    Anonymous,
    Simple { who: String, pass: String },
}

/// One machine account from the computer search.
#[derive(Debug, Clone)]
pub(crate) struct LdapComputer {
    pub(crate) dns_host: Option<String>,
    pub(crate) sam: Option<String>,
}

/// LDAPv3 simple bind messages carry the version as an INTEGER.
const LDAP_VERSION: i64 = 3;
/// Paged-results control (Microsoft): 1.2.840.113556.1.4.319.
const PAGED_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x34, 0x01, 0x04, 0x3f];
/// Page size for the computer search (and the uncontrolled fallback's
/// only-page count).
const PAGE_SIZE: u32 = 1000;
/// The paging loop must converge; 500 rounds × 1000 entries is 500k
/// computer objects — far past any audit we expect, and the cap bounds a
/// hostile or buggy server.
const MAX_ROUNDS: usize = 500;
/// One LDAP message from the wire.
const MSG_MAX: usize = 256 * 1024;
/// One attribute value.
const VALUE_MAX: usize = 64 * 1024;

/// The bind spec from `RUSTRAWL_LDAP_BIND`: `who:password`, split at the
/// FIRST colon — a UPN or DN never carries one, but a password may.
/// `user@domain` stays a UPN; `DOMAIN\user` becomes
/// `user@DOMAIN`; a `CN=…` DN passes verbatim. Anything without a colon is
/// a config error naming the env var.
pub(crate) fn parse_bind_spec(spec: &str) -> Result<LdapAuth> {
    let (who, pass) = spec.split_once(':').context(
        "RUSTRAWL_LDAP_BIND must be who:password - the password is separated by a colon",
    )?;
    if who.is_empty() {
        bail!("RUSTRAWL_LDAP_BIND has an empty user part (who:password)");
    }
    if pass.is_empty() {
        bail!("RUSTRAWL_LDAP_BIND has an empty password part (who:password)");
    }
    let who = match who.split_once('\\') {
        Some((domain, user)) => format!("{user}@{domain}"),
        None => who.to_string(),
    };
    Ok(LdapAuth::Simple {
        who,
        pass: pass.to_string(),
    })
}

/// The run's LDAP auth: unset/empty `RUSTRAWL_LDAP_BIND` means anonymous;
/// anything else goes through `parse_bind_spec`.
pub(crate) fn auth_from_env() -> Result<LdapAuth> {
    match std::env::var("RUSTRAWL_LDAP_BIND") {
        Err(_) => Ok(LdapAuth::Anonymous),
        Ok(spec) if spec.trim().is_empty() => Ok(LdapAuth::Anonymous),
        Ok(spec) => parse_bind_spec(&spec),
    }
}

// --- encoding ---------------------------------------------------------------

fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = body.len();
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xff {
        out.extend_from_slice(&[0x81, len as u8]);
    } else {
        out.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]);
    }
    out.extend_from_slice(body);
    out
}

fn integer(v: i64) -> Vec<u8> {
    // Minimal big-endian; every value this collector sends is non-negative,
    // so only the leading byte's high bit needs a pad.
    if v == 0 {
        return tlv(0x02, &[0x00]);
    }
    let be = v.to_be_bytes();
    let first = be.iter().position(|&b| b != 0).unwrap();
    let mut body = be[first..].to_vec();
    if body[0] & 0x80 != 0 {
        body.insert(0, 0x00); // keep it positive
    }
    tlv(0x02, &body)
}

fn enumerated(v: u32) -> Vec<u8> {
    let mut out = integer(v as i64);
    out[0] = 0x0a;
    out
}

fn octet(bytes: &[u8]) -> Vec<u8> {
    tlv(0x04, bytes)
}

/// One LDAP message: SEQUENCE { messageID, protocolOp, [controls] }.
fn ldap_message(id: u32, op: &[u8], controls: Option<&[u8]>) -> Vec<u8> {
    let mut body = integer(id as i64);
    body.extend_from_slice(op);
    if let Some(c) = controls {
        body.extend_from_slice(&tlv(0xa0, c));
    }
    tlv(0x30, &body)
}

fn bind_request(auth: &LdapAuth) -> Vec<u8> {
    let (name, pass) = match auth {
        LdapAuth::Anonymous => ("", ""),
        LdapAuth::Simple { who, pass } => (who.as_str(), pass.as_str()),
    };
    let mut body = integer(LDAP_VERSION);
    body.extend_from_slice(&octet(name.as_bytes()));
    body.extend_from_slice(&tlv(0x80, pass.as_bytes())); // [0] simple
    tlv(0x60, &body) // [APPLICATION 0] bindRequest
}

fn present_filter(attr: &str) -> Vec<u8> {
    tlv(0x87, attr.as_bytes()) // [7] present
}

fn equality_filter(attr: &str, value: &str) -> Vec<u8> {
    let mut body = octet(attr.as_bytes());
    body.extend_from_slice(&octet(value.as_bytes()));
    tlv(0xa3, &body) // [3] equalityMatch
}

/// The paged-results control: OID + controlValue, where the value is the
/// full BER encoding of RealVal = SEQUENCE { size, cookie } (header
/// included — that is what the OCTET STRING wraps).
fn paged_control(cookie: &[u8]) -> Vec<u8> {
    let mut real = integer(PAGE_SIZE as i64);
    real.extend_from_slice(&octet(cookie));
    let control = [
        octet(PAGED_OID).as_slice(),
        octet(&tlv(0x30, &real)).as_slice(),
    ]
    .concat();
    tlv(0x30, &control)
}

/// The searchRequest protocolOp (the [APPLICATION 3] TLV, no id, no
/// controls — `ldap_message` wraps those on).
fn search_op(base: &str, scope: u32, filter: &[u8], attrs: &[&str]) -> Vec<u8> {
    let mut body = octet(base.as_bytes());
    body.extend_from_slice(&enumerated(scope));
    body.extend_from_slice(&enumerated(0)); // neverDerefAliases
    body.extend_from_slice(&integer(0)); // no client size limit
    body.extend_from_slice(&integer(0)); // no time limit
    body.extend_from_slice(&tlv(0x01, &[0x00])); // typesOnly FALSE
    body.extend_from_slice(filter);
    let mut attr_list = Vec::new();
    for a in attrs {
        attr_list.extend_from_slice(&octet(a.as_bytes()));
    }
    body.extend_from_slice(&tlv(0x30, &attr_list));
    tlv(0x63, &body)
}

fn unbind_message(id: u32) -> Vec<u8> {
    ldap_message(id, &tlv(0x42, &[]), None) // [APPLICATION 2] NULL
}

// --- wire -------------------------------------------------------------------

fn read_ber_length(r: &mut impl Read) -> Result<usize> {
    let mut b = [0u8; 1];
    r.read_exact(&mut b)?;
    match b[0] {
        0x80 => bail!("ldap: indefinite length is not accepted"),
        n if n < 0x80 => Ok(n as usize),
        n => {
            let count = (n & 0x7f) as usize;
            if count == 0 || count > 4 {
                bail!("ldap: absurd length prefix");
            }
            let mut bytes = [0u8; 4];
            r.read_exact(&mut bytes[4 - count..])?;
            let len = u32::from_be_bytes(bytes) as usize;
            if len > MSG_MAX {
                bail!("ldap: message of {len} bytes exceeds the cap");
            }
            Ok(len)
        }
    }
}

/// One LDAP message off the stream: (protocolOp tag, op body, controls).
/// The outer SEQUENCE and the message id are consumed and unchecked — this
/// is a private conversation in request/response order.
fn read_message(r: &mut impl Read) -> Result<(u8, Vec<u8>, Option<Vec<u8>>)> {
    let mut tag = [0u8; 1];
    r.read_exact(&mut tag)?;
    if tag[0] != 0x30 {
        bail!("ldap: expected a BER SEQUENCE, got {:#04x}", tag[0]);
    }
    let len = read_ber_length(r)?;
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    let (id_tag, _, rest) = ber_tlv(&buf).context("ldap: message id does not parse")?;
    if id_tag != 0x02 {
        bail!("ldap: message id is not an INTEGER");
    }
    let (op_tag, op_body, rest) = ber_tlv(rest).context("ldap: protocolOp does not parse")?;
    let controls = match ber_tlv(rest) {
        // the controls FIELD, wrapper included — paged_cookie matches on it
        Some((0xa0, ctl, _)) => Some(tlv(0xa0, ctl)),
        Some(_) => bail!("ldap: trailing junk after the protocolOp"),
        None => {
            if rest.is_empty() {
                None
            } else {
                bail!("ldap: trailing junk after the protocolOp")
            }
        }
    };
    Ok((op_tag, op_body.to_vec(), controls))
}

/// Definite-length BER TLV: (tag, content, what follows). Same rules as
/// the DER walker in tls_cert — indefinite and absurd lengths rejected —
/// kept local so each protocol module reads standalone.
fn ber_tlv(buf: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = buf.split_first()?;
    if tag & 0x1f == 0x1f {
        return None;
    }
    let (&first, mut rest) = rest.split_first()?;
    let len = match first {
        0x80 => return None, // indefinite: not accepted
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

/// LDAPResult = SEQ { ENUMERATED code, matchedDN, diagnostics }.
fn parse_result_code(body: &[u8]) -> Result<(u32, String)> {
    let Some((0x0a, code_bytes, rest)) = ber_tlv(body) else {
        bail!("ldap: result code does not parse");
    };
    let code = match code_bytes {
        [c] => u32::from(*c),
        _ => bail!("ldap: result code is not one byte"),
    };
    let Some((_, _, rest)) = ber_tlv(rest) else {
        bail!("ldap: matchedDN does not parse");
    };
    let diag = match ber_tlv(rest) {
        Some((0x04, d, _)) => String::from_utf8_lossy(d).into_owned(),
        _ => String::new(),
    };
    Ok((code, diag))
}

/// The attribute list of one searchResEntry → (attr, first value) pairs.
fn parse_attrs(entry_body: &[u8]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    // entry = SEQ { objectName, attributes SEQ OF PartialAttribute }
    let Some((0x04, _object, rest)) = ber_tlv(entry_body) else {
        return out;
    };
    let Some((0x30, attrs, _)) = ber_tlv(rest) else {
        return out;
    };
    let mut cur = attrs;
    while !cur.is_empty() {
        let Some((0x30, pa, rest)) = ber_tlv(cur) else {
            break;
        };
        cur = rest;
        // PartialAttribute = SEQ { type, vals SET OF value }
        let Some((0x04, attr_type, tail)) = ber_tlv(pa) else {
            break;
        };
        let Ok(attr_type) = std::str::from_utf8(attr_type) else {
            break;
        };
        let Some((0x31, vals, _)) = ber_tlv(tail) else {
            continue;
        };
        let Some((0x04, value, _)) = ber_tlv(vals) else {
            continue;
        };
        if value.len() > VALUE_MAX {
            continue;
        }
        out.push((
            attr_type.to_ascii_lowercase(),
            String::from_utf8_lossy(value).into_owned(),
        ));
    }
    out
}

fn parse_computer(entry_body: &[u8]) -> Option<LdapComputer> {
    let mut c = LdapComputer {
        dns_host: None,
        sam: None,
    };
    for (attr, value) in parse_attrs(entry_body) {
        match attr.as_str() {
            "samaccountname" => c.sam = Some(value),
            "dnshostname" => c.dns_host = Some(value),
            _ => {}
        }
    }
    if c.dns_host.is_none() && c.sam.is_none() {
        None
    } else {
        Some(c)
    }
}

/// The paged-results cookie from a searchResDone's controls, if the server
/// sent one (more pages to come).
fn paged_cookie(controls: &[u8]) -> Option<Vec<u8>> {
    let (tag, seq, _) = ber_tlv(controls)?;
    if tag != 0xa0 {
        return None;
    }
    let mut cur = seq;
    while !cur.is_empty() {
        let Some((0x30, ctl, rest)) = ber_tlv(cur) else {
            break;
        };
        cur = rest;
        let Some((0x04, oid, tail)) = ber_tlv(ctl) else {
            break;
        };
        if oid != PAGED_OID {
            continue;
        }
        let mut tail = tail;
        if let Some((0x01, _, rest)) = ber_tlv(tail) {
            tail = rest; // the optional criticality flag
        }
        let Some((0x04, value, _)) = ber_tlv(tail) else {
            continue;
        };
        let Some((0x30, real, _)) = ber_tlv(value) else {
            continue;
        };
        let Some((0x02, _, after_size)) = ber_tlv(real) else {
            continue;
        };
        let Some((0x04, cookie, _)) = ber_tlv(after_size) else {
            continue;
        };
        return Some(cookie.to_vec());
    }
    None
}

/// Drains one search's entries until the done arrives. Returns
/// (resultCode, controls) — any code, including failures, is a value: the
/// caller decides what a code means here. Only transport surprises and
/// unknown ops are Err.
fn read_search(
    r: &mut impl Read,
    on_entry: &mut impl FnMut(&[u8]),
) -> Result<(u32, Option<Vec<u8>>)> {
    loop {
        let (tag, body, controls) = read_message(r)?;
        match tag {
            0x64 => on_entry(&body), // searchResEntry
            0x65 => {
                // searchResDone — any code is a value here; the caller
                // decides what a code means (paging fallback lives there).
                let (code, _) = parse_result_code(&body)?;
                return Ok((code, controls));
            }
            other => bail!("ldap: unexpected op tag {other:#04x} inside a search"),
        }
    }
}

/// The whole exchange: bind → rootDSE → paged computer search. Returns
/// (defaultNamingContext, computers, uncontrolled-fallback flag). An `Err`
/// is a protocol or transport answer the caller logs — never a crash.
pub(crate) fn ldap_enumerate(
    addr: SocketAddr,
    auth: &LdapAuth,
    timeout: Duration,
) -> Result<(Option<String>, Vec<LdapComputer>, bool)> {
    let mut sock = TcpStream::connect_timeout(&addr, timeout).context("connect failed")?;
    sock.set_read_timeout(Some(timeout))
        .context("read timeout setup")?;
    sock.set_write_timeout(Some(timeout))
        .context("write timeout setup")?;
    let mut next_id = 1u32;

    // bind
    let bind = ldap_message(next_id, &bind_request(auth), None);
    next_id += 1;
    sock.write_all(&bind).context("bind write failed")?;
    let (tag, body, _) = read_message(&mut sock)?;
    if tag != 0x61 {
        bail!("expected bindResponse, got op tag {tag:#04x}");
    }
    let (code, diag) = parse_result_code(&body)?;
    if code == 49 {
        bail!("bind failed (invalidCredentials, code 49) - check RUSTRAWL_LDAP_BIND");
    }
    if code != 0 {
        if diag.is_empty() {
            bail!("bind refused (code {code})");
        }
        bail!("bind refused (code {code}): {diag}");
    }

    // rootDSE: the tree's base, asked with an anonymous-friendly present
    // filter against the empty base.
    let root = ldap_message(
        next_id,
        &search_op(
            "",
            0,
            &present_filter("objectClass"),
            &["defaultNamingContext"],
        ),
        None,
    );
    next_id += 1;
    sock.write_all(&root).context("rootDSE write failed")?;
    let mut default_nc: Option<String> = None;
    read_search(&mut sock, &mut |entry| {
        for (attr, value) in parse_attrs(entry) {
            if attr == "defaultnamingcontext" {
                default_nc = Some(value);
            }
        }
    })?;

    // paged computer search
    let computers_op = search_op(
        default_nc.as_deref().unwrap_or(""),
        2, // wholeSubtree
        &equality_filter("objectClass", "computer"),
        &["sAMAccountName", "dNSHostName"],
    );
    let mut computers: Vec<LdapComputer> = Vec::new();
    let mut cookie: Vec<u8> = Vec::new();
    let mut uncontrolled = false;
    let mut rounds = 0usize;
    loop {
        rounds += 1;
        if rounds > MAX_ROUNDS {
            bail!("paged search did not converge in {MAX_ROUNDS} rounds");
        }
        // ldap_message wraps the control list in the [0] context tag itself
        let controls = if uncontrolled {
            None
        } else {
            Some(paged_control(&cookie))
        };
        let msg = ldap_message(next_id, &computers_op, controls.as_deref());
        next_id += 1;
        sock.write_all(&msg).context("search write failed")?;
        let (code, done_controls) = read_search(&mut sock, &mut |entry| {
            if let Some(c) = parse_computer(entry) {
                computers.push(c);
            }
        })?;
        if code == 2 && !uncontrolled && rounds == 1 {
            // protocolError: the server refuses the paged control. One
            // fallback without it — the first page only.
            uncontrolled = true;
            continue;
        }
        if code != 0 {
            bail!("computer search failed (code {code})");
        }
        cookie = done_controls
            .as_deref()
            .and_then(paged_cookie)
            .unwrap_or_default();
        if cookie.is_empty() {
            break;
        }
    }

    // polite close: unbind, then the drop finishes the job
    let _ = sock.write_all(&unbind_message(next_id));

    Ok((default_nc, computers, uncontrolled))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn message_id_of(request_body: &[u8]) -> Vec<u8> {
        // The id TLV bytes of a request body, copied verbatim (ids in tests
        // are < 128, so the encoding is [0x02, 0x01, id]).
        let Some((tag, content, _)) = ber_tlv(request_body) else {
            panic!("message id does not parse");
        };
        assert_eq!(tag, 0x02, "message id is not an INTEGER");
        let mut out = vec![0x02, content.len() as u8];
        out.extend_from_slice(content);
        out
    }

    /// Reads one request per batch, answers with EVERY message of batch[i]
    /// spliced onto the request's message id (a search answer is a batch of
    /// entries plus a done), and returns the request bodies for assertions.
    pub(crate) fn fake_ldap(
        script: Vec<Vec<Vec<u8>>>,
    ) -> (SocketAddr, std::thread::JoinHandle<Vec<Vec<u8>>>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            s.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut seen: Vec<Vec<u8>> = Vec::new();
            for batch in &script {
                // read one full request: outer SEQ header, then the body.
                // Fewer requests than batches is fine (the unbind is not
                // scripted).
                let mut tag = [0u8; 1];
                if s.read_exact(&mut tag).is_err() {
                    break;
                }
                assert_eq!(tag[0], 0x30);
                let len = read_ber_length(&mut s).unwrap();
                let mut body = vec![0u8; len];
                s.read_exact(&mut body).unwrap();
                let id = message_id_of(&body);
                seen.push(body);
                for canned in batch {
                    let mut resp = id.clone();
                    resp.extend_from_slice(canned);
                    // a client that hangs up early (a failing test) must not
                    // mask its own assertion with a fake-side panic
                    if s.write_all(&tlv(0x30, &resp)).is_err() {
                        return seen;
                    }
                }
            }
            // the unbind (if any) is read and ignored
            let mut tag = [0u8; 1];
            if s.read_exact(&mut tag).is_ok() && tag[0] == 0x30 {
                let len = read_ber_length(&mut s).unwrap_or(0);
                let mut rest = vec![0u8; len];
                let _ = s.read_exact(&mut rest);
            }
            seen
        });
        (addr, handle)
    }

    pub(crate) fn bind_ok() -> Vec<u8> {
        tlv(0x61, &[0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00])
    }

    pub(crate) fn bind_result(code: u8) -> Vec<u8> {
        tlv(0x61, &[0x0a, 0x01, code, 0x04, 0x00, 0x04, 0x00])
    }

    pub(crate) fn entry(sam: Option<&str>, dns_host: Option<&str>) -> Vec<u8> {
        let mut attrs = Vec::new();
        if let Some(sam) = sam {
            let pa = [
                octet(b"sAMAccountName").as_slice(),
                tlv(0x31, &octet(sam.as_bytes())).as_slice(),
            ]
            .concat();
            attrs.extend_from_slice(&tlv(0x30, &pa));
        }
        if let Some(host) = dns_host {
            let pa = [
                octet(b"dNSHostName").as_slice(),
                tlv(0x31, &octet(host.as_bytes())).as_slice(),
            ]
            .concat();
            attrs.extend_from_slice(&tlv(0x30, &pa));
        }
        let attr_seq = tlv(0x30, &attrs);
        tlv(0x64, &[octet(b"").as_slice(), attr_seq.as_slice()].concat())
    }

    /// searchResDone: resultCode + matchedDN + diagnostics. When a cookie is
    /// given, the paged-results control is appended as the message-level
    /// controls field (a sibling of the protocolOp, not inside it), so a
    /// canned item is "everything after the messageID".
    pub(crate) fn done(code: u8, cookie: Option<&[u8]>) -> Vec<u8> {
        let body = [0x0a, 0x01, code, 0x04, 0x00, 0x04, 0x00].to_vec();
        let mut out = tlv(0x65, &body);
        if let Some(cookie) = cookie {
            out.extend_from_slice(&tlv(0xa0, &paged_control(cookie)));
        }
        out
    }

    /// The rootDSE answer: one `defaultNamingContext` attribute — unlike a
    /// computer entry, which carries sAMAccountName/dNSHostName.
    pub(crate) fn rootdse_entry(nc: &str) -> Vec<u8> {
        let pa = [
            octet(b"defaultNamingContext").as_slice(),
            tlv(0x31, &octet(nc.as_bytes())).as_slice(),
        ]
        .concat();
        let attr_seq = tlv(0x30, &tlv(0x30, &pa)); // SEQ OF PartialAttribute
        tlv(0x64, &[octet(b"").as_slice(), attr_seq.as_slice()].concat())
    }

    #[test]
    fn anonymous_bind_message_is_pinned() {
        let msg = ldap_message(1, &bind_request(&LdapAuth::Anonymous), None);
        assert_eq!(
            msg,
            vec![
                0x30, 0x0c, // SEQUENCE, 12 bytes
                0x02, 0x01, 0x01, // messageID 1
                0x60, 0x07, // bindRequest, 7 bytes
                0x02, 0x01, 0x03, // version 3
                0x04, 0x00, // empty name
                0x80, 0x00, // simple, empty password
            ]
        );
    }

    #[test]
    fn simple_bind_carries_who_and_pass() {
        let auth = parse_bind_spec("user@corp.example.com:s3cret").unwrap();
        let op = bind_request(&auth);
        assert_eq!(&op[..3], &[0x60, 0x22, 0x02]); // 34-byte bindRequest
        let text = String::from_utf8_lossy(&op).into_owned();
        assert!(text.contains("user@corp.example.com"));
        assert!(text.contains("s3cret"));
    }

    #[test]
    fn bind_spec_forms() {
        match parse_bind_spec("CORP\\admin:pw").unwrap() {
            LdapAuth::Simple { who, pass } => {
                assert_eq!(who, "admin@CORP");
                assert_eq!(pass, "pw");
            }
            other => panic!("expected simple, got {other:?}"),
        }
        match parse_bind_spec("CN=admin,CN=Users,DC=corp,DC=example,DC=com:s3cret").unwrap() {
            LdapAuth::Simple { who, pass } => {
                assert_eq!(who, "CN=admin,CN=Users,DC=corp,DC=example,DC=com");
                assert_eq!(pass, "s3cret");
            }
            other => panic!("expected simple, got {other:?}"),
        }
        // a password may contain colons: the split is from the right
        match parse_bind_spec("u:p:w").unwrap() {
            LdapAuth::Simple { who, pass } => {
                assert_eq!(who, "u");
                assert_eq!(pass, "p:w");
            }
            other => panic!("expected simple, got {other:?}"),
        }
    }

    #[test]
    fn bind_spec_errors_name_the_env_var() {
        let err = parse_bind_spec("nocolon").unwrap_err().to_string();
        assert!(err.contains("RUSTRAWL_LDAP_BIND"), "{err}");
        let err = parse_bind_spec(":pw").unwrap_err().to_string();
        assert!(err.contains("RUSTRAWL_LDAP_BIND"), "{err}");
        let err = parse_bind_spec("u:").unwrap_err().to_string();
        assert!(err.contains("RUSTRAWL_LDAP_BIND"), "{err}");
    }

    #[test]
    fn auth_from_env_unset_or_empty_is_anonymous() {
        std::env::remove_var("RUSTRAWL_LDAP_BIND");
        assert!(matches!(auth_from_env().unwrap(), LdapAuth::Anonymous));
        std::env::set_var("RUSTRAWL_LDAP_BIND", "   ");
        assert!(matches!(auth_from_env().unwrap(), LdapAuth::Anonymous));
        std::env::set_var("RUSTRAWL_LDAP_BIND", "u@corp.example.com:pw");
        match auth_from_env().unwrap() {
            LdapAuth::Simple { who, pass } => {
                assert_eq!(who, "u@corp.example.com");
                assert_eq!(pass, "pw");
            }
            other => panic!("expected simple, got {other:?}"),
        }
        std::env::remove_var("RUSTRAWL_LDAP_BIND");
    }

    #[test]
    fn paged_control_is_pinned() {
        assert_eq!(
            paged_control(&[]),
            vec![
                0x30, 0x15, // SEQUENCE (one Control), 21 bytes
                0x04, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x34, 0x01, 0x04, 0x3f, // OID
                0x04, 0x08, // controlValue
                0x30, 0x06, // RealVal SEQUENCE
                0x02, 0x02, 0x03, 0xe8, // size 1000
                0x04, 0x00, // empty cookie
            ]
        );
        assert_eq!(
            &paged_control(b"AB")[13..],
            &[0x04, 0x0a, 0x30, 0x08, 0x02, 0x02, 0x03, 0xe8, 0x04, 0x02, 0x41, 0x42]
        );
    }

    #[test]
    fn filters_are_pinned() {
        assert_eq!(
            equality_filter("objectClass", "computer"),
            [
                &[0xa3, 0x17, 0x04, 0x0b][..],
                b"objectClass".as_slice(),
                &[0x04, 0x08][..],
                b"computer".as_slice(),
            ]
            .concat()
        );
        assert_eq!(
            present_filter("objectClass"),
            [&[0x87, 0x0b][..], b"objectClass".as_slice()].concat()
        );
    }

    #[test]
    fn search_op_carries_scope_filter_and_attrs() {
        let op = search_op(
            "",
            0,
            &present_filter("objectClass"),
            &["defaultNamingContext"],
        );
        assert_eq!(op[0], 0x63);
        let text = String::from_utf8_lossy(&op).into_owned();
        assert!(text.contains("defaultNamingContext"));
        assert!(
            op.windows(2).any(|w| w == [0x0a, 0x01]),
            "scope enumerated is present"
        );
    }

    #[test]
    fn result_codes_parse_with_and_without_diagnostics() {
        assert_eq!(
            parse_result_code(&[0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00]).unwrap(),
            (0, String::new())
        );
        let (code, _) = parse_result_code(&[0x0a, 0x01, 0x31, 0x04, 0x00, 0x04, 0x00]).unwrap();
        assert_eq!(code, 49);
        let (code, diag) = parse_result_code(
            &[
                &[0x0a, 0x01, 0x02, 0x04, 0x00][..],
                &octet(b"paged results not supported")[..],
            ]
            .concat(),
        )
        .unwrap();
        assert_eq!(code, 2);
        assert_eq!(diag, "paged results not supported");
    }

    #[test]
    fn computer_entries_parse_in_any_attribute_order() {
        // parse_computer sees the op BODY (what read_search hands over),
        // not the full 0x64 TLV the fake script carries.
        let body_of = |e: &[u8]| match ber_tlv(e) {
            Some((_, content, [])) => content.to_vec(),
            _ => panic!("entry does not parse"),
        };
        let c = parse_computer(&body_of(&entry(
            Some("DC01$"),
            Some("dc01.corp.example.com"),
        )))
        .unwrap();
        assert_eq!(c.sam.as_deref(), Some("DC01$"));
        assert_eq!(c.dns_host.as_deref(), Some("dc01.corp.example.com"));
        let c = parse_computer(&body_of(&entry(Some("WEB01$"), None))).unwrap();
        assert_eq!(c.sam.as_deref(), Some("WEB01$"));
        assert_eq!(c.dns_host, None);
        assert!(parse_computer(&[0x04, 0x00, 0x30, 0x00]).is_none());
    }

    #[test]
    fn paged_cookie_roundtrip() {
        assert_eq!(
            paged_cookie(&tlv(0xa0, &paged_control(b"AB"))),
            Some(b"AB".to_vec())
        );
        assert_eq!(
            paged_cookie(&tlv(0xa0, &paged_control(&[]))),
            Some(Vec::new())
        );
        assert_eq!(paged_cookie(&[0xa0, 0x02, 0x30, 0x00]), None);
        assert_eq!(paged_cookie(&[0x04, 0x00]), None);
    }

    #[test]
    fn fake_server_end_to_end_two_computers_and_one_cookie_round() {
        let script = vec![
            vec![bind_ok()],
            vec![
                rootdse_entry("DC=corp,DC=example,DC=com"),
                done(0, None), // rootDSE done
            ],
            vec![
                entry(Some("DC01$"), Some("dc01.corp.example.com")),
                entry(Some("WEB01$"), None),
                done(0, Some(b"AB".as_slice())), // more pages
            ],
            vec![
                entry(Some("SRV02$"), Some("srv02.corp.example.com")),
                done(0, None), // last page
            ],
        ];
        let (addr, handle) = fake_ldap(script);
        let (nc, computers, uncontrolled) =
            ldap_enumerate(addr, &LdapAuth::Anonymous, Duration::from_secs(2)).unwrap();
        let seen = handle.join().unwrap();
        assert_eq!(nc.as_deref(), Some("DC=corp,DC=example,DC=com"));
        assert_eq!(computers.len(), 3);
        assert_eq!(computers[0].sam.as_deref(), Some("DC01$"));
        assert_eq!(computers[2].sam.as_deref(), Some("SRV02$"));
        assert!(!uncontrolled);
        assert_eq!(
            seen.len(),
            4,
            "bind, rootDSE, two search rounds (the unbind is not scripted)"
        );
        // the two search rounds both carried the paged control (round 2
        // re-sends the cookie it was handed)
        let paged = seen[2].windows(PAGED_OID.len()).any(|w| w == PAGED_OID);
        let paged2 = seen[3].windows(PAGED_OID.len()).any(|w| w == PAGED_OID);
        assert!(paged && paged2);
    }

    #[test]
    fn bind_rejection_names_the_env_var() {
        let script = vec![vec![bind_result(49)]];
        let (addr, handle) = fake_ldap(script);
        let err = ldap_enumerate(addr, &LdapAuth::Anonymous, Duration::from_secs(2))
            .unwrap_err()
            .to_string();
        handle.join().unwrap();
        assert!(err.contains("RUSTRAWL_LDAP_BIND"), "{err}");
    }

    #[test]
    fn protocol_error_falls_back_once_without_the_control() {
        let script = vec![
            vec![bind_ok()],
            vec![rootdse_entry("DC=corp,DC=example,DC=com"), done(0, None)],
            vec![done(2, None)], // protocolError on the first paged round
            vec![
                entry(Some("DC01$"), Some("dc01.corp.example.com")),
                done(0, None),
            ],
        ];
        let (addr, handle) = fake_ldap(script);
        let (nc, computers, uncontrolled) =
            ldap_enumerate(addr, &LdapAuth::Anonymous, Duration::from_secs(2)).unwrap();
        let seen = handle.join().unwrap();
        assert_eq!(nc.as_deref(), Some("DC=corp,DC=example,DC=com"));
        assert_eq!(computers.len(), 1);
        assert!(uncontrolled);
        let paged1 = seen[2].windows(PAGED_OID.len()).any(|w| w == PAGED_OID);
        let paged2 = seen[3].windows(PAGED_OID.len()).any(|w| w == PAGED_OID);
        assert!(paged1, "first round asks for paging");
        assert!(!paged2, "fallback round drops the control");
    }
}
