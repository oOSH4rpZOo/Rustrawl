//! End-to-end `names` through the real binary, loopback only: connect-mode
//! discovery seeds the registry on 127.0.0.0/29 (every refusal is a live
//! stack), a fake-nmap scan adds one https and one ldap service row (the
//! collector picks TLS/LDAP targets by service name, so ephemeral ports
//! work), then three loopback fakes — DNS (PTR/A/AXFR), TLS 1.2, LDAP —
//! feed a single `names` run. Asserts the contract through the binary:
//! the host cards in a batch console session, the web API's names field
//! and the names.log trail. Port 22 is this box's sshd — never bound or probed.

use std::fs;
use std::io::{BufRead, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

const SCOPE: &str = "\
name: names-it
includes:
  - 127.0.0.0/29
discovery:
  rate_pps: 5000
  ports: [39145]
  expand_ports: [39145, 39146]
  icmp: false
scan:
  nmap_args: \"-sV -p 39146,39147\"
  threads: 1
";

/// Deterministic nmap stand-in: whatever host list it receives, it reports
/// exactly the two collector targets (https on .2, ldap on .3) — the names
/// collectors pick TLS/LDAP targets by service name, so ephemeral ports
/// work. Writes the same -oA outputs the real ingest reads.
const FAKE_NMAP: &str = r#"#!/usr/bin/env bash
set -u
base=""
args=("$@")
for ((i = 0; i < ${#args[@]}; i++)); do
  if [[ "${args[$i]}" == "-oA" ]]; then
    base="${args[$((i + 1))]}"
  fi
done
if [[ -n "$base" ]]; then
  printf '%s\n' "${args[@]}" > "$base.argv"
fi
: > "$base.gnmap"
: > "$base.nmap"
printf 'Host: 127.0.0.2 ()\tStatus: Up\nHost: 127.0.0.2 ()\tPorts: 39146/open/tcp//https//Apache 2.4.57\tIgnored State: closed (2)\n' >> "$base.gnmap"
printf 'Host: 127.0.0.3 ()\tStatus: Up\nHost: 127.0.0.3 ()\tPorts: 39147/open/tcp//ldap//OpenLDAP 2.6\tIgnored State: closed (2)\n' >> "$base.gnmap"
printf 'Nmap scan report for 127.0.0.2\nHost is up (0.001s latency).\n' >> "$base.nmap"
printf 'Nmap scan report for 127.0.0.3\nHost is up (0.001s latency).\n' >> "$base.nmap"
printf 'Nmap scan report for 127.0.0.2\nNmap scan report for 127.0.0.3\n'
"#;

fn temp_root(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "rustrawl-names-it-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|t| t.subsec_nanos())
            .unwrap_or(0)
    ));
    fs::create_dir_all(&d).unwrap();
    d
}

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rustrawl"))
}

// --------------------------------------------------------------- fake DNS

fn name_wire(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

/// Header + echoed question; answer records appended by the caller.
fn reply(txid: u16, question: &[u8], rcode: u8, an: usize) -> Vec<u8> {
    let mut m = Vec::with_capacity(12 + question.len());
    m.extend_from_slice(&txid.to_be_bytes());
    m.extend_from_slice(&(0x8000u16 | rcode as u16).to_be_bytes());
    m.extend_from_slice(&1u16.to_be_bytes()); // qd
    m.extend_from_slice(&(an as u16).to_be_bytes());
    m.extend_from_slice(&[0; 4]); // ns + ar
    m.extend_from_slice(question);
    m
}

/// An answer record whose owner is a compression pointer at offset 12.
fn answer_rr(rtype: u16, rdata: Vec<u8>) -> Vec<u8> {
    let mut r = vec![0xC0, 0x0C];
    r.extend_from_slice(&rtype.to_be_bytes());
    r.extend_from_slice(&1u16.to_be_bytes()); // IN
    r.extend_from_slice(&300u32.to_be_bytes()); // ttl
    r.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    r.extend_from_slice(&rdata);
    r
}

/// The zone's fake DNS: verified PTRs for .2 and .3, A records backing them
/// plus the LDAP dNSHostNames, one AXFR stream with a known and a foreign
/// address. Everything else is NXDOMAIN.
fn spawn_fake_dns(stop: Arc<AtomicBool>) -> SocketAddr {
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let listener = TcpListener::bind(udp.local_addr().unwrap()).unwrap();
    let addr = udp.local_addr().unwrap();
    std::thread::spawn(move || {
        listener.set_nonblocking(true).unwrap();
        udp.set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        loop {
            if stop.load(Ordering::SeqCst) {
                return;
            }
            let mut buf = [0u8; 2048];
            if let Ok((n, peer)) = udp.recv_from(&mut buf) {
                let msg = &buf[..n];
                if msg.len() < 12 {
                    continue;
                }
                let txid = u16::from_be_bytes([msg[0], msg[1]]);
                let mut p = 12usize;
                let mut qname = String::new();
                while p < msg.len() && msg[p] != 0 {
                    let l = msg[p] as usize;
                    if !qname.is_empty() {
                        qname.push('.');
                    }
                    qname.push_str(&String::from_utf8_lossy(&msg[p + 1..p + 1 + l]));
                    p += 1 + l;
                }
                let qtype = u16::from_be_bytes([msg[p + 1], msg[p + 2]]);
                let question = &msg[12..p + 5];
                let out = match (qtype, qname.as_str()) {
                    (12, "2.0.0.127.in-addr.arpa") => {
                        let mut r = reply(txid, question, 0, 1);
                        r.extend_from_slice(&answer_rr(12, name_wire("dc01.corp.example.com")));
                        r
                    }
                    (12, "3.0.0.127.in-addr.arpa") => {
                        let mut r = reply(txid, question, 0, 1);
                        r.extend_from_slice(&answer_rr(12, name_wire("srv03.corp.example.com")));
                        r
                    }
                    (1, "dc01.corp.example.com") | (1, "dc02.corp.example.com") => {
                        let mut r = reply(txid, question, 0, 1);
                        r.extend_from_slice(&answer_rr(1, vec![127, 0, 0, 2]));
                        r
                    }
                    (1, "srv03.corp.example.com") | (1, "srv04.corp.example.com") => {
                        let mut r = reply(txid, question, 0, 1);
                        r.extend_from_slice(&answer_rr(1, vec![127, 0, 0, 3]));
                        r
                    }
                    _ => reply(txid, question, 3, 0), // NXDOMAIN
                };
                let _ = udp.send_to(&out, peer);
            }
            // TCP: one framed AXFR exchange — SOA, two A records, SOA, EOF.
            if let Ok((mut sock, _)) = listener.accept() {
                sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                let mut lb = [0u8; 2];
                if sock.read_exact(&mut lb).is_err() {
                    continue;
                }
                let mut skip = vec![0u8; u16::from_be_bytes(lb) as usize];
                if sock.read_exact(&mut skip).is_err() {
                    continue;
                }
                let mut question = name_wire("corp.example.com");
                question.extend_from_slice(&252u16.to_be_bytes()); // AXFR
                question.extend_from_slice(&1u16.to_be_bytes()); // IN
                let soa_rdata = {
                    let mut rd = name_wire("ns1.corp.example.com");
                    rd.extend_from_slice(&name_wire("hostmaster.corp.example.com"));
                    rd.extend_from_slice(&1u32.to_be_bytes()); // serial
                    rd.extend_from_slice(&[0u8; 16]); // refresh/retry/expiry/minimum
                    rd
                };
                let mut soa_rr = name_wire("corp.example.com");
                soa_rr.extend_from_slice(&6u16.to_be_bytes());
                soa_rr.extend_from_slice(&1u16.to_be_bytes());
                soa_rr.extend_from_slice(&0u32.to_be_bytes());
                soa_rr.extend_from_slice(&(soa_rdata.len() as u16).to_be_bytes());
                soa_rr.extend_from_slice(&soa_rdata);
                let mut msg1 = reply(0, &question, 0, 3);
                msg1.extend_from_slice(&soa_rr);
                for (name, ip) in [
                    ("srv01.corp.example.com", [127, 0, 0, 2]),
                    ("foreign.corp.example.com", [10, 99, 0, 5]),
                ] {
                    let mut rr = name_wire(name);
                    rr.extend_from_slice(&1u16.to_be_bytes());
                    rr.extend_from_slice(&1u16.to_be_bytes());
                    rr.extend_from_slice(&0u32.to_be_bytes());
                    rr.extend_from_slice(&4u16.to_be_bytes());
                    rr.extend_from_slice(&ip);
                    msg1.extend_from_slice(&rr);
                }
                let mut msg2 = vec![0u8; 12];
                msg2[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
                msg2[6..8].copy_from_slice(&1u16.to_be_bytes());
                msg2.extend_from_slice(&soa_rr);
                let mut frame = (msg1.len() as u16).to_be_bytes().to_vec();
                frame.extend_from_slice(&msg1);
                frame.extend_from_slice(&(msg2.len() as u16).to_be_bytes());
                frame.extend_from_slice(&msg2);
                let _ = sock.write_all(&frame);
                // drop closes: the normal end of a transfer
            }
        }
    });
    addr
}

// --------------------------------------------------------------- fake TLS

/// One DER TLV, definite lengths (long form past 127 bytes).
fn der(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = body.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes(); // 8 bytes on a 64-bit usize
        let first = bytes.iter().position(|&b| b != 0).unwrap();
        out.push(0x80 | (bytes.len() - first) as u8);
        out.extend_from_slice(&bytes[first..]);
    }
    out.extend_from_slice(body);
    out
}

fn handshake_msg(t: u8, body: &[u8]) -> Vec<u8> {
    let mut m = vec![
        t,
        (body.len() >> 16) as u8,
        (body.len() >> 8) as u8,
        body.len() as u8,
    ];
    m.extend_from_slice(body);
    m
}

fn record(t: u8, body: &[u8]) -> Vec<u8> {
    let mut r = vec![t, 0x03, 0x03];
    r.extend_from_slice(&(body.len() as u16).to_be_bytes());
    r.extend_from_slice(body);
    r
}

/// A minimal v3 leaf: CN in the subject, SAN dNSName entries.
fn leaf_cert(cn: &str, sans: &[&str]) -> Vec<u8> {
    let atv = [
        der(0x06, &[0x55, 0x04, 0x03]).as_slice(),
        der(0x13, cn.as_bytes()).as_slice(),
    ]
    .concat();
    let mut san_blob = Vec::new();
    for s in sans {
        let mut g = vec![0x82, s.len() as u8];
        g.extend_from_slice(s.as_bytes());
        san_blob.extend_from_slice(&g);
    }
    let san_ext = der(
        0x30,
        &[
            der(0x06, &[0x55, 0x1d, 0x11]).as_slice(),
            der(0x04, &der(0x30, &san_blob)).as_slice(),
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

/// Binds `addr`, accepts one TLS connection, ignores the ClientHello and
/// answers with a static ServerHello + Certificate for `cn`/`sans`.
fn spawn_fake_tls(addr: &str, cn: &'static str, sans: &'static [&'static str]) {
    let listener = TcpListener::bind(addr).unwrap();
    std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        sock.set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut hello = [0u8; 1];
        if sock.read_exact(&mut hello).is_err() {
            return;
        }
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // empty session id
        body.extend_from_slice(&[0xc0, 0x13]); // suite
        body.push(0); // compression
        let cert = leaf_cert(cn, sans);
        let mut entries = vec![
            (cert.len() >> 16) as u8,
            (cert.len() >> 8) as u8,
            cert.len() as u8,
        ];
        entries.extend_from_slice(&cert);
        // TLS 1.2 Certificate message: the 3-byte list length straight away
        // (the request-context byte is a TLS 1.3 shape)
        let mut cert_body = vec![
            (entries.len() >> 16) as u8,
            (entries.len() >> 8) as u8,
            entries.len() as u8,
        ];
        cert_body.extend_from_slice(&entries);
        let mut out = record(0x16, &handshake_msg(2, &body)); // ServerHello
        out.extend_from_slice(&record(0x16, &handshake_msg(11, &cert_body))); // Certificate
        let _ = sock.write_all(&out);
        // the collector stops at the Certificate message and hangs up
    });
}

// -------------------------------------------------------------- fake LDAP

fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = body.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes(); // 8 bytes on a 64-bit usize
        let first = bytes.iter().position(|&b| b != 0).unwrap();
        out.push(0x80 | (bytes.len() - first) as u8);
        out.extend_from_slice(&bytes[first..]);
    }
    out.extend_from_slice(body);
    out
}

fn octet(bytes: &[u8]) -> Vec<u8> {
    tlv(0x04, bytes)
}

fn bind_ok() -> Vec<u8> {
    tlv(0x61, &[0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00])
}

fn rootdse_entry(nc: &str) -> Vec<u8> {
    let pa = [
        octet(b"defaultNamingContext").as_slice(),
        tlv(0x31, &octet(nc.as_bytes())).as_slice(),
    ]
    .concat();
    let attr_seq = tlv(0x30, &tlv(0x30, &pa)); // SEQ OF PartialAttribute
    tlv(0x64, &[octet(b"").as_slice(), attr_seq.as_slice()].concat())
}

fn entry(sam: Option<&str>, dns_host: Option<&str>) -> Vec<u8> {
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

fn done(code: u8) -> Vec<u8> {
    tlv(0x65, &[0x0a, 0x01, code, 0x04, 0x00, 0x04, 0x00])
}

/// Binds `addr`, reads one request per batch, answers with every message of
/// batch[i] spliced onto the request's message id. Fewer requests than
/// batches is fine (the unbind is not scripted).
fn spawn_fake_ldap(addr: &str, script: Vec<Vec<Vec<u8>>>) {
    let listener = TcpListener::bind(addr).unwrap();
    std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        s.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
        for batch in &script {
            let mut tag = [0u8; 1];
            if s.read_exact(&mut tag).is_err() {
                return;
            }
            assert_eq!(tag[0], 0x30);
            let len = read_ber_length(&mut s);
            let mut body = vec![0u8; len];
            s.read_exact(&mut body).unwrap();
            // the id TLV, copied verbatim (ids in tests are < 128)
            let id = vec![0x02, body[1], body[2]];
            for canned in batch {
                let mut resp = id.clone();
                resp.extend_from_slice(canned);
                if s.write_all(&tlv(0x30, &resp)).is_err() {
                    return;
                }
            }
        }
        // the unbind (if any) is read and ignored
        let mut tag = [0u8; 1];
        if s.read_exact(&mut tag).is_ok() && tag[0] == 0x30 {
            let len = read_ber_length(&mut s);
            let mut rest = vec![0u8; len];
            let _ = s.read_exact(&mut rest);
        }
    });
}

fn read_ber_length(r: &mut impl Read) -> usize {
    let mut b = [0u8; 1];
    r.read_exact(&mut b).unwrap();
    match b[0] {
        n if n < 0x80 => n as usize,
        n => {
            let count = (n & 0x7f) as usize;
            let mut bytes = [0u8; 4];
            r.read_exact(&mut bytes[4 - count..]).unwrap();
            u32::from_be_bytes(bytes) as usize
        }
    }
}

// ------------------------------------------------------------------ test

/// The whole chain, one shot: discovery → fake-nmap scan → fakes up →
/// `names` run → every surface shows the collected hostnames.
#[test]
fn names_collects_from_all_sources_through_the_binary() {
    let root = temp_root("e2e");
    let scope_path = root.join("scope.yaml");
    fs::write(&scope_path, SCOPE).unwrap();
    let perim = root.join("perim");

    // discovery seeds the registry (8 addresses, all "live" refusals)
    let out = bin()
        .args([
            "run",
            scope_path.to_str().unwrap(),
            "--out",
            perim.to_str().unwrap(),
            "--mode",
            "connect",
        ])
        .output()
        .expect("run launches");
    assert!(
        out.status.success(),
        "run failed: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // the two collector targets land in the registry through a fake-nmap
    // scan: name-based selection makes ephemeral ports usable (https on
    // .2, ldap on .3)
    let fake_nmap = root.join("fake-nmap");
    fs::write(&fake_nmap, FAKE_NMAP).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&fake_nmap, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let out = bin()
        .args([
            "scan",
            scope_path.to_str().unwrap(),
            "--out",
            perim.to_str().unwrap(),
        ])
        .env("RUSTRAWL_NMAP_BIN", &fake_nmap)
        .output()
        .expect("scan launches");
    assert!(
        out.status.success(),
        "scan failed: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let services = console(&perim, "services\nquit\n");
    assert!(services.contains("39146"), "{services}");
    assert!(services.contains("39147"), "{services}");

    // the three fakes
    let stop = Arc::new(AtomicBool::new(false));
    let resolver = spawn_fake_dns(Arc::clone(&stop));
    // the fakes listen on the service rows' own addresses — that is where
    // the collector connects (39146/39147 are this repo's test ports)
    spawn_fake_tls(
        "127.0.0.2:39146",
        "web01.corp.example.com",
        &["alt1.corp.example.com"],
    );
    spawn_fake_ldap(
        "127.0.0.3:39147",
        vec![
            vec![bind_ok()],
            vec![rootdse_entry("DC=corp,DC=example,DC=com"), done(0)],
            vec![
                entry(Some("DC02$"), Some("dc02.corp.example.com")),
                entry(Some("SRV04$"), Some("srv04.corp.example.com")),
                done(0),
            ],
        ],
    );

    // the run: TLS 39146 on .2 (https by name), LDAP 39147 on .3 (ldap by
    // name) — both service rows come from the fake-nmap scan above
    let out = bin()
        .args([
            "names",
            "--out",
            perim.to_str().unwrap(),
            "--dns",
            &format!("127.0.0.1:{}", resolver.port()),
            "--zone",
            "corp.example.com",
            "--timeout",
            "2",
        ])
        .output()
        .expect("names launches");
    assert!(
        out.status.success(),
        "names failed: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    stop.store(true, Ordering::SeqCst);

    // 1) the host cards carry every source, nothing from the stale or
    // foreign shapes; the classifier's verdict rides on the .2 card
    let sheets = console(&perim, "hosts -i 127.0.0.2\nhosts -i 127.0.0.3\nquit\n");
    for (name, source) in [
        ("dc01.corp.example.com", "dns-ptr"),
        ("srv01.corp.example.com", "dns-axfr"),
        ("web01.corp.example.com", "tls"),
        ("alt1.corp.example.com", "tls"),
        ("dc02.corp.example.com", "ldap"),
        ("dc02$", "ldap-sam"),
        ("srv03.corp.example.com", "dns-ptr"),
        ("srv04.corp.example.com", "ldap"),
        ("srv04$", "ldap-sam"),
    ] {
        assert!(
            sheets.contains(&format!("  name\t{name}\t{source}")),
            "missing {name:?} ({source}) in:\n{sheets}"
        );
    }
    assert!(
        !sheets.contains("foreign"),
        "the AXFR foreign address never lands in the registry:\n{sheets}"
    );

    // 1b) the names run re-ran the classifier over every host it touched.
    // Names follow their A-verified address: dc01 (PTR) and the dc02
    // machine accounts both landed on .2 — a dc by name. .3 keeps srv03 +
    // srv04 (no stem matches, and the OpenLDAP banner is no dc evidence):
    // honestly untyped, absence rather than a stored guess.
    let sheet2 = console(&perim, "hosts -i 127.0.0.2\nquit\n");
    assert!(
        sheet2.contains("  type\tdc ("),
        "the host card carries the type line:\n{sheet2}"
    );
    let sheet3 = console(&perim, "hosts -i 127.0.0.3\nquit\n");
    assert!(
        !sheet3.contains("  type\t"),
        "the srv-stemmed host stays untyped:\n{sheet3}"
    );

    // 3) the web API carries the names, overview and sheet alike
    let mut child = bin()
        .args([
            "db",
            "--out",
            perim.to_str().unwrap(),
            "--web",
            "--port",
            "0",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("dashboard launches");
    let stderr = child.stderr.take().expect("stderr piped");
    let mut banner = String::new();
    std::io::BufReader::new(stderr)
        .read_line(&mut banner)
        .expect("banner line");
    let port: u16 = banner
        .trim_start_matches("# dashboard: http://")
        .trim_end_matches(
            "/ - writes: triage, types, bookmark, pwned, tags, notes, screenshots, manual rescans (one host, a list or a range); exports: /api/export/*; ^C stops the server\n",
        )
        .rsplit(':')
        .next()
        .and_then(|p| p.parse().ok())
        .unwrap_or_else(|| panic!("no dashboard banner with a port in: {banner:?}"));
    let (status, page) = get(port, "/");
    assert_eq!(status, 200);
    for key in [
        "{ key: \"names\", label: \"names\"", // the hosts-table column
        "case \"name\": case \"hostname\":",  // the hostMatcher field
        "no hostname collected",              // the empty detail section
    ] {
        assert!(page.contains(key), "page contract: {key} missing");
    }
    let (status, body) = get(port, "/api/hosts");
    assert_eq!(status, 200);
    assert!(
        body.contains("dc01.corp.example.com") && body.contains("srv04$"),
        "the overview carries the names: {body}"
    );
    let (status, body) = get(port, "/api/host/127.0.0.2");
    assert_eq!(status, 200);
    assert!(
        body.contains("\"source\":\"dns-ptr\"")
            && body.contains("\"source\":\"tls\"")
            && body.contains("\"source\":\"ldap\""),
        "the sheet names carry their sources: {body}"
    );
    let _ = child.kill();
    let _ = child.wait();

    // 4) names.log: the whole trail in the newest names_ run directory
    let mut runs: Vec<_> = fs::read_dir(perim.join("runs"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with("names_"))
                .unwrap_or(false)
        })
        .collect();
    runs.sort();
    let log = fs::read_to_string(runs.last().expect("a names_ run dir").join("names.log"))
        .expect("names.log exists");
    for line in [
        "ptr 127.0.0.2 dc01.corp.example.com (verified)",
        "ptr 127.0.0.3 srv03.corp.example.com (verified)",
        "axfr corp.example.com via",
        "name foreign.corp.example.com for 10.99.0.5 (dns-axfr) - not a known asset, log-only",
        "tls 127.0.0.2:39146: cn=web01.corp.example.com san=[alt1.corp.example.com]",
        "ldap 127.0.0.3:39147: root DC=corp,DC=example,DC=com; 2 computer(s)",
    ] {
        assert!(log.contains(line), "missing {line:?} in:\n{log}");
    }

    fs::remove_dir_all(&root).ok();
}

/// A batch console session: `db --out perim` with the script piped in.
/// Returns stdout; a nonzero exit fails the test.
fn console(perim: &std::path::Path, script: &str) -> String {
    let mut child = bin()
        .arg("db")
        .arg("--out")
        .arg(perim.to_str().unwrap())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("db console launches");
    child
        .stdin
        .take()
        .expect("stdin piped")
        .write_all(script.as_bytes())
        .unwrap();
    let out = child.wait_with_output().expect("console drains");
    assert!(
        out.status.success(),
        "console session failed: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// One HTTP GET over a fresh TcpStream; returns (status, body).
fn get(port: u16, path: &str) -> (u16, String) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("server accepts");
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).expect("response drains");
    let text = String::from_utf8_lossy(&buf).into_owned();
    let status: u16 = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .expect("a status line");
    let body = text.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    (status, body)
}
