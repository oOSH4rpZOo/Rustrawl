//! Asset-type classification from evidence the registry already holds —
//! zero new probes on the wire. A host's open services (port, nmap service
//! name, banner/version) and collected hostnames go through an ordered rule
//! table, first match wins, and the reasons behind the winning rule become
//! the stored `basis` string. No match means unknown: absence of a row, never
//! a stored guess. Rows the operator wrote by hand (`source = 'manual'`)
//! are never touched — the shared `reclassify_host` checks before writing
//! and the flush upsert carries the same guard.

use std::net::Ipv4Addr;

use super::db::Db;

/// Guesses a host's type. `entries` is its open services as
/// (port, service name, banner/version); `names` its collected hostnames.
/// Returns `(kind, basis)` — the reasons, "; "-joined — or `None`.
pub(crate) fn classify(
    entries: &[(u16, String, String)],
    names: &[String],
) -> Option<(String, String)> {
    // dc: the domain controller signature. Kerberos (88) plus LDAP (389)
    // together, a Global Catalog port on its own, a machine account named
    // like a DC, or an AD/Kerberos banner.
    let mut reasons: Vec<String> = Vec::new();
    let has = |p: u16| entries.iter().any(|e| e.0 == p);
    if has(88) && has(389) {
        reasons.push("ports 88+389".to_string());
    }
    if has(3268) {
        reasons.push("port 3268".to_string());
    }
    for n in names {
        let l = first_label(n);
        if is_named(&l, "dc") || is_named(&l, "ad") {
            reasons.push(format!("name {n}"));
        }
    }
    for (_, _, v) in entries {
        let u = v.to_ascii_lowercase();
        if u.contains("active directory") || u.contains("kerberos") {
            reasons.push(format!("banner {v}"));
        }
    }
    if !reasons.is_empty() {
        return Some(("dc".to_string(), reasons.join("; ")));
    }

    // printer: JetDirect/IPP/LPD ports, a printer-vendor banner, a name
    // named like a print queue host.
    let mut reasons: Vec<String> = Vec::new();
    for p in [9100, 631, 515] {
        if has(p) {
            reasons.push(format!("port {p}"));
        }
    }
    for (_, _, v) in entries {
        let u = v.to_ascii_lowercase();
        if ["jetdirect", "ricoh", "brother", "canon", "hp ", "lexmark"]
            .iter()
            .any(|k| u.contains(k))
        {
            reasons.push(format!("banner {v}"));
        }
    }
    for n in names {
        let l = first_label(n);
        if is_named(&l, "printer") || is_named(&l, "prn") {
            reasons.push(format!("name {n}"));
        }
    }
    if !reasons.is_empty() {
        return Some(("printer".to_string(), reasons.join("; ")));
    }

    // network: telnet or BGP speak switches/routers more than anything
    // else, alongside Cisco banners and the sw/rt/gw/ap/firewall names.
    let mut reasons: Vec<String> = Vec::new();
    if has(23) {
        reasons.push("port 23 (telnet)".to_string());
    }
    if has(179) {
        reasons.push("port 179 (bgp)".to_string());
    }
    for (_, _, v) in entries {
        if v.to_ascii_lowercase().contains("cisco") {
            reasons.push(format!("banner {v}"));
        }
    }
    for n in names {
        let l = first_label(n);
        if ["sw", "rt", "gw", "ap"].iter().any(|s| is_named(&l, s))
            || l.starts_with("firewall-")
            || l.starts_with("fw-")
        {
            reasons.push(format!("name {n}"));
        }
    }
    if !reasons.is_empty() {
        return Some(("network".to_string(), reasons.join("; ")));
    }

    // windows: SMB or RDP is the windows workstation/server signature; the
    // microsoft-ish service names and banners only pad the basis.
    let mut reasons: Vec<String> = Vec::new();
    if has(445) {
        reasons.push("port 445 (smb)".to_string());
    }
    if has(3389) {
        reasons.push("port 3389 (rdp)".to_string());
    }
    if !reasons.is_empty() {
        for (p, name, v) in entries {
            if *p == 445 || *p == 3389 {
                continue; // the ports ARE the reason; extra banners only pad
            }
            let u = format!("{name} {v}").to_ascii_lowercase();
            if u.contains("microsoft") || u.contains("msrpc") || u.contains("windows") {
                reasons.push(format!("banner {name} {v}"));
            }
        }
        return Some(("windows".to_string(), reasons.join("; ")));
    }

    // unix: OpenSSH or Samba. Any other SSH daemon on 22 is unix-flavored
    // too (the basis says which banner was seen).
    let mut reasons: Vec<String> = Vec::new();
    for (p, name, v) in entries {
        if *p == 22 {
            let u = format!("{name} {v}").to_ascii_lowercase();
            if u.contains("openssh") {
                reasons.push("port 22 (OpenSSH)".to_string());
            } else {
                reasons.push("port 22 (ssh)".to_string());
            }
        }
        if v.to_ascii_lowercase().contains("samba") {
            reasons.push(format!("banner {v} (Samba)"));
        }
    }
    if !reasons.is_empty() {
        return Some(("unix".to_string(), reasons.join("; ")));
    }

    None
}

/// The host's first name label, lowercased — "DC01.corp.local" is "dc01",
/// the LDAP machine account "DC02$" is "dc02".
fn first_label(name: &str) -> String {
    let l = name.split('.').next().unwrap_or(name);
    let l = l.strip_suffix('$').unwrap_or(l);
    l.to_ascii_lowercase()
}

/// Does a name label start with `stem` followed by a dash or a digit —
/// the machine-naming conventions ("dc01", "sw-2", "rt1") without catching
/// ordinary words ("dcweb", "switchroom")?
fn is_named(label: &str, stem: &str) -> bool {
    label
        .strip_prefix(stem)
        .is_some_and(|rest| rest.starts_with('-') || rest.starts_with(|c: char| c.is_ascii_digit()))
}

/// Re-runs the classifier for one host from the registry's own evidence and
/// buffers the result on `db` (the caller flushes): writes a heuristic row
/// when the evidence points somewhere, retracts a stale heuristic row when
/// it no longer does. A manual row stops everything — the operator's word
/// is final. Returns whether the buffered state changed.
pub(crate) fn reclassify_host(db: &mut Db, ip: Ipv4Addr) -> bool {
    if matches!(
        db.type_for_ip(ip),
        Ok(Some((_, _, source))) if source == "manual"
    ) {
        return false;
    }
    let mut entries: Vec<(u16, String, String)> = Vec::new();
    let _ = db.services_for_ip(ip, &mut |p, n, v| {
        entries.push((p, n.to_string(), v.to_string()))
    });
    let mut names: Vec<String> = Vec::new();
    let _ = db.names_for_ip(ip, &mut |n, _, _, _| names.push(n.to_string()));
    match classify(&entries, &names) {
        Some((kind, basis)) => {
            if matches!(&db.type_for_ip(ip), Ok(Some((k, b, _))) if *k == kind && *b == basis) {
                return false; // same row already stored — don't churn `updated`
            }
            db.record_asset_type(ip, &kind, &basis, "heuristic");
            true
        }
        None => {
            if matches!(db.type_for_ip(ip), Ok(Some(_))) {
                db.clear_asset_type(ip);
                return true;
            }
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ent(port: u16, name: &str, ver: &str) -> (u16, String, String) {
        (port, name.to_string(), ver.to_string())
    }

    #[test]
    fn name_stems_match_machine_conventions_only() {
        assert!(is_named("dc01", "dc"));
        assert!(is_named("dc-01", "dc"));
        assert!(is_named("sw2", "sw"));
        assert!(is_named("firewall-1", "firewall"));
        // ordinary words sharing the stem stay untyped
        assert!(!is_named("dcweb", "dc"));
        assert!(!is_named("admin01", "ad"));
        assert!(!is_named("sw", "sw")); // no suffix, no match
        assert!(!is_named("backup", "ap"));
        // the LDAP machine account's trailing dollar trims off
        assert_eq!(first_label("DC02$.corp.example.com"), "dc02");
    }

    #[test]
    fn dc_beats_windows_and_smb_alone_is_windows() {
        // A DC carries 445 too — the dc rule wins and the basis lists every
        // reason that fired.
        let (kind, basis) = classify(
            &[
                ent(88, "kerberos-sec", "Microsoft Windows Kerberos"),
                ent(389, "ldap", "Active Directory LDAP"),
                ent(445, "microsoft-ds", ""),
                ent(3389, "ms-wbt-server", ""),
            ],
            &["dc01.corp.local".to_string()],
        )
        .unwrap();
        assert_eq!(kind, "dc");
        assert!(basis.contains("ports 88+389"), "{basis}");
        assert!(basis.contains("name dc01.corp.local"), "{basis}");
        assert!(
            basis.contains("banner Microsoft Windows Kerberos"),
            "{basis}"
        );

        // A Global Catalog port on its own is a dc.
        let (kind, basis) = classify(&[ent(3268, "ms-gc", "")], &[]).unwrap();
        assert_eq!(kind, "dc");
        assert_eq!(basis, "port 3268");

        // 445 + an unrelated Microsoft banner, no AD evidence: windows.
        let (kind, basis) = classify(
            &[
                ent(445, "microsoft-ds", ""),
                ent(135, "msrpc", "Microsoft RPC"),
            ],
            &[],
        )
        .unwrap();
        assert_eq!(kind, "windows");
        assert_eq!(
            basis, "port 445 (smb); banner msrpc Microsoft RPC",
            "the 445 entry itself is not padded into the basis twice"
        );

        // 3389 alone: windows by RDP.
        let (kind, basis) = classify(&[ent(3389, "ms-wbt-server", "")], &[]).unwrap();
        assert_eq!(kind, "windows");
        assert_eq!(basis, "port 3389 (rdp)");
    }

    #[test]
    fn printer_network_unix_rules_and_unknown() {
        // printer: the port and the vendor banner both pad the basis.
        let (kind, basis) = classify(
            &[ent(9100, "jetdirect", "HP JetDirect"), ent(80, "http", "")],
            &["prn-2.corp.local".to_string()],
        )
        .unwrap();
        assert_eq!(kind, "printer");
        assert!(basis.contains("port 9100"), "{basis}");
        assert!(basis.contains("banner HP JetDirect"), "{basis}");
        assert!(basis.contains("name prn-2.corp.local"), "{basis}");

        // network: telnet plus a Cisco banner; a sw/rt/gw name alone is
        // enough even with an ssh port open (the rule table is ordered).
        let (kind, basis) = classify(&[ent(23, "telnet", "Cisco IOS 15")], &[]).unwrap();
        assert_eq!(kind, "network");
        assert_eq!(basis, "port 23 (telnet); banner Cisco IOS 15");

        let (kind, basis) = classify(
            &[ent(22, "ssh", "OpenSSH 9.2")],
            &["gw-1.corp.local".to_string()],
        )
        .unwrap();
        assert_eq!(kind, "network", "the name rule outranks unix");
        assert_eq!(basis, "name gw-1.corp.local");

        // unix: OpenSSH; Samba speaks through any port's banner.
        let (kind, basis) = classify(&[ent(22, "ssh", "OpenSSH_9.2p1 Debian")], &[]).unwrap();
        assert_eq!(kind, "unix");
        assert_eq!(basis, "port 22 (OpenSSH)");
        let (kind, basis) = classify(&[ent(139, "netbios-ssn", "Samba smbd 4.17")], &[]).unwrap();
        assert_eq!(kind, "unix");
        assert_eq!(basis, "banner Samba smbd 4.17 (Samba)");

        // unknown: nothing in the rule table — absence, never a guess.
        assert_eq!(classify(&[ent(80, "http", "nginx 1.22")], &[]), None);
        assert_eq!(classify(&[], &["fileserver.corp.local".to_string()]), None);
        assert_eq!(classify(&[], &[]), None);
    }

    fn tmp_root(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "rustrawl-classify-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|t| t.subsec_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn reclassify_writes_flips_and_keeps_manual() {
        use crate::discovery::db::Stage;
        let root = tmp_root("rw");
        let mut db = Db::open(&root).unwrap();
        db.set_run_id("t");
        let ip: Ipv4Addr = "10.0.0.5".parse().unwrap();
        db.record_host(ip, Stage::Scan, true, 3);
        db.record_service(ip, 445, "microsoft-ds", "");
        db.record_service(ip, 135, "msrpc", "Microsoft RPC");
        db.flush().unwrap();

        // First pass writes the heuristic row.
        assert!(reclassify_host(&mut db, ip));
        db.flush().unwrap();
        assert_eq!(
            db.type_for_ip(ip).unwrap().unwrap(),
            (
                "windows".to_string(),
                "port 445 (smb); banner msrpc Microsoft RPC".to_string(),
                "heuristic".to_string()
            )
        );

        // A no-op re-run (same evidence, same row) writes nothing — `updated`
        // must not churn on every chunk.
        assert!(!reclassify_host(&mut db, ip));
        db.flush().unwrap();
        assert_eq!(db.type_for_ip(ip).unwrap().unwrap().0, "windows");

        // New evidence flips the row (Kerberos + LDAP arrive: dc).
        db.record_service(ip, 88, "kerberos-sec", "Heimdal Kerberos");
        db.record_service(ip, 389, "ldap", "");
        db.flush().unwrap();
        assert!(reclassify_host(&mut db, ip));
        db.flush().unwrap();
        assert_eq!(db.type_for_ip(ip).unwrap().unwrap().0, "dc");

        // A manual override survives every later re-run.
        db.record_asset_type(ip, "jump host", "operator said so", "manual");
        db.flush().unwrap();
        assert!(!reclassify_host(&mut db, ip));
        db.flush().unwrap();
        assert_eq!(
            db.type_for_ip(ip).unwrap().unwrap(),
            (
                "jump host".to_string(),
                "operator said so".to_string(),
                "manual".to_string()
            )
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn reclassify_retracts_stale_rows_and_the_manual_guard_holds() {
        use crate::discovery::db::Stage;
        let root = tmp_root("retract");
        let mut db = Db::open(&root).unwrap();
        db.set_run_id("t");

        // A stale heuristic row on a host with no evidence: reclassified to
        // nothing — the row is retracted, not left lying around.
        let ip: Ipv4Addr = "10.0.0.6".parse().unwrap();
        db.record_host(ip, Stage::Scan, true, 0);
        db.record_asset_type(ip, "unix", "port 22 (OpenSSH)", "heuristic");
        db.flush().unwrap();
        assert!(reclassify_host(&mut db, ip));
        db.flush().unwrap();
        assert!(
            db.type_for_ip(ip).unwrap().is_none(),
            "unknown is absence - the stale guess is gone"
        );

        // Retracting twice is a no-op (nothing left to clear).
        assert!(!reclassify_host(&mut db, ip));

        // A manual row is never retracted, not even by the clear path.
        let ip2: Ipv4Addr = "10.0.0.7".parse().unwrap();
        db.record_host(ip2, Stage::Scan, true, 0);
        db.record_asset_type(ip2, "mail", "operator said so", "manual");
        db.flush().unwrap();
        db.clear_asset_type(ip2); // a hypothetical stale buffer
        db.flush().unwrap();
        assert_eq!(db.type_for_ip(ip2).unwrap().unwrap().0, "mail");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn reclassify_host_writes_guesses_and_skips_manual_rows() {
        use crate::discovery::db::{Answer, Stage};
        let root = tmp_root("all");
        let mut db = Db::open(&root).unwrap();
        db.set_run_id("t");
        for (ip, ports) in [
            ("10.0.0.8", vec![(445u16, "microsoft-ds", "")]),
            ("10.0.0.9", vec![(22, "ssh", "OpenSSH 9.2")]),
            ("10.0.0.10", vec![]),
        ] {
            let ip: Ipv4Addr = ip.parse().unwrap();
            db.record_host(ip, Stage::Scan, true, 1);
            for (p, n, v) in ports {
                db.record_result(ip, p, Stage::Scan, Answer::Open);
                db.record_service(ip, p, n, v);
            }
        }
        let manual: Ipv4Addr = "10.0.0.11".parse().unwrap();
        db.record_host(manual, Stage::Scan, true, 1);
        db.record_asset_type(manual, "printer", "operator said so", "manual");
        db.flush().unwrap();

        for (ip, want) in [
            ("10.0.0.8", true),
            ("10.0.0.9", true),
            ("10.0.0.10", false),
            ("10.0.0.11", false),
        ] {
            let ip: Ipv4Addr = ip.parse().unwrap();
            assert_eq!(reclassify_host(&mut db, ip), want, "{ip}");
        }
        db.flush().unwrap();
        assert_eq!(
            db.type_for_ip("10.0.0.8".parse().unwrap())
                .unwrap()
                .unwrap()
                .0,
            "windows"
        );
        assert_eq!(
            db.type_for_ip("10.0.0.9".parse().unwrap())
                .unwrap()
                .unwrap()
                .0,
            "unix"
        );
        assert!(db
            .type_for_ip("10.0.0.10".parse().unwrap())
            .unwrap()
            .is_none());
        assert_eq!(db.type_for_ip(manual).unwrap().unwrap().0, "printer");
        std::fs::remove_dir_all(&root).ok();
    }
}
