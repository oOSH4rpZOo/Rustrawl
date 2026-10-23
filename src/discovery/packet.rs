//! SYN packet construction (IP + TCP headers) with pnet checksums.
//! 40 bytes fixed, no options — nothing to fragment, nothing to trim.

use std::net::Ipv4Addr;

use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::MutableIpv4Packet;
use pnet_packet::tcp::{MutableTcpPacket, TcpFlags};
use pnet_packet::Packet;

pub const SYN_LEN: usize = 40;

/// Builds a SYN from `src` to `dst:(dport,)` carrying `seq` as the probe cookie.
pub fn build_syn(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    seq: u32,
    ip_id: u16,
) -> [u8; SYN_LEN] {
    let mut buf = [0u8; SYN_LEN];
    {
        let mut ip = MutableIpv4Packet::new(&mut buf).expect("40-byte buffer");
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_total_length(SYN_LEN as u16);
        ip.set_identification(ip_id);
        ip.set_flags(0x02); // Don't Fragment
        ip.set_ttl(64);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip.set_source(src);
        ip.set_destination(dst);
    }
    {
        let mut tcp = MutableTcpPacket::new(&mut buf[20..]).expect("20-byte tail");
        tcp.set_source(sport);
        tcp.set_destination(dport);
        tcp.set_sequence(seq);
        tcp.set_acknowledgement(0);
        tcp.set_data_offset(5);
        tcp.set_flags(TcpFlags::SYN);
        tcp.set_window(1024);
        tcp.set_urgent_ptr(0);
    }
    // pnet's checksum helpers read immutable views; borrow, compute, store.
    let tcp_sum = pnet_packet::tcp::ipv4_checksum(
        &pnet_packet::tcp::TcpPacket::new(&buf[20..]).expect("20-byte tail"),
        &src,
        &dst,
    );
    MutableTcpPacket::new(&mut buf[20..])
        .expect("20-byte tail")
        .set_checksum(tcp_sum);
    // IP checksum last — it covers the header only, but write it after the
    // TCP block for a simple invariant: a finished packet is a valid packet.
    let ip_sum = pnet_packet::ipv4::checksum(
        &pnet_packet::ipv4::Ipv4Packet::new(&buf).expect("40-byte buffer"),
    );
    MutableIpv4Packet::new(&mut buf)
        .expect("40-byte buffer")
        .set_checksum(ip_sum);
    buf
}

/// Parses a reply into the fields the engine needs. Returns None for anything
/// that is not a full IPv4/TCP packet (BPF already narrowed it down).
pub fn parse_reply(buf: &[u8]) -> Option<Reply> {
    let ip = pnet_packet::ipv4::Ipv4Packet::new(buf)?;
    if ip.get_version() != 4 || ip.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
        return None;
    }
    let tcp = pnet_packet::tcp::TcpPacket::new(ip.payload())?;
    Some(Reply {
        src: ip.get_source(),
        dst: ip.get_destination(),
        sport: tcp.get_source(),
        dport: tcp.get_destination(),
        flags: tcp.get_flags(),
        ack: tcp.get_acknowledgement(),
    })
}

#[derive(Debug, Clone, Copy)]
pub struct Reply {
    pub src: Ipv4Addr,
    /// Kept for evidence/debugging; the engine only matches on src/ack/dport.
    #[allow(dead_code)]
    pub dst: Ipv4Addr,
    #[allow(dead_code)]
    pub sport: u16,
    pub dport: u16,
    pub flags: u8,
    pub ack: u32,
}

impl Reply {
    pub fn is_synack(&self) -> bool {
        self.flags & TcpFlags::SYN != 0 && self.flags & TcpFlags::ACK != 0
    }

    pub fn is_rst(&self) -> bool {
        self.flags & TcpFlags::RST != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet_packet::PacketSize;

    /// Folds 16-bit words with carries — independent of pnet's implementation.
    fn checksum(bytes: &[u8]) -> u16 {
        let mut sum = 0u32;
        for pair in bytes.chunks(2) {
            let w = u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]) as u32;
            sum += w;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }

    #[test]
    fn checksums_verify() {
        let src: Ipv4Addr = "192.168.12.44".parse().unwrap();
        let dst: Ipv4Addr = "10.44.7.9".parse().unwrap();
        let pkt = build_syn(src, dst, 40123, 443, 0xDEAD_BEEF, 7);

        // IP header: checksum field is bytes 10..12; verify over the 20 header bytes
        let mut header = pkt;
        header[10] = 0;
        header[11] = 0;
        assert_eq!(
            checksum(&header[..20]),
            u16::from_be_bytes([pkt[10], pkt[11]])
        );

        // TCP: pseudo-header + header (checksum zeroed); total length 20
        let mut sum: u32 = 0;
        for w in [src.octets(), dst.octets()] {
            sum += u16::from_be_bytes([w[0], w[1]]) as u32;
            sum += u16::from_be_bytes([w[2], w[3]]) as u32;
        }
        sum += 6u32; // proto
        sum += 20u32; // tcp length
        let mut tcp = pkt;
        tcp[36] = 0;
        tcp[37] = 0;
        for pair in tcp[20..40].chunks(2) {
            sum += u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]) as u32;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        assert_eq!(!(sum as u16), u16::from_be_bytes([pkt[36], pkt[37]]));
    }

    #[test]
    fn wire_size_and_shape() {
        let pkt = build_syn(
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            40000,
            80,
            42,
            1,
        );
        let ip = pnet_packet::ipv4::Ipv4Packet::new(&pkt).unwrap();
        assert_eq!(ip.packet_size(), SYN_LEN);
        assert_eq!(ip.get_total_length() as usize, SYN_LEN);
        let tcp = pnet_packet::tcp::TcpPacket::new(ip.payload()).unwrap();
        assert_eq!(tcp.get_flags(), TcpFlags::SYN);
        assert_eq!(tcp.get_sequence(), 42);
        assert_eq!(tcp.get_destination(), 80);
    }

    #[test]
    fn parse_reply_roundtrip() {
        let pkt = build_syn(
            "10.0.0.2".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
            443,
            40001,
            7,
            1,
        );
        let rep = parse_reply(&pkt).unwrap();
        assert_eq!(rep.src, "10.0.0.2".parse::<Ipv4Addr>().unwrap());
        assert_eq!(rep.sport, 443);
        assert!(!rep.is_synack() && !rep.is_rst()); // a bare SYN is not a live signal

        // flip the flags byte (IP 20 + TCP flag offset 13) to SYN|ACK — the
        // shape the engine looks for — and re-parse
        let mut synack = pkt;
        synack[33] = TcpFlags::SYN | TcpFlags::ACK;
        let rep = parse_reply(&synack).unwrap();
        assert!(rep.is_synack() && !rep.is_rst());
        assert_eq!(rep.dport, 40001);
        assert_eq!(rep.ack, 0);

        // garbage does not parse as a reply
        assert!(parse_reply(&[0u8; 10]).is_none());
    }
}
