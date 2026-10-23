//! Raw send socket (IP_HDRINCL) and source-address selection.
//!
//! The source IP for each target is discovered with a UDP
//! `connect()`/`getsockname()` — no packet is sent, it is a pure routing-table
//! lookup — and cached per exact destination (policy routing can pick
//! different sources inside one /24). When an interface is pinned
//! (`discovery.interface`), both the raw socket and the route lookups are
//! bound to it with SO_BINDTODEVICE: probes cannot leak through another
//! interface, and a wrong pin fails on the first route lookup instead of
//! scanning some other network.

use std::collections::HashMap;
use std::io;
use std::net::Ipv4Addr;

use super::bpf;
use crate::discovery::packet;

pub struct Sender {
    fd: libc::c_int,
    iface: Option<String>,
    ip_id: u16,
    src_cache: HashMap<u32, Ipv4Addr>,
}

impl Sender {
    /// Opens the raw socket with IP_HDRINCL, bound to `iface` when given.
    /// Returns `io::Error` (EPERM/EACCES) when the process lacks CAP_NET_RAW —
    /// the caller falls back to connect mode.
    pub fn open(iface: Option<&str>) -> io::Result<Self> {
        // SAFETY: plain socket syscall with fixed constants; fd ownership moves
        // into Self and is closed on drop (every error path below closes it).
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_TCP) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let one: libc::c_int = 1;
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_HDRINCL,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            let err = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(err);
        }
        if let Some(name) = iface {
            if let Err(e) = bind_to_device(fd, name) {
                unsafe { libc::close(fd) };
                return Err(e);
            }
        }
        // The kernel also clones matching inbound TCP packets onto a raw send
        // socket; the flags filter keeps that never-read queue from filling
        // with the host's unrelated traffic (it would overflow and silently
        // drop forever).
        if let Err(e) = bpf::attach(fd) {
            unsafe { libc::close(fd) };
            return Err(io::Error::other(e.to_string()));
        }
        Ok(Self {
            fd,
            iface: iface.map(str::to_owned),
            ip_id: 0x4000,
            src_cache: HashMap::new(),
        })
    }

    /// The local address the routing table would pick for `dst`, cached per
    /// exact address. With a pinned interface the lookup is constrained to
    /// that device, so an unroutable perimeter fails here on first use.
    pub fn source_ip_for(&mut self, dst: Ipv4Addr) -> io::Result<Ipv4Addr> {
        let key = u32::from(dst);
        if let Some(&src) = self.src_cache.get(&key) {
            return Ok(src);
        }
        let src = udp_route_source(dst, self.iface.as_deref())?;
        self.src_cache.insert(key, src);
        Ok(src)
    }

    pub fn send_syn(
        &mut self,
        src: Ipv4Addr,
        dst: Ipv4Addr,
        sport: u16,
        dport: u16,
        seq: u32,
    ) -> io::Result<()> {
        self.ip_id = self.ip_id.wrapping_add(1);
        let pkt = packet::build_syn(src, dst, sport, dport, seq, self.ip_id);
        let sa = sockaddr(dst, 0);
        let n = unsafe {
            libc::sendto(
                self.fd,
                pkt.as_ptr() as *const libc::c_void,
                pkt.len(),
                0,
                &sa as *const libc::sockaddr_in as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

impl Drop for Sender {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

/// SO_BINDTODEVICE on a raw socket: every packet leaves through that
/// interface and nothing else is seen. Name must fit IFNAMSIZ including NUL.
pub(crate) fn bind_to_device(fd: libc::c_int, iface: &str) -> io::Result<()> {
    if iface.len() >= libc::IFNAMSIZ {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "interface name \"{iface}\" is too long ({} byte limit)",
                libc::IFNAMSIZ - 1
            ),
        ));
    }
    let mut name = [0u8; libc::IFNAMSIZ];
    name[..iface.len()].copy_from_slice(iface.as_bytes());
    // SAFETY: setsockopt with an IFNAMSIZ-sized option buffer (the documented
    // shape for SO_BINDTODEVICE); fd is owned by the caller.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            name.as_ptr() as *const libc::c_void,
            libc::IFNAMSIZ as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Non-sending route lookup: UDP connect only fills in the routing decision.
fn udp_route_source(dst: Ipv4Addr, iface: Option<&str>) -> io::Result<Ipv4Addr> {
    // SAFETY: socket/connect/getsockname on a throwaway UDP socket, closed on
    // every path before returning.
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        if let Some(name) = iface {
            if let Err(e) = bind_to_device(fd, name) {
                libc::close(fd);
                return Err(e);
            }
        }
        let sa = sockaddr(dst, 9); // discard port — never actually sent to
        let rc = libc::connect(
            fd,
            &sa as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        );
        if rc != 0 {
            let err = io::Error::last_os_error();
            libc::close(fd);
            return Err(err);
        }
        let mut out: libc::sockaddr_in = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let rc = libc::getsockname(
            fd,
            &mut out as *mut libc::sockaddr_in as *mut libc::sockaddr,
            &mut len,
        );
        libc::close(fd);
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Ipv4Addr::from(u32::from_be(out.sin_addr.s_addr)))
    }
}

fn sockaddr(ip: Ipv4Addr, port: u16) -> libc::sockaddr_in {
    libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: port.to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from(ip).to_be(),
        },
        sin_zero: [0; 8],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Loopback-only: the route lookup resolves through lo with no pin, and a
    /// bogus pin must fail rather than silently route elsewhere.
    #[test]
    fn route_lookup_respects_pin() {
        let ip: Ipv4Addr = "127.0.0.1".parse().unwrap();
        let src = udp_route_source(ip, None).expect("loopback always routable");
        assert_eq!(src, ip);
        let err = udp_route_source(ip, Some("definitely-not-an-iface0")).unwrap_err();
        assert_ne!(err.raw_os_error(), Some(0));
    }
}
