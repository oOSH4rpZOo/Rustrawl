//! Raw receive socket: big SO_RCVBUF, classic BPF reply filter, poll-based
//! waiting, non-blocking drains. Kernel drop detection via SO_RXQ_OVERFLOW —
//! a silent drop would masquerade hosts as dead (a miss is not a verdict).

use std::io;

use crate::discovery::bpf;
use crate::discovery::packet;

pub struct Receiver {
    fd: libc::c_int,
    buf: Vec<u8>,
}

impl Receiver {
    /// Opens the raw receive socket, bound to `iface` when given — replies
    /// arriving through any other interface never reach this queue.
    pub fn open(rcvbuf_bytes: i32, iface: Option<&str>) -> io::Result<Self> {
        // SAFETY: socket/setsockopt syscalls with fixed constants; fd closed
        // on drop and on every error path below.
        unsafe {
            let fd = libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_TCP);
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &rcvbuf_bytes as *const _ as *const libc::c_void,
                std::mem::size_of::<i32>() as libc::socklen_t,
            );
            if let Some(name) = iface {
                if let Err(e) = super::sender::bind_to_device(fd, name) {
                    libc::close(fd);
                    return Err(e);
                }
            }
            bpf::attach(fd).map_err(|e| {
                libc::close(fd);
                io::Error::other(e.to_string())
            })?;
            Ok(Self {
                fd,
                buf: vec![0u8; 65_536],
            })
        }
    }

    /// Reads back the SO_RCVBUF the kernel actually granted.
    pub fn actual_rcvbuf(&self) -> i32 {
        let mut v: i32 = 0;
        let mut len = std::mem::size_of::<i32>() as libc::socklen_t;
        // SAFETY: standard getsockopt with a properly sized out parameter.
        unsafe {
            libc::getsockopt(
                self.fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &mut v as *mut _ as *mut libc::c_void,
                &mut len,
            );
        }
        v
    }

    /// Did the receive queue overflow since the last check?
    pub fn took_overflow(&self) -> bool {
        let mut v: i32 = 0;
        let mut len = std::mem::size_of::<i32>() as libc::socklen_t;
        const SO_RXQ_OVERFLOW: libc::c_int = 40;
        // SAFETY: standard getsockopt with a properly sized out parameter.
        unsafe {
            libc::getsockopt(
                self.fd,
                libc::SOL_SOCKET,
                SO_RXQ_OVERFLOW,
                &mut v as *mut _ as *mut libc::c_void,
                &mut len,
            );
        }
        v != 0
    }

    /// Blocks up to `timeout_ms` waiting for data.
    pub fn wait(&self, timeout_ms: i32) {
        // SAFETY: poll on a live fd with a single-entry array.
        unsafe {
            let mut fds = [libc::pollfd {
                fd: self.fd,
                events: libc::POLLIN,
                revents: 0,
            }];
            libc::poll(fds.as_mut_ptr(), 1, timeout_ms);
        }
    }

    /// Drains every pending reply, calling `f` on each. Returns the count.
    pub fn drain(&mut self, mut f: impl FnMut(packet::Reply)) -> usize {
        let mut n = 0;
        loop {
            // SAFETY: recvfrom into our owned buffer; src sockaddr is parsed
            // only when the kernel reported a real datagram.
            unsafe {
                let mut sa: libc::sockaddr_in = std::mem::zeroed();
                let mut sa_len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
                let got = libc::recvfrom(
                    self.fd,
                    self.buf.as_mut_ptr() as *mut libc::c_void,
                    self.buf.len(),
                    libc::MSG_DONTWAIT,
                    &mut sa as *mut libc::sockaddr_in as *mut libc::sockaddr,
                    &mut sa_len,
                );
                if got <= 0 {
                    break;
                }
                if let Some(rep) = packet::parse_reply(&self.buf[..got as usize]) {
                    f(rep);
                    n += 1;
                }
            }
        }
        n
    }
}

impl Drop for Receiver {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}
