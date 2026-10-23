//! Classic BPF filter attached to the raw receive socket (SO_ATTACH_FILTER).
//! Keeps the kernel from copying unrelated traffic into userspace, and avoids
//! libpcap entirely — the whole engine stays musl-friendly.
//!
//! Accept: TCP flags byte (tcp[13]) such that `flags & (SYN|ACK|RST)` is
//! `SYN|ACK` (0x12), `RST` (0x04) or `RST|ACK` (0x14). Everything the engine
//! can decode is a SYN-ACK or a RST+ACK; a bare SYN (our own probes reflected
//! by some middlebox) must not match.

use anyhow::{anyhow, Result};
use libc::{sock_filter, sock_fprog};

const BPF_LD: u16 = 0x00;
const BPF_LDX: u16 = 0x01;
const BPF_ALU: u16 = 0x04;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;
const BPF_B: u16 = 0x10;
const BPF_K: u16 = 0x00;
const BPF_IND: u16 = 0x40;
const BPF_MSH: u16 = 0xA0;
const BPF_AND: u16 = 0x50;
const BPF_JEQ: u16 = 0x10;

const SO_ATTACH_FILTER: libc::c_int = 26;

fn insn(code: u16, jt: u8, jf: u8, k: u32) -> sock_filter {
    sock_filter { code, jt, jf, k }
}

/// Attaches the reply filter to `fd`. The socket keeps receiving only
/// matching packets afterwards.
pub fn attach(fd: libc::c_int) -> Result<()> {
    // 0: X = 4*(ip[0] & 0xf)        — IP header length
    // 1: A = tcp[X + 13]            — flags byte
    // 2: A &= SYN|ACK|RST
    // 3-5: accept SYN|ACK, RST, RST|ACK
    // 6: reject; 7: accept (keep the full packet)
    let prog = [
        insn(BPF_LDX | BPF_B | BPF_MSH, 0, 0, 0),
        insn(BPF_LD | BPF_B | BPF_IND, 0, 0, 13),
        insn(BPF_ALU | BPF_AND | BPF_K, 0, 0, 0x16),
        insn(BPF_JMP | BPF_JEQ | BPF_K, 3, 0, 0x12),
        insn(BPF_JMP | BPF_JEQ | BPF_K, 2, 0, 0x04),
        insn(BPF_JMP | BPF_JEQ | BPF_K, 1, 0, 0x14),
        insn(BPF_RET | BPF_K, 0, 0, 0),        // reject
        insn(BPF_RET | BPF_K, 0, 0, u32::MAX), // accept, full packet
    ];
    let fprog = sock_fprog {
        len: prog.len() as u16,
        filter: prog.as_ptr() as *mut sock_filter,
    };
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            SO_ATTACH_FILTER,
            &fprog as *const sock_fprog as *const libc::c_void,
            std::mem::size_of::<sock_fprog>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(anyhow!(
            "SO_ATTACH_FILTER failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}
