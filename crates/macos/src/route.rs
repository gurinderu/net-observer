//! Persistent PF_ROUTE socket monitor: the real [`EventSource`] behind the
//! `route` collector.
//!
//! [`PfRouteSource::open`] opens a raw routing socket
//! (`socket(AF_ROUTE, SOCK_RAW, 0)`) and *holds it for the life of the source* —
//! the "persistent PF_ROUTE socket" engineering win, unlike the shell
//! `route -n monitor` or sing-tun's darwin monitor, which reopen a socket per
//! message and miss events. Each [`EventSource::next`] does one blocking
//! `read(2)` and parses the leading `rt_msghdr`/`if_msghdr`/`ifa_msghdr` message
//! type into a [`RouteEvent`].
//!
//! The blocking read means `next()` must be driven on the daemon's blocking
//! pool. Message *parsing* (`parse_rtm`) is pure and unit-tested; the raw socket
//! read path is verified manually.

use std::ffi::CStr;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use collector_core::EventSource;
use types::{RouteEvent, Sample, now_us};

/// Size of the read buffer for one routing message. Route/interface messages are
/// well under 2 KiB; a short read simply yields a smaller slice.
const READ_BUF: usize = 2048;

/// A persistent PF_ROUTE socket. Owns the file descriptor for its whole life
/// (closed on drop via [`OwnedFd`]).
pub struct PfRouteSource {
    fd: OwnedFd,
    buf: Vec<u8>,
}

impl PfRouteSource {
    /// Open a raw routing socket (`socket(AF_ROUTE, SOCK_RAW, 0)`).
    ///
    /// # Errors
    /// Returns the OS error if the socket cannot be opened (used by the
    /// collector's readiness check).
    pub fn open() -> io::Result<Self> {
        // SAFETY: `socket` is called with valid domain/type constants and no
        // pointers; it returns a fresh fd (>= 0) or -1 on error.
        let raw = unsafe { libc::socket(libc::AF_ROUTE, libc::SOCK_RAW, 0) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `raw` is a fresh, valid, exclusively-owned fd returned by
        // `socket`; `OwnedFd` takes over closing it.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        Ok(Self {
            fd,
            buf: vec![0u8; READ_BUF],
        })
    }
}

impl EventSource for PfRouteSource {
    fn next(&mut self) -> Option<Vec<Sample>> {
        loop {
            // SAFETY: `read` is passed our live socket fd and a pointer into our
            // owned buffer with its exact length; it writes at most that many
            // bytes and returns the count read, 0 on EOF, or -1 on error.
            let n = unsafe {
                libc::read(
                    self.fd.as_raw_fd(),
                    self.buf.as_mut_ptr().cast::<libc::c_void>(),
                    self.buf.len(),
                )
            };
            if n <= 0 {
                // Error or EOF on the routing socket ends the stream; the daemon
                // logs the gap and may reopen. Absence of the signal is itself
                // diagnostic.
                return None;
            }
            #[allow(clippy::cast_sign_loss)] // guarded by `n <= 0` above
            let n = n as usize;
            if let Some(event) = route_event_from(&self.buf[..n]) {
                return Some(vec![Sample::Route(event)]);
            }
            // A message type we do not translate — keep blocking for the next.
        }
    }
}

/// Build a [`RouteEvent`] from one raw routing message, or `None` for message
/// types we do not translate. Timestamps at receive time.
fn route_event_from(buf: &[u8]) -> Option<RouteEvent> {
    let rtm = parse_rtm(buf)?;
    Some(RouteEvent {
        ts_us: now_us(),
        kind: rtm.kind.to_string(),
        iface: if_name(rtm.index),
        detail: rtm.type_name.to_string(),
    })
}

/// The fields we extract from a routing-socket message header.
#[derive(Debug, PartialEq, Eq)]
struct Rtm {
    /// Coarse category recorded in [`RouteEvent::kind`]: `"iface"`, `"addr"`, or `"route"`.
    kind: &'static str,
    /// Interface index carried by the message (0 if none / not applicable).
    index: u16,
    /// The concrete `RTM_*` message-type name recorded in [`RouteEvent::detail`].
    type_name: &'static str,
}

/// Parse the leading routing-message header, mapping its `rtm_type` to a
/// [`Rtm`]. The interface-index offset differs per message shape:
/// `if_msghdr` (RTM_IFINFO) carries `ifm_index` at byte 12, while `ifa_msghdr`
/// (RTM_*ADDR) and `rt_msghdr` (RTM_ADD/DELETE/CHANGE) carry their index at
/// byte 4. All multi-byte fields are host-endian (the kernel writes native).
///
/// Returns `None` for a truncated header or an untranslated message type.
fn parse_rtm(buf: &[u8]) -> Option<Rtm> {
    // rt_msghdr: rtm_msglen(u16) rtm_version(u8) rtm_type(u8) ...
    let rtm_type = i32::from(*buf.get(3)?);
    let (kind, index, type_name) = match rtm_type {
        libc::RTM_IFINFO => ("iface", read_u16(buf, 12)?, "RTM_IFINFO"),
        libc::RTM_NEWADDR => ("addr", read_u16(buf, 4)?, "RTM_NEWADDR"),
        libc::RTM_DELADDR => ("addr", read_u16(buf, 4)?, "RTM_DELADDR"),
        libc::RTM_ADD => ("route", read_u16(buf, 4)?, "RTM_ADD"),
        libc::RTM_DELETE => ("route", read_u16(buf, 4)?, "RTM_DELETE"),
        libc::RTM_CHANGE => ("route", read_u16(buf, 4)?, "RTM_CHANGE"),
        _ => return None,
    };
    Some(Rtm {
        kind,
        index,
        type_name,
    })
}

/// Read a host-endian `u16` at byte offset `off`, or `None` if out of bounds.
fn read_u16(buf: &[u8], off: usize) -> Option<u16> {
    let bytes = buf.get(off..off + 2)?;
    Some(u16::from_ne_bytes([bytes[0], bytes[1]]))
}

/// Resolve an interface index to its name via `if_indextoname`, or `None` for
/// index 0 / an unknown index.
fn if_name(index: u16) -> Option<String> {
    if index == 0 {
        return None;
    }
    let mut buf = [0u8; libc::IF_NAMESIZE];
    // SAFETY: `if_indextoname` writes a NUL-terminated name of at most
    // `IF_NAMESIZE` bytes into `buf`, returning `buf`'s pointer on success or
    // NULL on failure.
    let ret = unsafe { libc::if_indextoname(libc::c_uint::from(index), buf.as_mut_ptr().cast()) };
    if ret.is_null() {
        return None;
    }
    // SAFETY: on success `buf` holds a NUL-terminated C string within its bounds.
    let cstr = unsafe { CStr::from_ptr(buf.as_ptr().cast()) };
    cstr.to_str().ok().map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal routing-message buffer: `rtm_type` at byte 3 and a `u16`
    /// interface index written host-endian at `index_off`.
    fn msg(rtm_type: i32, index: u16, index_off: usize) -> Vec<u8> {
        let mut buf = vec![0u8; 32];
        buf[3] = rtm_type as u8;
        let idx = index.to_ne_bytes();
        buf[index_off] = idx[0];
        buf[index_off + 1] = idx[1];
        buf
    }

    #[test]
    fn parses_ifinfo_index_at_byte_12() {
        let buf = msg(libc::RTM_IFINFO, 7, 12);
        assert_eq!(
            parse_rtm(&buf),
            Some(Rtm {
                kind: "iface",
                index: 7,
                type_name: "RTM_IFINFO",
            })
        );
    }

    #[test]
    fn parses_newaddr_and_deladdr_index_at_byte_4() {
        assert_eq!(
            parse_rtm(&msg(libc::RTM_NEWADDR, 3, 4)),
            Some(Rtm {
                kind: "addr",
                index: 3,
                type_name: "RTM_NEWADDR",
            })
        );
        assert_eq!(
            parse_rtm(&msg(libc::RTM_DELADDR, 3, 4)).map(|r| r.type_name),
            Some("RTM_DELADDR")
        );
    }

    #[test]
    fn parses_route_add_delete_change_as_route_kind() {
        for (ty, name) in [
            (libc::RTM_ADD, "RTM_ADD"),
            (libc::RTM_DELETE, "RTM_DELETE"),
            (libc::RTM_CHANGE, "RTM_CHANGE"),
        ] {
            let rtm = parse_rtm(&msg(ty, 1, 4)).expect("route message parses");
            assert_eq!(rtm.kind, "route");
            assert_eq!(rtm.type_name, name);
            assert_eq!(rtm.index, 1);
        }
    }

    #[test]
    fn unknown_message_type_is_none() {
        // 0xff is not one of the translated RTM_* types.
        assert_eq!(parse_rtm(&msg(0xff, 1, 4)), None);
    }

    #[test]
    fn truncated_header_is_none() {
        assert_eq!(parse_rtm(&[0u8; 3]), None);
    }

    #[test]
    fn read_u16_out_of_bounds_is_none() {
        assert_eq!(read_u16(&[0u8; 5], 4), None);
        assert_eq!(read_u16(&[1u8, 0], 0), Some(1));
    }

    #[test]
    fn index_zero_resolves_to_no_iface() {
        assert_eq!(if_name(0), None);
    }
}
