//! Network reachability probes: ICMP echo (`surge-ping`) and interface-bound
//! TCP connect (`socket2` + macOS `IP_BOUND_IF`).
//!
//! Both are synchronous and blocking — call them from a `spawn_blocking`
//! context. Raw ICMP and, on some networks, bound TCP need elevated
//! privileges, so failures degrade to an unreachable [`PingOutcome`] rather
//! than panicking ("absence is a signal").

use std::ffi::CString;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::os::fd::{AsRawFd, RawFd};
use std::time::{Duration, Instant};

use collectors::probes::{PingOutcome, Pinger, TcpProber};
use socket2::{Domain, Protocol, Socket, Type};
use surge_ping::{Client, Config, ICMP, PingIdentifier, PingSequence};

/// Per-probe deadline. Kept short: a stalled probe is itself a signal.
const PROBE_TIMEOUT: Duration = Duration::from_secs(1);

/// ICMP echo pinger backed by `surge-ping`.
///
/// Builds a tiny current-thread tokio runtime per call and blocks on a single
/// echo request, so it must be invoked from a blocking context (never from
/// inside an async runtime worker).
#[derive(Debug, Default, Clone, Copy)]
pub struct IcmpPinger;

impl IcmpPinger {
    /// Create a new pinger. Stateless.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Pinger for IcmpPinger {
    fn ping_gw(&self, gw: &str) -> PingOutcome {
        let Ok(addr) = gw.parse::<IpAddr>() else {
            tracing::debug!(%gw, "gateway is not a parseable IP address");
            return PingOutcome {
                reachable: false,
                rtt_ms: None,
            };
        };
        match ping_once(addr) {
            Some(rtt_ms) => PingOutcome {
                reachable: true,
                rtt_ms: Some(rtt_ms),
            },
            None => PingOutcome {
                reachable: false,
                rtt_ms: None,
            },
        }
    }
}

/// Send a single ICMP echo to `addr`, returning the RTT in milliseconds.
fn ping_once(addr: IpAddr) -> Option<f64> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .ok()?;
    rt.block_on(async move {
        let config = match addr {
            IpAddr::V4(_) => Config::default(),
            IpAddr::V6(_) => Config::builder().kind(ICMP::V6).build(),
        };
        let client = Client::new(&config).ok()?;
        let ident = PingIdentifier((std::process::id() & 0xffff) as u16);
        let mut pinger = client.pinger(addr, ident).await;
        pinger.timeout(PROBE_TIMEOUT);
        let payload = [0u8; 56];
        match pinger.ping(PingSequence(0), &payload).await {
            Ok((_packet, rtt)) => Some(rtt.as_secs_f64() * 1000.0),
            Err(e) => {
                tracing::debug!(error = %e, "icmp echo failed");
                None
            }
        }
    })
}

/// TCP connectivity prober that pins the connect to a physical interface via
/// the macOS `IP_BOUND_IF` socket option, so it measures the *underlay* path
/// (bypassing any default TUN route).
#[derive(Debug, Default, Clone, Copy)]
pub struct BoundTcpProber;

impl BoundTcpProber {
    /// Create a new prober. Stateless.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl TcpProber for BoundTcpProber {
    fn connect_bound(&self, host: &str, port: u16, iface: &str) -> PingOutcome {
        match connect_bound_inner(host, port, iface) {
            Some(rtt_ms) => PingOutcome {
                reachable: true,
                rtt_ms: Some(rtt_ms),
            },
            None => PingOutcome {
                reachable: false,
                rtt_ms: None,
            },
        }
    }
}

/// Open a TCP socket, bind it to `iface`, and connect to `host:port` with a
/// timeout, returning the connect latency in milliseconds on success.
fn connect_bound_inner(host: &str, port: u16, iface: &str) -> Option<f64> {
    let addr = (host, port).to_socket_addrs().ok()?.next()?;
    let domain = match addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP)).ok()?;
    if !iface.is_empty() && domain == Domain::IPV4 && !bind_to_iface_v4(socket.as_raw_fd(), iface) {
        tracing::debug!(iface, "IP_BOUND_IF failed; probing on default route");
    }
    let start = Instant::now();
    socket.connect_timeout(&addr.into(), PROBE_TIMEOUT).ok()?;
    Some(start.elapsed().as_secs_f64() * 1000.0)
}

/// Pin an IPv4 socket to a physical interface with `IP_BOUND_IF`.
///
/// Returns `true` on success. Uses `if_nametoindex` to resolve the interface
/// index and `setsockopt(IPPROTO_IP, IP_BOUND_IF, idx)`.
fn bind_to_iface_v4(fd: RawFd, iface: &str) -> bool {
    let Ok(cstr) = CString::new(iface) else {
        return false;
    };
    // SAFETY: `cstr` is a valid NUL-terminated C string for the duration of the call.
    let idx: libc::c_uint = unsafe { libc::if_nametoindex(cstr.as_ptr()) };
    if idx == 0 {
        return false;
    }
    // SAFETY: `fd` is a live socket owned by the caller; we pass a pointer to a
    // stack `c_uint` with its exact size, matching the `IP_BOUND_IF` contract.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_BOUND_IF,
            std::ptr::from_ref(&idx).cast::<libc::c_void>(),
            std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
        )
    };
    rc == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ping_gw_rejects_non_ip() {
        let p = IcmpPinger::new();
        let out = p.ping_gw("not-an-ip");
        assert!(!out.reachable);
        assert_eq!(out.rtt_ms, None);
    }

    #[test]
    fn connect_bound_unresolvable_host_is_unreachable() {
        // A host that cannot resolve must degrade to unreachable, never panic.
        let p = BoundTcpProber::new();
        let out = p.connect_bound("this.host.does.not.exist.invalid", 443, "en0");
        assert!(!out.reachable);
        assert_eq!(out.rtt_ms, None);
    }
}
