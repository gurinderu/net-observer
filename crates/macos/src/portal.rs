//! The real captive-portal probe: one DNS question to the interface's DHCP
//! resolver, one HTTP GET of the captive-detect URL, every socket pinned to
//! the physical interface (`IP_BOUND_IF`) so the tunnel cannot answer for
//! the underlay (realm net-observer, nodes #176, #178).
//!
//! The system resolver is deliberately not used: it answers through
//! sing-box's TUN, and a fakeip there would send the probe into the tunnel —
//! the reading would then be about the wrong path. The lease's own resolver
//! hijacking the name to the portal is a fine answer: the probe reaches the
//! portal and reads the intercept. The network paths here are verified
//! manually, like every adapter in this crate; the packet and response logic
//! is `collector-portal`'s, unit-tested there.

use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::time::Duration;

use collector_portal::{DETECT_HOST, DETECT_PATH, PortalProbe, dns, http};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use crate::dhcp_arp::{ip_for_key, run};
use crate::net::{bind_to_iface_v4, open_bound_stream};

/// Deadline for the DNS exchange with the lease's resolver.
const DNS_TIMEOUT: Duration = Duration::from_secs(2);
/// Deadline for reading the HTTP answer after the connect.
const READ_TIMEOUT: Duration = Duration::from_secs(4);
/// Cap on the answer read: status, headers and enough body to see `Success`
/// or a portal page's opening — never a whole page.
const READ_CAP: usize = 16 * 1024;

/// macOS implementation of [`PortalProbe`]. Stateless: every fetch reads the
/// lease fresh, because the resolver is exactly what a new network changes.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemPortalProbe;

impl SystemPortalProbe {
    /// Create a new probe. Stateless.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl PortalProbe for SystemPortalProbe {
    async fn fetch(&self, iface: &str) -> Result<Vec<u8>, String> {
        let resolver = dhcp_resolver(iface)
            .await
            .ok_or("no DHCP resolver on the interface's lease")?;
        let ip = resolve_bound(&resolver, iface).await?;
        let mut stream = open_bound_stream(&ip.to_string(), 80, Some(iface), true)
            .await
            .ok_or_else(|| format!("bound connect to {ip}:80 failed"))?;
        stream
            .write_all(&http::detect_request(DETECT_HOST, DETECT_PATH))
            .await
            .map_err(|e| format!("send failed: {e}"))?;
        read_capped(&mut stream).await
    }
}

/// The first DNS server of the interface's current DHCP lease.
async fn dhcp_resolver(iface: &str) -> Option<String> {
    let out = run("ipconfig", &["getpacket", iface]).await?;
    ip_for_key(&out, "domain_name_server")
}

/// Resolve [`DETECT_HOST`] at `resolver`, over a UDP socket pinned to
/// `iface`. The bind is required: an unpinned question would ride the
/// default route — the tunnel — and measure the wrong path.
async fn resolve_bound(resolver: &str, iface: &str) -> Result<std::net::Ipv4Addr, String> {
    let addr: SocketAddr = format!("{resolver}:53")
        .parse()
        .map_err(|_| format!("resolver {resolver} is not an address"))?;
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|e| format!("udp socket: {e}"))?;
    socket
        .set_nonblocking(true)
        .map_err(|e| format!("udp socket: {e}"))?;
    if !bind_to_iface_v4(socket.as_raw_fd(), iface) {
        return Err(format!("IP_BOUND_IF failed on {iface}"));
    }
    let socket =
        tokio::net::UdpSocket::from_std(socket.into()).map_err(|e| format!("udp socket: {e}"))?;
    socket
        .connect(addr)
        .await
        .map_err(|e| format!("udp connect {addr}: {e}"))?;
    // The id only pairs answer to question on this one socket; sub-second
    // nanos are unpredictable enough for that.
    let id = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos()
        & 0xffff) as u16;
    socket
        .send(&dns::a_query(id, DETECT_HOST))
        .await
        .map_err(|e| format!("DNS send: {e}"))?;
    let mut buf = [0u8; 1500];
    let n = timeout(DNS_TIMEOUT, socket.recv(&mut buf))
        .await
        .map_err(|_| format!("DNS timed out at {resolver}"))?
        .map_err(|e| format!("DNS recv: {e}"))?;
    dns::first_a_answer(&buf[..n], id)
}

/// Read the HTTP answer to EOF, the deadline, or the cap — whichever comes
/// first. A partial answer is returned as read: the response reader names
/// truncation itself, and a truncated intercept is still an intercept.
async fn read_capped(stream: &mut tokio::net::TcpStream) -> Result<Vec<u8>, String> {
    let deadline = tokio::time::Instant::now() + READ_TIMEOUT;
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    loop {
        match tokio::time::timeout_at(deadline, stream.read(&mut chunk)).await {
            // Deadline: whatever arrived is the answer.
            Err(_) => break,
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() >= READ_CAP {
                    buf.truncate(READ_CAP);
                    break;
                }
            }
            Ok(Err(e)) => {
                if buf.is_empty() {
                    return Err(format!("read failed: {e}"));
                }
                break;
            }
        }
    }
    if buf.is_empty() {
        return Err("empty answer on port 80".into());
    }
    Ok(buf)
}
