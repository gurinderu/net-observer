//! The operator-pressed neighbour scan: the one place in this daemon that
//! deliberately puts packets on the local segment to find out who is there.
//!
//! Everything else about neighbours is passive (see [`crate::neighbors`]). This
//! runs only on an explicit `ControlCmd::ScanNeighbors`, never on a timer, and
//! it is visible to anyone watching the segment — which is exactly why every run
//! writes its own `neighbor_scan` row saying what was probed and how far it
//! reached.
//!
//! Two methods, both bounded in time:
//!
//! * **Sweep** — one UDP datagram to every host address of the local IPv4
//!   subnet, which makes the kernel resolve each address, then the ARP cache is
//!   re-read. Nothing is expected to answer the datagram; the ARP resolution it
//!   provokes is the whole point, so no reply parsing and no raw sockets.
//! * **mDNS** — a DNS-SD browse. This is what supplies *names*: the ARP cache
//!   knows a MAC and an address and nothing else. Results are joined back onto
//!   the ARP cache by address, so a name lands on the device that owns it.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use types::{NeighborObs, NeighborRole, NeighborSource};

use crate::dhcp_arp::run;

/// Discard port (RFC 863). The datagram is never meant to be answered — sending
/// it is only a way to make the kernel ARP for the address.
const SWEEP_PORT: u16 = 9;

/// Largest subnet the sweep will touch, as a host count. A /22 is 1024 addresses;
/// beyond that a sweep is neither quick nor discreet, and the daemon refuses
/// rather than spraying a corporate /16.
const MAX_SWEEP_HOSTS: u32 = 1024;

/// How long the kernel is given to finish resolving before the ARP cache is
/// re-read.
const SWEEP_SETTLE: Duration = Duration::from_secs(2);

/// What the mDNS browse did and found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MdnsOutcome {
    /// Hostname discovered per address.
    pub names: HashMap<IpAddr, String>,
    /// How many DNS-SD service types were browsed.
    pub types_browsed: usize,
    pub duration_ms: i64,
}

/// The DNS-SD meta-query, recorded as the mDNS scan's target.
pub const MDNS_TARGET: &str = DNS_SD_META;

/// Total budget for the mDNS browse.
const MDNS_BUDGET: Duration = Duration::from_secs(4);

/// The meta-query every DNS-SD responder answers with the service types it offers.
const DNS_SD_META: &str = "_services._dns-sd._udp.local.";

/// An interface's IPv4 address and netmask, as `ifconfig` reports them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Iface {
    pub addr: Ipv4Addr,
    pub mask: Ipv4Addr,
}

impl Ipv4Iface {
    /// Every host address of this subnet, excluding the network and broadcast
    /// addresses and this machine's own. `None` when the subnet is larger than
    /// [`MAX_SWEEP_HOSTS`] — refused rather than truncated, so a scan never
    /// silently covers less than its recorded target.
    #[must_use]
    pub fn host_addrs(&self) -> Option<Vec<Ipv4Addr>> {
        let mask = u32::from(self.mask);
        // A netmask must be a run of ones followed by a run of zeros: its
        // complement is then one less than a power of two.
        let inv = !mask;
        if inv & inv.wrapping_add(1) != 0 {
            return None;
        }
        let hosts = inv.checked_add(1)?.checked_sub(2)?;
        if hosts == 0 || hosts > MAX_SWEEP_HOSTS {
            return None;
        }
        let net = u32::from(self.addr) & mask;
        let me = u32::from(self.addr);
        Some(
            (1..=hosts)
                .map(|i| net + i)
                .filter(|&a| a != me)
                .map(Ipv4Addr::from)
                .collect(),
        )
    }

    /// The subnet in CIDR form (`192.168.1.0/24`) — what the scan records as the
    /// target it covered.
    #[must_use]
    pub fn cidr(&self) -> String {
        let mask = u32::from(self.mask);
        let net = Ipv4Addr::from(u32::from(self.addr) & mask);
        format!("{net}/{}", mask.count_ones())
    }
}

/// Parse `ifconfig <iface>`'s `inet` line into address and netmask.
///
/// The netmask is printed in hex (`netmask 0xffffff00`), which is why this is
/// parsed rather than assumed to be a /24 — a coworking network is as likely to
/// hand out a /22.
#[must_use]
pub fn parse_ifconfig_inet(out: &str) -> Option<Ipv4Iface> {
    for line in out.lines() {
        let mut fields = line.split_whitespace();
        if fields.next() != Some("inet") {
            continue;
        }
        let addr: Ipv4Addr = fields.next()?.parse().ok()?;
        // `netmask` follows, but not always immediately (some lines carry
        // `-->` for point-to-point links first).
        let mut mask = None;
        while let Some(f) = fields.next() {
            if f == "netmask" {
                let raw = fields.next()?;
                let hex = raw.strip_prefix("0x").unwrap_or(raw);
                mask = Some(Ipv4Addr::from(u32::from_str_radix(hex, 16).ok()?));
                break;
            }
        }
        return Some(Ipv4Iface { addr, mask: mask? });
    }
    None
}

/// Attach mDNS-discovered names to ARP-known devices by matching addresses.
///
/// mDNS answers with a name and an IP; only the ARP cache knows the MAC behind
/// that IP. A name whose address is in no ARP entry is dropped rather than
/// recorded against an invented MAC — the row is keyed by MAC, and a wrong key
/// is worse than a missing name.
#[must_use]
pub fn join_names_onto_arp(
    arp: &[NeighborObs],
    names: &HashMap<IpAddr, String>,
) -> Vec<NeighborObs> {
    let mut out = Vec::new();
    for n in arp {
        let Ok(ip) = n.ip.parse::<IpAddr>() else {
            continue;
        };
        if let Some(host) = names.get(&ip) {
            out.push(NeighborObs {
                mac: n.mac.clone(),
                ip: n.ip.clone(),
                source: NeighborSource::Mdns,
                hostname: Some(host.clone()),
                role: NeighborRole::Unknown,
            });
        }
    }
    out
}

/// What the sweep actually put on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SweepStats {
    /// The subnet in CIDR form — the target the scan records as covered.
    pub target: String,
    pub sent: usize,
    pub total: usize,
    pub duration_ms: i64,
    /// `Some` when the sweep did not run: the subnet was too large, or no socket
    /// could be opened. A refusal is an outcome to record, not an error.
    pub refused: Option<String>,
}

/// Probe every host address of `iface`'s subnet and wait for the kernel to
/// resolve them. The caller re-reads the ARP cache afterwards — the resolution
/// this provokes is the entire product, so nothing here parses a reply.
///
/// The socket is pinned to `iface_name` with `IP_BOUND_IF`, like every other
/// outbound probe in this daemon. Without it a tunnel holding the default route
/// swallows the datagrams: nothing is ARPed on the segment, yet the recorded row
/// still names the segment's CIDR — a scan that reports covering ground it never
/// touched. A failed bind is recorded in `refused` rather than probing anyway.
///
/// Blocking (a `UdpSocket` and a settle sleep); the daemon drives it on the
/// blocking pool.
pub fn sweep_probe_blocking(iface: &Ipv4Iface, iface_name: &str) -> SweepStats {
    let started = Instant::now();
    let target = iface.cidr();
    let refuse = |detail: String, started: Instant| SweepStats {
        target: iface.cidr(),
        sent: 0,
        total: 0,
        duration_ms: i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX),
        refused: Some(detail),
    };
    let Some(addrs) = iface.host_addrs() else {
        return refuse(
            format!("subnet larger than {MAX_SWEEP_HOSTS} hosts, or not a subnet"),
            started,
        );
    };
    let socket = match UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))) {
        Ok(s) => s,
        Err(e) => return refuse(format!("no socket: {e}"), started),
    };
    if !crate::net::bind_to_iface_v4(socket.as_raw_fd(), iface_name) {
        return refuse(
            format!("could not pin the sweep to {iface_name}; the tunnel would have taken it"),
            started,
        );
    }
    let mut sent = 0usize;
    for a in &addrs {
        if socket
            .send_to(&[0u8], SocketAddr::from((*a, SWEEP_PORT)))
            .is_ok()
        {
            sent += 1;
        }
    }
    std::thread::sleep(SWEEP_SETTLE);
    SweepStats {
        target,
        sent,
        total: addrs.len(),
        duration_ms: i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX),
        refused: None,
    }
}

/// Read `ifconfig <iface>` and parse its IPv4 address and netmask.
pub async fn iface_ipv4(iface: &str) -> Option<Ipv4Iface> {
    parse_ifconfig_inet(&run("ifconfig", &[iface]).await?)
}

/// Browse DNS-SD for a bounded time and return the hostname discovered for each
/// address.
///
/// Blocking (mdns-sd's own channel receive); driven on the blocking pool.
/// A responder that answers nothing within the budget simply yields no names —
/// an empty result, not a failure.
#[must_use]
pub fn mdns_names_blocking() -> MdnsOutcome {
    let started = Instant::now();
    let mut names = HashMap::new();
    let done = |names: HashMap<IpAddr, String>, types: usize, started: Instant| MdnsOutcome {
        names,
        types_browsed: types,
        duration_ms: i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX),
    };
    let Ok(daemon) = mdns_sd::ServiceDaemon::new() else {
        return done(names, 0, started);
    };
    let deadline = started + MDNS_BUDGET;
    // The meta-query names the service types present; browsing each of those is
    // what actually resolves instances to a hostname and addresses.
    let Ok(meta) = daemon.browse(DNS_SD_META) else {
        return done(names, 0, started);
    };
    let mut browsed: Vec<String> = Vec::new();
    while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
        // Half the budget discovering types, the rest resolving them.
        let Ok(event) = meta.recv_timeout(remaining.min(MDNS_BUDGET / 2)) else {
            break;
        };
        if let mdns_sd::ServiceEvent::ServiceFound(_, fullname) = event
            && !browsed.contains(&fullname)
            && daemon.browse(&fullname).is_ok()
        {
            browsed.push(fullname);
        }
        if Instant::now() + MDNS_BUDGET / 2 >= deadline {
            break;
        }
    }
    // Each discovered type gets an EQUAL slice of what is left. Giving the first
    // type the whole remainder — the obvious loop — means several types are
    // discovered and exactly one is ever resolved, so names go missing with no
    // signal telling that apart from a segment where nobody answers.
    let types = browsed.len().max(1);
    for (i, ty) in browsed.iter().enumerate() {
        let Ok(rx) = daemon.browse(ty) else { continue };
        let Some(left) = deadline.checked_duration_since(Instant::now()) else {
            break;
        };
        let slice_deadline = Instant::now() + left / u32::try_from(types - i).unwrap_or(1).max(1);
        while let Some(remaining) = slice_deadline.checked_duration_since(Instant::now()) {
            let Ok(event) = rx.recv_timeout(remaining) else {
                break;
            };
            if let mdns_sd::ServiceEvent::ServiceResolved(info) = event {
                let host = info.get_hostname().trim_end_matches('.').to_string();
                // `get_addresses` yields scoped addresses (a link-local v6 may
                // carry an interface index); the ARP/NDP join is by bare address.
                for addr in info.get_addresses() {
                    names.insert(addr.to_ip_addr(), host.clone());
                }
            }
        }
    }
    let _ = daemon.shutdown();
    done(names, browsed.len(), started)
}

/// A common-service port list. Deliberately short: the scan is meant to profile
/// what a device leaves open, not to enumerate all 65535 ports — a full sweep is
/// neither quick nor a good neighbour on a shared segment. Extend consciously.
pub const COMMON_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 465, 587, 993, 995, 1433, 1883, 3306, 3389,
    5432, 5900, 6379, 8000, 8080, 8443, 9000, 9200,
];

/// How long to wait for a single TCP connect before calling the port closed.
/// Short: a stalled connect is itself a "no" for a scan on a local segment.
const PORT_CONNECT_TIMEOUT: Duration = Duration::from_millis(400);

/// How many connects are in flight at once. Bounded so the scan stays a good
/// citizen on a shared segment (rate-limiting to not disrupt the network — NOT
/// stealth) and cannot exhaust file descriptors.
const PORT_SCAN_CONCURRENCY: usize = 64;

/// One open port found on a neighbour.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortFinding {
    pub ip: IpAddr,
    pub port: u16,
}

/// What the port scan did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortScanOutcome {
    pub open: Vec<PortFinding>,
    /// (hosts, ports-per-host) actually probed — the recorded reach.
    pub hosts: usize,
    pub ports_per_host: usize,
    pub duration_ms: i64,
}

/// TCP-connect-scan `ports` on each of `targets`, pinning every connect to
/// `iface_name` with `IP_BOUND_IF` so the tunnel cannot answer for the segment
/// (the same invariant the sweep and the underlay TCP prober hold). Bounded
/// concurrency, short per-connect timeout; blocking, driven on the blocking pool.
///
/// A closed or filtered port is simply absent from the result — absence is the
/// signal, no per-port "closed" row.
pub fn port_scan_blocking(targets: &[IpAddr], ports: &[u16], iface_name: &str) -> PortScanOutcome {
    let started = Instant::now();
    // Flatten to a work list of (ip, port); a shared cursor hands each worker the
    // next item, so a slow host does not idle the others.
    let work: Vec<(IpAddr, u16)> = targets
        .iter()
        .flat_map(|ip| ports.iter().map(move |p| (*ip, *p)))
        .collect();
    let cursor = AtomicUsize::new(0);
    let workers = PORT_SCAN_CONCURRENCY.min(work.len().max(1));

    let open: Vec<PortFinding> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..workers)
            .map(|_| {
                scope.spawn(|| {
                    let mut found = Vec::new();
                    loop {
                        let i = cursor.fetch_add(1, Ordering::Relaxed);
                        let Some(&(ip, port)) = work.get(i) else {
                            break;
                        };
                        if connect_open(ip, port, iface_name) {
                            found.push(PortFinding { ip, port });
                        }
                    }
                    found
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().unwrap_or_default())
            .collect()
    });

    let mut open = open;
    open.sort_by_key(|a| (a.ip, a.port));
    PortScanOutcome {
        open,
        hosts: targets.len(),
        ports_per_host: ports.len(),
        duration_ms: i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX),
    }
}

/// One bound TCP connect with a deadline. `true` iff the port accepted.
fn connect_open(ip: IpAddr, port: u16, iface_name: &str) -> bool {
    use socket2::{Domain, Protocol, Socket, Type};
    let addr = SocketAddr::new(ip, port);
    let domain = if ip.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let Ok(socket) = Socket::new(domain, Type::STREAM, Some(Protocol::TCP)) else {
        return false;
    };
    // Pin IPv4 connects to the physical interface, like every other probe here;
    // a v6 link-local neighbour is already scoped by its address. A port probe
    // must NOT silently fall through to the default route: if the bind fails the
    // connect would go over a tunnel and the record would still name the segment,
    // so skip it — the sweep refuses for the same reason. An empty `iface_name`
    // (the loopback test) has no interface to pin and is let through.
    if ip.is_ipv4()
        && !iface_name.is_empty()
        && !crate::net::bind_to_iface_v4(socket.as_raw_fd(), iface_name)
    {
        return false;
    }
    if socket
        .connect_timeout(&addr.into(), PORT_CONNECT_TIMEOUT)
        .is_err()
    {
        return false;
    }
    // A completed connect that we hand straight back to the OS: the profile is
    // "the port accepts", nothing is sent.
    let _stream: TcpStream = socket.into();
    true
}

/// How long to wait for a service to volunteer its banner before giving up.
/// Short: a service that says nothing quickly says nothing at all here.
const BANNER_READ_TIMEOUT: Duration = Duration::from_millis(600);

/// Hard cap on how much of a banner is read. A banner is a greeting, not a
/// payload; anything past the first kilobyte is not identifying and is not read.
const BANNER_MAX_BYTES: usize = 1024;

/// Total wall-clock budget for one banner grab. Without it a host that dribbles
/// a byte just under each read timeout, never sending a newline, would force ~1
/// read per byte to the cap — minutes on a single port — and stall the whole
/// operator-pressed scan, which blocks the control request. The per-read timeout
/// bounds one read; this bounds the grab.
const BANNER_GRAB_BUDGET: Duration = Duration::from_secs(2);

/// Cleartext HTTP ports where a bare connect volunteers nothing, so a minimal
/// `HEAD` is sent to elicit the status/`Server:` line. TLS ports (443/8443) are
/// deliberately absent: the bytes there are a handshake, not a readable banner.
const HTTP_BANNER_PORTS: &[u16] = &[80, 8000, 8080];

/// One banner grabbed from an open port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BannerFinding {
    pub ip: IpAddr,
    pub port: u16,
    pub banner: String,
}

/// What the banner rung did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BannerGrabOutcome {
    pub banners: Vec<BannerFinding>,
    /// How many open ports were probed for a banner.
    pub probed: usize,
    pub duration_ms: i64,
}

/// Grab whatever each open port volunteers about itself, pinning every connect
/// to `iface_name` exactly like [`port_scan_blocking`] so the tunnel cannot
/// answer for the segment. Bounded concurrency, short per-connect and per-read
/// timeouts, capped bytes. A port that says nothing readable yields no finding —
/// silence stays silence, never a guessed banner.
pub fn banner_grab_blocking(open: &[PortFinding], iface_name: &str) -> BannerGrabOutcome {
    let started = Instant::now();
    let cursor = AtomicUsize::new(0);
    let workers = PORT_SCAN_CONCURRENCY.min(open.len().max(1));

    let banners: Vec<BannerFinding> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..workers)
            .map(|_| {
                scope.spawn(|| {
                    let mut found = Vec::new();
                    loop {
                        let i = cursor.fetch_add(1, Ordering::Relaxed);
                        let Some(f) = open.get(i) else {
                            break;
                        };
                        if let Some(banner) = grab_banner(f.ip, f.port, iface_name) {
                            found.push(BannerFinding {
                                ip: f.ip,
                                port: f.port,
                                banner,
                            });
                        }
                    }
                    found
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().unwrap_or_default())
            .collect()
    });

    let mut banners = banners;
    banners.sort_by_key(|b| (b.ip, b.port));
    BannerGrabOutcome {
        banners,
        probed: open.len(),
        duration_ms: i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX),
    }
}

/// Open a bound connection to one open port and read the banner it volunteers.
/// `None` when the bind fails (the probe must never fall through to the tunnel,
/// just like [`connect_open`]), the connect fails, or nothing readable comes
/// back. Sends only the minimal `HEAD` needed to elicit an HTTP banner; every
/// other port is read passively.
fn grab_banner(ip: IpAddr, port: u16, iface_name: &str) -> Option<String> {
    use socket2::{Domain, Protocol, Socket, Type};
    let addr = SocketAddr::new(ip, port);
    let domain = if ip.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP)).ok()?;
    // Same pinning discipline as the port scan: never let the probe fall through
    // to the default route. An empty `iface_name` (the loopback test) is let
    // through, as there is no interface to pin.
    if ip.is_ipv4()
        && !iface_name.is_empty()
        && !crate::net::bind_to_iface_v4(socket.as_raw_fd(), iface_name)
    {
        return None;
    }
    socket
        .connect_timeout(&addr.into(), PORT_CONNECT_TIMEOUT)
        .ok()?;
    // `connect_timeout` drove the socket non-blocking; the timed reads below need
    // it blocking again, or every read returns `WouldBlock` at once.
    socket.set_nonblocking(false).ok()?;
    socket.set_read_timeout(Some(BANNER_READ_TIMEOUT)).ok()?;
    socket.set_write_timeout(Some(BANNER_READ_TIMEOUT)).ok()?;
    let mut stream: TcpStream = socket.into();

    // HTTP ports volunteer nothing on a bare connect: send the minimal request
    // that elicits a status/`Server:` line, and nothing more.
    if HTTP_BANNER_PORTS.contains(&port) {
        stream.write_all(b"HEAD / HTTP/1.0\r\n\r\n").ok()?;
    }

    // Read up to the byte cap or the grab budget, then take the first line as the
    // banner. The monotonic deadline is what makes a dribbling host cost seconds,
    // not minutes.
    let deadline = Instant::now() + BANNER_GRAB_BUDGET;
    let mut buf = [0u8; BANNER_MAX_BYTES];
    let mut used = 0;
    while used < buf.len() {
        if Instant::now() >= deadline {
            break;
        }
        match stream.read(&mut buf[used..]) {
            Ok(0) => break,
            Ok(n) => {
                used += n;
                // One line is enough to identify the service; stop at the first.
                if buf[..used].contains(&b'\n') {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    first_line(&buf[..used])
}

/// The first line of a banner as trimmed, printable-ASCII text — or `None` if
/// there is nothing readable.
///
/// A service banner is printable ASCII in practice (`SSH-2.0-OpenSSH_7.4`,
/// `220 smtp ready`, `Server: nginx`). If the greeting carries ANY byte outside
/// printable ASCII (plus tab/CR) it is a binary or length-prefixed protocol — a
/// TLS handshake, MySQL's greeting on 3306 — and `None` is stored rather than a
/// lossy-decoded guess: silent wrong data is worse than none. `from_utf8_lossy`
/// was the bug — it turned high bytes into U+FFFD, which is not a control char,
/// so mojibake passed the old filter.
fn first_line(bytes: &[u8]) -> Option<String> {
    let line_end = bytes
        .iter()
        .position(|&b| b == b'\n')
        .unwrap_or(bytes.len());
    let line = &bytes[..line_end];
    if line
        .iter()
        .any(|&b| !(b == b'\t' || b == b'\r' || (0x20..=0x7e).contains(&b)))
    {
        return None;
    }
    // Now known to be valid ASCII.
    let text = std::str::from_utf8(line).ok()?.trim().to_string();
    if text.is_empty() { None } else { Some(text) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_port_scan_finds_an_open_local_port_and_misses_a_closed_one() {
        use std::net::{Ipv4Addr, TcpListener};
        // A real listener on loopback: its port is open, an adjacent one is not.
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let open_port = listener.local_addr().unwrap().port();
        // A port nothing listens on. Bind-then-drop frees it, so a connect is
        // refused fast rather than timing out.
        let scratch = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let closed_port = scratch.local_addr().unwrap().port();
        drop(scratch);

        let target = IpAddr::V4(Ipv4Addr::LOCALHOST);
        // Empty iface name: bind_to_iface is skipped on loopback (if_nametoindex
        // of "" fails, the connect proceeds unpinned — fine for a loopback test).
        let out = port_scan_blocking(&[target], &[open_port, closed_port], "");
        assert!(
            out.open.iter().any(|f| f.port == open_port),
            "the listening port must be found: {:?}",
            out.open
        );
        assert!(
            !out.open.iter().any(|f| f.port == closed_port),
            "a closed port must not appear"
        );
        assert_eq!(out.hosts, 1);
        assert_eq!(out.ports_per_host, 2);
    }

    /// How many times a socket test may re-attempt before it counts as a real
    /// failure: the loopback handshake is a race the harness owns, and a single
    /// attempt has repeatedly failed under CI load while the code was correct.
    const ATTEMPTS: usize = 5;

    /// A service that announces itself on connect (SSH-style) has its greeting
    /// read back as the banner; the byte cap and first-line rule keep it to the
    /// greeting.
    #[test]
    fn a_banner_grab_reads_a_service_that_announces_on_connect() {
        use std::io::Write;
        use std::net::{Ipv4Addr, TcpListener};
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        // The greeting is served to as many connections as the attempts below
        // may make: `grab_banner` gives a peer BANNER_READ_TIMEOUT to speak, and
        // on a loaded machine the accept-and-write can lose that race once. The
        // race is the test harness's, not the grab's, so it is retried here
        // rather than paid for with a longer production timeout.
        let handle = std::thread::spawn(move || {
            for sock in listener.incoming().take(ATTEMPTS) {
                let Ok(mut sock) = sock else { break };
                let _ = sock.write_all(b"SSH-2.0-OpenSSH_9.6\r\nrest of protocol\r\n");
            }
        });

        let finding = PortFinding {
            ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
        };
        let mut last = None;
        for _ in 0..ATTEMPTS {
            let out = banner_grab_blocking(std::slice::from_ref(&finding), "");
            assert_eq!(out.probed, 1);
            if out.banners.len() == 1 {
                last = Some(out);
                break;
            }
        }
        drop(handle);
        let out = last.expect("the greeting must be read within the attempts");
        assert_eq!(out.banners[0].banner, "SSH-2.0-OpenSSH_9.6");
    }

    /// An HTTP-shaped port volunteers nothing on connect, so the grab sends a
    /// minimal `HEAD` and the status line comes back as the banner.
    #[test]
    fn a_banner_grab_elicits_an_http_status_line_with_head() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        // Bind on an HTTP-listed port; if it is busy, the test still exercises the
        // HEAD path only when we actually got one of them.
        let listener = HTTP_BANNER_PORTS
            .iter()
            .find_map(|p| TcpListener::bind((Ipv4Addr::LOCALHOST, *p)).ok())
            .expect("no HTTP-listed loopback port was free");
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                let mut scratch = [0u8; 64];
                let _ = sock.read(&mut scratch); // consume the HEAD request
                let _ = sock.write_all(b"HTTP/1.0 200 OK\r\nServer: tiny/1.0\r\n\r\n");
            }
        });

        let finding = PortFinding {
            ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
        };
        let out = banner_grab_blocking(std::slice::from_ref(&finding), "");
        handle.join().unwrap();
        assert_eq!(out.banners.len(), 1);
        assert_eq!(out.banners[0].banner, "HTTP/1.0 200 OK");
    }

    /// A port that accepts but says nothing yields no banner — silence is never
    /// turned into a guessed one.
    #[test]
    fn a_binary_greeter_stores_no_banner_only_ascii_does() {
        // Printable ASCII is a real banner.
        assert_eq!(
            first_line(b"SSH-2.0-OpenSSH_9.6\r\n").as_deref(),
            Some("SSH-2.0-OpenSSH_9.6")
        );
        // A high-byte / length-prefixed greeting (MySQL-style, TLS) is NOT a
        // banner: storing lossy mojibake would be silent wrong data.
        assert_eq!(first_line(&[0x0a, 0x33, 0x2e, 0xff, 0x00, 0x15]), None);
        assert_eq!(first_line(&[0xde, 0xad, 0xbe, 0xef]), None);
        // Empty / whitespace-only is nothing.
        assert_eq!(first_line(b"   \r\n"), None);
    }

    #[test]
    fn a_silent_port_yields_no_banner() {
        use std::net::TcpListener;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            // Accept, hold briefly so the grab's read times out, then close.
            if let Ok((sock, _)) = listener.accept() {
                std::thread::sleep(Duration::from_millis(50));
                drop(sock);
            }
        });

        let finding = PortFinding {
            ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
        };
        let out = banner_grab_blocking(std::slice::from_ref(&finding), "");
        handle.join().unwrap();
        assert_eq!(out.probed, 1);
        assert!(out.banners.is_empty(), "silence must yield no banner");
    }

    #[test]
    fn parses_a_slash_24_from_ifconfig() {
        let out = "\
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tinet6 fe80::1%en0 prefixlen 64 scopeid 0x8
\tinet 192.168.1.23 netmask 0xffffff00 broadcast 192.168.1.255";
        let i = parse_ifconfig_inet(out).expect("parsed");
        assert_eq!(i.addr, Ipv4Addr::new(192, 168, 1, 23));
        assert_eq!(i.cidr(), "192.168.1.0/24");
    }

    #[test]
    fn an_interface_without_an_inet_line_yields_none() {
        assert!(parse_ifconfig_inet("en5: flags=8822<BROADCAST> mtu 1500\n").is_none());
    }

    #[test]
    fn a_slash_24_sweep_covers_every_host_but_this_one() {
        let i = Ipv4Iface {
            addr: Ipv4Addr::new(192, 168, 1, 23),
            mask: Ipv4Addr::new(255, 255, 255, 0),
        };
        let hosts = i.host_addrs().expect("sweepable");
        assert_eq!(hosts.len(), 253);
        assert!(hosts.contains(&Ipv4Addr::new(192, 168, 1, 1)));
        assert!(hosts.contains(&Ipv4Addr::new(192, 168, 1, 254)));
        assert!(!hosts.contains(&Ipv4Addr::new(192, 168, 1, 23)));
        assert!(!hosts.contains(&Ipv4Addr::new(192, 168, 1, 0)));
        assert!(!hosts.contains(&Ipv4Addr::new(192, 168, 1, 255)));
    }

    /// The cap is a refusal, not a truncation: a scan must cover the target it
    /// records or none of it.
    #[test]
    fn a_subnet_above_the_cap_is_refused() {
        let i = Ipv4Iface {
            addr: Ipv4Addr::new(10, 0, 0, 5),
            mask: Ipv4Addr::new(255, 255, 0, 0),
        };
        assert_eq!(i.cidr(), "10.0.0.0/16");
        assert!(i.host_addrs().is_none());
    }

    #[test]
    fn a_non_contiguous_mask_is_not_a_subnet() {
        let i = Ipv4Iface {
            addr: Ipv4Addr::new(192, 168, 1, 5),
            mask: Ipv4Addr::new(255, 0, 255, 0),
        };
        assert!(i.host_addrs().is_none());
    }

    fn arp(mac: &str, ip: &str) -> NeighborObs {
        NeighborObs {
            mac: mac.into(),
            ip: ip.into(),
            source: NeighborSource::Arp,
            hostname: None,
            role: NeighborRole::Unknown,
        }
    }

    #[test]
    fn a_name_lands_on_the_device_that_owns_the_address() {
        let arp_rows = vec![
            arp("11:22:33:44:55:66", "192.168.1.5"),
            arp("aa:bb:cc:dd:ee:00", "192.168.1.6"),
        ];
        let mut names = HashMap::new();
        names.insert(
            "192.168.1.6".parse::<IpAddr>().unwrap(),
            "printer.local".to_string(),
        );
        let joined = join_names_onto_arp(&arp_rows, &names);
        assert_eq!(joined.len(), 1);
        assert_eq!(joined[0].mac, "aa:bb:cc:dd:ee:00");
        assert_eq!(joined[0].hostname.as_deref(), Some("printer.local"));
        assert_eq!(joined[0].source, NeighborSource::Mdns);
    }

    /// A name for an address no ARP entry claims is dropped: the row is keyed by
    /// MAC, and there is no MAC to key it by.
    #[test]
    fn a_name_with_no_arp_entry_is_dropped() {
        let mut names = HashMap::new();
        names.insert(
            "192.168.1.99".parse::<IpAddr>().unwrap(),
            "ghost.local".to_string(),
        );
        assert!(join_names_onto_arp(&[arp("11:22:33:44:55:66", "192.168.1.5")], &names).is_empty());
    }
}
