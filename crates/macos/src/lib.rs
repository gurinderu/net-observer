//! macOS platform adapters for the observer collectors.
//!
//! These are the thin, OS-specific glue implementations of the probe traits
//! declared in `collector-core` (`Pinger`/`TcpProber`), `collector-link`
//! (`LinkFacts`), and `collector-proxy` (`ProxyFacts`). They use async-native
//! I/O throughout: ICMP ping (`surge-ping`), interface-bound TCP connect
//! (`socket2` + `IP_BOUND_IF` → `tokio::net::TcpStream`), DHCP/ARP/Wi-Fi facts
//! (`tokio::process` over `route` / `ipconfig` / `arp` / `networksetup`), Wi-Fi
//! air quality read from CoreWLAN via hand-declared `objc2` message sends, the
//! Clash/Mihomo RESTful API and DoH client (`reqwest` async), and the `tcpdump`
//! pcap ring with freeze-to-disk. The only genuinely blocking probe, the
//! PF_ROUTE `read`, stays a sync `EventSource` driven on a dedicated thread.
//!
//! Raw ICMP and `tcpdump` require root, so the reachability paths are verified
//! manually; the pure parsing/copy logic is unit-tested.

pub mod clash;
pub mod corewlan;
pub mod dhcp_arp;
pub mod dns;
pub mod host;
pub mod neighbors;
pub mod net;
pub mod pcap;
pub mod route;
pub mod wifi;

pub use clash::{ClashClient, ProxySystemFacts};
pub use corewlan::CoreWlanFacts;
pub use dhcp_arp::SystemFacts;
pub use dns::DnsResolver;
pub use host::HostLoad;
pub use neighbors::SystemNeighbors;
pub use net::{BoundTcpProber, IcmpPinger};
pub use pcap::PcapRing;
pub use route::PfRouteSource;
