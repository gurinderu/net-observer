//! macOS platform adapters for the observer collectors.
//!
//! These are the thin, OS-specific glue implementations of the probe traits
//! declared in `collector-core` (`Pinger`/`TcpProber`), `collector-link`
//! (`LinkFacts`), and `collector-proxy` (`ProxyFacts`): ICMP ping (`surge-ping`), interface-bound
//! TCP connect (`socket2` + `IP_BOUND_IF`), DHCP/ARP/Wi-Fi facts (`route` /
//! `ipconfig` / `arp` / `networksetup`), the Clash/Mihomo RESTful API client
//! (`reqwest`), and the `tcpdump` pcap ring with freeze-to-disk.
//!
//! Raw ICMP and `tcpdump` require root, so the reachability paths are verified
//! manually; the pure parsing/copy logic is unit-tested.

pub mod clash;
pub mod dhcp_arp;
pub mod dns;
pub mod host;
pub mod net;
pub mod pcap;
pub mod route;
pub mod wifi;

pub use clash::{ClashClient, ProxySystemFacts};
pub use dhcp_arp::SystemFacts;
pub use dns::DnsResolver;
pub use host::HostLoad;
pub use net::{BoundTcpProber, IcmpPinger};
pub use pcap::PcapRing;
pub use route::PfRouteSource;
