//! `collector-announce` — the `announce` collector: neighbours from what the
//! segment announces about itself, heard passively (realm net-observer,
//! node #92).
//!
//! A segment talks without being asked: the gateway answers ARP, a laptop
//! announces its mDNS services and its name, phones ask for DHCP leases and
//! say what they are called, a router notifies SSDP. A listener on those four
//! protocols keeps the neighbour map alive under the passive probing tier
//! with no packet of ours — which the neighbour-cache reading cannot, since a
//! cache only holds what this machine talked to.
//!
//! **Passive by construction.** Nothing here opens a socket or addresses a
//! packet at anybody. The bytes come from a pcap stream — on the daemon, a
//! second `tcpdump` child's stdout, spawned by the `macos` crate — and this
//! crate only reads. This machine's own frames — the OS's own traffic and,
//! during an operator-pressed scan, the sweep's ARP and the mDNS browse;
//! never the periodic probes, which do not pass the filter — it recognises by the interface's own MAC, read afresh for every window,
//! counts and drops: a machine is not its own neighbour, and the count says
//! the listener saw itself and ignored it. The passivity proof is elsewhere
//! (the frozen pcap slice, realm net-observer, node #88).
//!
//! **Pure Rust, tested where it runs.** [`pcap::PcapStream`] walks the
//! classic savefile format over any `Read`; [`frame`] slices Ethernet / ARP
//! / IP / UDP with `etherparse`; [`mdns`] reads DNS-SD records with
//! `simple-dns`; [`ssdp`] and [`dhcp`] decode their protocols by hand. Every
//! decoder is a function over `&[u8]` with unit tests on frames built from
//! their fields; none of it needs root, a network, or macOS.
//!
//! **One reading per window.** [`AnnounceSource`] implements
//! `collector_core::EventSource`: every [`FLUSH_EVERY`] it returns one
//! `Sample::Neighbors` carrying the neighbours and services heard since the
//! last flush, keyed by the segment (the gateway's MAC, the same key the
//! `neighbors` collector writes under), with `heard = Some(_)` marking it a
//! listener flush. A window in which nothing was heard is still a reading —
//! the segment said nothing — and the listener's end is bracketed by a
//! `SKIP` row naming why, never a silence.

pub mod collector;
pub mod dhcp;
pub mod frame;
pub mod mdns;
pub mod own_frames;
pub mod pcap;
pub mod source;
pub mod ssdp;
pub mod window;

pub use collector::{AnnounceCollector, META};
pub use frame::{Mac, is_unicast, mac_octets, mac_text};
pub use own_frames::count_own_frames;
pub use source::{AnnounceSource, FLUSH_EVERY, SegmentIdentity, SegmentIdentityReading};
pub use window::Window;
