//! `collector-dns` — the `dns` collector: resolver probes (sing-box TUN DNS, DHCP
//! resolver, DoH, control domain) mapped into [`types::DnsSample`]s.
//!
//! Holds the [`DnsFacts`] port trait (implemented by the `macos` crate), the pure
//! [`build_dns_samples`] mapping, static [`META`], and the [`DnsCollector`] that
//! plugs into `collector_core::Collector` for the daemon.

pub mod collector;
pub mod facts;
pub mod sample;

pub use collector::{DnsCollector, META};
pub use facts::DnsFacts;
pub use sample::build_dns_samples;
