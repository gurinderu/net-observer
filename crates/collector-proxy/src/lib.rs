//! `collector-proxy` — the proxy collector: per-upstream-server TCP reachability,
//! the TUN HTTP 204 probe, the active upstream node selection, the
//! established-flow discriminator (held reference streams), and the dial
//! probe — sing-box's own dial through each node of the selector group, by
//! IP and by name (realm net-observer, node #62). Holds the
//! [`ProxyFacts`] and [`StallProbe`] port traits,
//! the pure [`build_proxy_samples`] mapping, static [`META`], and the
//! [`ProxyCollector`] implementing [`collector_core::Collector`]. Real macOS
//! adapters for the ports live in the `macos` crate.

mod collector;
mod probes;
mod proxy;

pub use collector::{META, ProbeUrls, ProxyCollector};
pub use probes::{Dial, DialOutcome, ProxyFacts, StallProbe, StallReading, StreamCheck, TunProbe};
pub use proxy::build_proxy_samples;
