//! `collector-proxy` — the proxy collector: per-upstream-server TCP reachability,
//! the TUN HTTP 204 probe, the active upstream node selection, the
//! established-flow discriminator (held reference streams), and sing-box's
//! own URL-test history per node of the selector group — read from its
//! Clash API each tick, never triggered (realm net-observer, node #62).
//! Holds the
//! [`ProxyFacts`] and [`StallProbe`] port traits,
//! the pure [`build_proxy_samples`] mapping, static [`META`], and the
//! [`ProxyCollector`] implementing [`collector_core::Collector`]. Real macOS
//! adapters for the ports live in the `macos` crate.

mod collector;
mod probes;
mod proxy;

pub use collector::{META, ProxyCollector};
pub use probes::{
    ProxyFacts, ProxyInfo, StallProbe, StallReading, StreamCheck, TunProbe, UrlTest, UrlTestEntry,
};
pub use proxy::build_proxy_samples;
