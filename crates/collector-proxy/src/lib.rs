//! `collector-proxy` — the proxy collector: per-upstream-server TCP reachability,
//! the TUN HTTP 204 probe, the active upstream node selection, and the
//! established-flow discriminator (held reference streams). Holds the
//! [`ProxyFacts`] and [`StallProbe`] port traits,
//! the pure [`build_proxy_samples`] mapping, static [`META`], and the
//! [`ProxyCollector`] implementing [`collector_core::Collector`]. Real macOS
//! adapters for the ports live in the `macos` crate.

mod collector;
mod probes;
mod proxy;

pub use collector::{META, ProxyCollector};
pub use probes::{ProxyFacts, StallProbe, StallReading, StreamCheck};
pub use proxy::build_proxy_samples;
