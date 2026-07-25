//! `collector-proxy` — the proxy collector: per-upstream-server TCP reachability,
//! the TUN HTTP 204 probe, and the active upstream node selection. Holds the
//! [`ProxyFacts`] port trait,
//! the pure [`build_proxy_samples`] mapping, static [`META`], and the
//! [`ProxyCollector`] implementing [`collector_core::Collector`]. Real macOS
//! adapters for `ProxyFacts` live in the `macos` crate.

mod collector;
mod probes;
mod proxy;

pub use collector::{META, ProxyCollector};
pub use probes::ProxyFacts;
pub use proxy::build_proxy_samples;
