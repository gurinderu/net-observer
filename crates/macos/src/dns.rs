//! DNS resolver facts: the real [`DnsFacts`] adapter behind the `dns` collector.
//!
//! Resolves the monitored service domain and a `.ru` control domain over two
//! paths — the system resolver (`sb`/`rtr`: sing-box TUN DNS / DHCP resolver, via
//! `getaddrinfo`) and DNS-over-HTTPS (`doh`, Cloudflare's JSON API) — and
//! classifies the answer. The load-bearing regression check is fakeip leakage:
//! the `.ru` control domain answered from the sing-box fakeip pool is always
//! a bug, so it is verdict [`DnsVerdict::FakeIp`]. (A fakeip answer on the
//! *monitored* domain is expected routing, not a bug — so only the control
//! probe flags fakeip.) The pool is read from the RENDERED sing-box config on
//! every control probe, never hardcoded: the pool moved four times in one
//! month, and a literal here was left behind by one of those moves — the
//! verdict silently judged a pool sing-box no longer served.
//!
//! The network paths (system `getaddrinfo`, DoH request) are verified manually;
//! the pure classification/range logic is unit-tested.

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use collector_core::Readiness;
use collector_dns::DnsFacts;
use types::DnsVerdict;

/// Timeout for a single resolution attempt (system lookup or DoH request).
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(3);

/// The probe name label for the `.ru` control domain — the one probe on which a
/// fakeip answer is flagged as a bug.
const RU_CONTROL_PROBE: &str = "ru";

/// macOS implementation of [`DnsFacts`]: config-driven probes over the system
/// resolver and DNS-over-HTTPS, with fakeip-range classification.
pub struct DnsResolver {
    monitored_domain: String,
    ru_control_domain: String,
    doh_url: String,
    /// Path to the rendered sing-box config the fakeip pool is read from.
    singbox_config: String,
    http: reqwest::Client,
}

impl DnsResolver {
    /// Build a resolver for the monitored + `.ru` control domains, using
    /// `doh_url` for the DoH path and `singbox_config` (the rendered config)
    /// as the source of the fakeip pool.
    #[must_use]
    pub fn new(
        monitored_domain: String,
        ru_control_domain: String,
        doh_url: String,
        singbox_config: String,
    ) -> Self {
        crate::tls::install_default_provider();
        let http = reqwest::Client::builder()
            .timeout(RESOLVE_TIMEOUT)
            .build()
            .unwrap_or_default();
        Self {
            monitored_domain,
            ru_control_domain,
            doh_url,
            singbox_config,
            http,
        }
    }

    /// The fakeip pool the rendered sing-box config declares RIGHT NOW, as a
    /// `(network, mask)` pair. Read per control probe rather than cached at
    /// construction: a pool move re-renders the config and restarts sing-box,
    /// but not necessarily this daemon. `None` (no config / no range)
    /// disables the FakeIp verdict for that probe — "cannot judge" must never
    /// become "not a fakeip", and even less "judge against a guessed pool".
    fn current_fakeip_range(&self) -> Option<(u32, u32)> {
        let json = std::fs::read_to_string(&self.singbox_config).ok()?;
        crate::clash::fakeip_range(&json)
    }

    /// Map a probe name label to the domain it resolves: `nks` → the monitored
    /// domain, `ru` → the `.ru` control domain, anything else taken verbatim.
    fn domain_for(&self, probe: &str) -> String {
        match probe {
            "nks" => self.monitored_domain.clone(),
            RU_CONTROL_PROBE => self.ru_control_domain.clone(),
            other => other.to_string(),
        }
    }

    /// Resolve `domain` via the system resolver (`getaddrinfo`, run async-native
    /// by `tokio::net::lookup_host`), bounded by [`RESOLVE_TIMEOUT`]. `None` on
    /// error/timeout; an empty vector means the resolver answered with no
    /// addresses.
    async fn system_lookup(domain: &str) -> Option<Vec<IpAddr>> {
        let host = format!("{domain}:0");
        match tokio::time::timeout(RESOLVE_TIMEOUT, tokio::net::lookup_host(host)).await {
            Ok(Ok(addrs)) => Some(addrs.map(|sa| sa.ip()).collect()),
            _ => None,
        }
    }

    /// Resolve `domain`'s A records via Cloudflare's DoH JSON API. `None` on any
    /// request/parse error.
    async fn doh_lookup(&self, domain: &str) -> Option<Vec<IpAddr>> {
        let resp = self
            .http
            .get(&self.doh_url)
            .query(&[("name", domain), ("type", "A")])
            .header("Accept", "application/dns-json")
            .send()
            .await
            .ok()?;
        let body: serde_json::Value = resp.json().await.ok()?;
        let answers = body.get("Answer")?.as_array()?;
        let ips = answers
            .iter()
            // DNS record type 1 == A.
            .filter(|a| a.get("type").and_then(serde_json::Value::as_i64) == Some(1))
            .filter_map(|a| a.get("data").and_then(serde_json::Value::as_str))
            .filter_map(|s| s.parse::<IpAddr>().ok())
            .collect();
        Some(ips)
    }
}

impl DnsFacts for DnsResolver {
    async fn resolve(
        &self,
        probe: &str,
        server: &str,
    ) -> (DnsVerdict, Option<String>, Option<f64>) {
        let domain = self.domain_for(probe);
        let start = Instant::now();
        let ips = match server {
            "doh" => self.doh_lookup(&domain).await,
            _ => Self::system_lookup(&domain).await,
        };
        #[allow(clippy::cast_precision_loss)]
        let rtt_ms = start.elapsed().as_micros() as f64 / 1000.0;
        // A fakeip answer is a bug only on the `.ru` control probe; on the
        // monitored probe it is expected routing through sing-box.
        let fakeip_range = if probe == RU_CONTROL_PROBE {
            self.current_fakeip_range()
        } else {
            None
        };
        classify(fakeip_range, ips.as_deref(), rtt_ms)
    }

    async fn probes(&self) -> Vec<(String, String)> {
        vec![
            ("nks".into(), "sb".into()),
            (RU_CONTROL_PROBE.into(), "sb".into()),
            (RU_CONTROL_PROBE.into(), "doh".into()),
        ]
    }

    async fn preflight(&self) -> Readiness {
        if self.monitored_domain.is_empty() && self.ru_control_domain.is_empty() {
            Readiness::Unavailable("no resolver domain configured".into())
        } else {
            Readiness::Ready
        }
    }
}

/// Whether an IPv4 address falls in the fakeip pool `(network, mask)`.
fn is_fakeip_v4(ip: Ipv4Addr, (net, mask): (u32, u32)) -> bool {
    u32::from(ip) & mask == net
}

/// Pure verdict classification from a resolution outcome. `None` ips ⇒ the
/// lookup failed (TIMEOUT); an empty slice ⇒ the resolver answered with no
/// address (EMPTY); otherwise the first address is recorded, and — when a
/// `fakeip_range` is given — an answer inside it is FAKEIP, else OK. A `None`
/// range means "do not judge pool membership" (either this is not the control
/// probe, or the pool is unknowable right now).
fn classify(
    fakeip_range: Option<(u32, u32)>,
    ips: Option<&[IpAddr]>,
    rtt_ms: f64,
) -> (DnsVerdict, Option<String>, Option<f64>) {
    let Some(ips) = ips else {
        return (DnsVerdict::Timeout, None, None);
    };
    let Some(first) = ips.first() else {
        return (DnsVerdict::Empty, None, Some(rtt_ms));
    };
    let fakeip = fakeip_range.is_some_and(|range| {
        ips.iter().any(|ip| match ip {
            IpAddr::V4(v4) => is_fakeip_v4(*v4, range),
            IpAddr::V6(_) => false,
        })
    });
    let verdict = if fakeip {
        DnsVerdict::FakeIp
    } else {
        DnsVerdict::Ok
    };
    (verdict, Some(first.to_string()), Some(rtt_ms))
}

#[cfg(test)]
mod tests {
    /// Live check that the installed crypto provider actually completes a TLS
    /// handshake with the DoH endpoint — compiling against a provider-less
    /// rustls proves nothing about the handshake. Ignored by default: the rest
    /// of the suite needs no network. Run it by name after changing the TLS
    /// stack: `cargo test -p macos -- --ignored doh_handshake`.
    /// (realm net-observer, node #46)
    #[tokio::test]
    #[ignore = "needs the network"]
    async fn doh_handshake_succeeds_against_the_real_endpoint() {
        super::super::tls::install_default_provider();
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .expect("client builds");
        let resp = http
            .get("https://1.1.1.1/dns-query?name=example.com&type=A")
            .header("accept", "application/dns-json")
            .send()
            .await
            .expect("the TLS handshake and request must succeed");
        assert!(resp.status().is_success(), "status: {}", resp.status());
    }

    use super::*;

    /// The live pool at the time of writing: 172.24.0.0/14. The point of the
    /// tuple form is that tests and production share ONE membership test and
    /// the pool itself always comes from the rendered config.
    fn pool() -> (u32, u32) {
        (u32::from(Ipv4Addr::new(172, 24, 0, 0)), u32::MAX << 18)
    }

    #[test]
    fn membership_follows_the_given_pool_not_a_literal() {
        assert!(is_fakeip_v4(Ipv4Addr::new(172, 24, 1, 235), pool()));
        assert!(is_fakeip_v4(Ipv4Addr::new(172, 27, 255, 255), pool()));
        assert!(!is_fakeip_v4(Ipv4Addr::new(172, 28, 0, 1), pool()));
        // The OLD hardcoded pool no longer matches once the config moves on —
        // the exact false-negative the literal produced in the live trial.
        assert!(!is_fakeip_v4(Ipv4Addr::new(198, 18, 0, 7), pool()));
    }

    #[tokio::test]
    async fn control_probe_maps_to_ru_control_domain() {
        let r = DnsResolver::new(
            "nks.lab.mirari.ru".into(),
            "ya.ru".into(),
            "https://1.1.1.1/dns-query".into(),
            "/nonexistent/sing-box/config.json".into(),
        );
        assert_eq!(r.domain_for("nks"), "nks.lab.mirari.ru");
        assert_eq!(r.domain_for("ru"), "ya.ru");
        assert_eq!(r.domain_for("other"), "other");
        assert!(r.preflight().await.is_ready());
        assert!(
            r.current_fakeip_range().is_none(),
            "an unreadable config means the pool is unknowable, not defaulted"
        );
    }

    #[test]
    fn classify_fakeip_flagged_on_control_probe() {
        let ips = [IpAddr::V4(Ipv4Addr::new(172, 24, 0, 7))];
        let (v, ip, rtt) = classify(Some(pool()), Some(&ips), 3.0);
        assert_eq!(v, DnsVerdict::FakeIp);
        assert_eq!(ip.as_deref(), Some("172.24.0.7"));
        assert_eq!(rtt, Some(3.0));
    }

    #[test]
    fn classify_without_a_range_never_flags() {
        // Same fakeip address, but no range given (not the control probe, or
        // the pool is unknowable) ⇒ no judgement, OK.
        let ips = [IpAddr::V4(Ipv4Addr::new(172, 24, 0, 9))];
        let (v, _, _) = classify(None, Some(&ips), 1.0);
        assert_eq!(v, DnsVerdict::Ok);
    }

    #[test]
    fn classify_ok_for_real_answer() {
        let ips = [IpAddr::V4(Ipv4Addr::new(87, 250, 250, 242))];
        let (v, _, _) = classify(Some(pool()), Some(&ips), 1.0);
        assert_eq!(v, DnsVerdict::Ok);
    }

    #[test]
    fn classify_timeout_and_empty() {
        let (v, ip, rtt) = classify(Some(pool()), None, 5.0);
        assert_eq!(v, DnsVerdict::Timeout);
        assert!(ip.is_none());
        assert!(rtt.is_none());

        let (v2, ip2, rtt2) = classify(Some(pool()), Some(&[]), 5.0);
        assert_eq!(v2, DnsVerdict::Empty);
        assert!(ip2.is_none());
        assert_eq!(rtt2, Some(5.0));
    }
}
