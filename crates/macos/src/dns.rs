//! DNS resolver facts: the real [`DnsFacts`] adapter behind the `dns` collector.
//!
//! Resolves the monitored service domain and a `.ru` control domain over two
//! paths — the system resolver (`sb`/`rtr`: sing-box TUN DNS / DHCP resolver, via
//! `getaddrinfo`) and DNS-over-HTTPS (`doh`, Cloudflare's JSON API) — and
//! classifies the answer. The load-bearing regression check is fakeip leakage:
//! the `.ru` control domain answered from the sing-box fakeip range
//! (`198.18.0.0/15`) is always a bug, so it is verdict [`DnsVerdict::FakeIp`].
//! (A fakeip answer on the *monitored* domain is expected routing, not a bug —
//! so only the control probe flags fakeip.)
//!
//! The network paths (system `getaddrinfo`, DoH request) are verified manually;
//! the pure classification/range logic is unit-tested.

use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
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
    client: reqwest::blocking::Client,
}

impl DnsResolver {
    /// Build a resolver for the monitored + `.ru` control domains, using
    /// `doh_url` for the DoH path.
    #[must_use]
    pub fn new(monitored_domain: String, ru_control_domain: String, doh_url: String) -> Self {
        let client = reqwest::blocking::Client::builder()
            .timeout(RESOLVE_TIMEOUT)
            .build()
            .unwrap_or_default();
        Self {
            monitored_domain,
            ru_control_domain,
            doh_url,
            client,
        }
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

    /// Resolve `domain` via the system resolver (`getaddrinfo`). `None` on error;
    /// an empty vector means the resolver answered with no addresses.
    fn system_lookup(domain: &str) -> Option<Vec<IpAddr>> {
        format!("{domain}:0")
            .to_socket_addrs()
            .ok()
            .map(|it| it.map(|sa| sa.ip()).collect())
    }

    /// Resolve `domain`'s A records via Cloudflare's DoH JSON API. `None` on any
    /// request/parse error.
    fn doh_lookup(&self, domain: &str) -> Option<Vec<IpAddr>> {
        let resp = self
            .client
            .get(&self.doh_url)
            .query(&[("name", domain), ("type", "A")])
            .header(reqwest::header::ACCEPT, "application/dns-json")
            .send()
            .ok()?;
        let body: serde_json::Value = resp.json().ok()?;
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
    fn resolve(&self, probe: &str, server: &str) -> (DnsVerdict, Option<String>, Option<f64>) {
        let domain = self.domain_for(probe);
        let start = Instant::now();
        let ips = match server {
            "doh" => self.doh_lookup(&domain),
            _ => Self::system_lookup(&domain),
        };
        #[allow(clippy::cast_precision_loss)]
        let rtt_ms = start.elapsed().as_micros() as f64 / 1000.0;
        // A fakeip answer is a bug only on the `.ru` control probe; on the
        // monitored probe it is expected routing through sing-box.
        let flag_fakeip = probe == RU_CONTROL_PROBE;
        classify(flag_fakeip, ips.as_deref(), rtt_ms)
    }

    fn probes(&self) -> Vec<(String, String)> {
        vec![
            ("nks".into(), "sb".into()),
            (RU_CONTROL_PROBE.into(), "sb".into()),
            (RU_CONTROL_PROBE.into(), "doh".into()),
        ]
    }

    fn preflight(&self) -> Readiness {
        if self.monitored_domain.is_empty() && self.ru_control_domain.is_empty() {
            Readiness::Unavailable("no resolver domain configured".into())
        } else {
            Readiness::Ready
        }
    }
}

/// Whether an IPv4 address falls in the sing-box fakeip range `198.18.0.0/15`.
fn is_fakeip_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 198 && (o[1] == 18 || o[1] == 19)
}

/// Pure verdict classification from a resolution outcome. `None` ⇒ the lookup
/// failed (TIMEOUT); an empty slice ⇒ the resolver answered with no address
/// (EMPTY); otherwise the first address is recorded, and — when `flag_fakeip` —
/// an answer in the fakeip range is FAKEIP, else OK.
fn classify(
    flag_fakeip: bool,
    ips: Option<&[IpAddr]>,
    rtt_ms: f64,
) -> (DnsVerdict, Option<String>, Option<f64>) {
    let Some(ips) = ips else {
        return (DnsVerdict::Timeout, None, None);
    };
    let Some(first) = ips.first() else {
        return (DnsVerdict::Empty, None, Some(rtt_ms));
    };
    let fakeip = flag_fakeip
        && ips.iter().any(|ip| match ip {
            IpAddr::V4(v4) => is_fakeip_v4(*v4),
            IpAddr::V6(_) => false,
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
    use super::*;

    #[test]
    fn fakeip_range_covers_198_18_and_198_19() {
        assert!(is_fakeip_v4(Ipv4Addr::new(198, 18, 0, 7)));
        assert!(is_fakeip_v4(Ipv4Addr::new(198, 19, 255, 255)));
        assert!(!is_fakeip_v4(Ipv4Addr::new(198, 20, 0, 1)));
        assert!(!is_fakeip_v4(Ipv4Addr::new(87, 250, 250, 242)));
    }

    #[test]
    fn control_probe_maps_to_ru_control_domain() {
        let r = DnsResolver::new(
            "nks.lab.mirari.ru".into(),
            "ya.ru".into(),
            "https://1.1.1.1/dns-query".into(),
        );
        assert_eq!(r.domain_for("nks"), "nks.lab.mirari.ru");
        assert_eq!(r.domain_for("ru"), "ya.ru");
        assert_eq!(r.domain_for("other"), "other");
        assert!(r.preflight().is_ready());
    }

    #[test]
    fn classify_fakeip_flagged_on_control_probe() {
        let ips = [IpAddr::V4(Ipv4Addr::new(198, 18, 0, 7))];
        let (v, ip, rtt) = classify(true, Some(&ips), 3.0);
        assert_eq!(v, DnsVerdict::FakeIp);
        assert_eq!(ip.as_deref(), Some("198.18.0.7"));
        assert_eq!(rtt, Some(3.0));
    }

    #[test]
    fn classify_fakeip_range_unflagged_is_ok() {
        // Same fakeip address, but not on the control probe ⇒ expected routing.
        let ips = [IpAddr::V4(Ipv4Addr::new(198, 18, 0, 9))];
        let (v, _, _) = classify(false, Some(&ips), 1.0);
        assert_eq!(v, DnsVerdict::Ok);
    }

    #[test]
    fn classify_ok_for_real_answer() {
        let ips = [IpAddr::V4(Ipv4Addr::new(87, 250, 250, 242))];
        let (v, _, _) = classify(true, Some(&ips), 1.0);
        assert_eq!(v, DnsVerdict::Ok);
    }

    #[test]
    fn classify_timeout_and_empty() {
        let (v, ip, rtt) = classify(true, None, 5.0);
        assert_eq!(v, DnsVerdict::Timeout);
        assert!(ip.is_none());
        assert!(rtt.is_none());

        let (v2, ip2, rtt2) = classify(true, Some(&[]), 5.0);
        assert_eq!(v2, DnsVerdict::Empty);
        assert!(ip2.is_none());
        assert_eq!(rtt2, Some(5.0));
    }
}
