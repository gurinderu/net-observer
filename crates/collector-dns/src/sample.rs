use types::{DnsSample, DnsVerdict};

/// One resolved probe: the `(name, server)` pair together with the outcome of
/// resolving it. [`DnsCollector::collect`](crate::DnsCollector::collect) `await`s
/// the async [`DnsFacts`](crate::DnsFacts) probes to produce these, then hands
/// them to the sync [`build_dns_samples`] — keeping the sample assembly pure and
/// trivially testable.
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedProbe {
    /// The probe name label (e.g. `"nks"`, `"ru"`).
    pub probe: String,
    /// The resolver path used (e.g. `"sb"`, `"doh"`).
    pub server: String,
    /// The classified resolution verdict.
    pub verdict: DnsVerdict,
    /// The resolved IP, if any.
    pub ip: Option<String>,
    /// The measured round-trip time in milliseconds, if any.
    pub rtt_ms: Option<f64>,
}

/// Pure mapping: one [`DnsSample`] per already-resolved probe. The
/// verdict/ip/rtt come straight from [`DnsFacts::resolve`](crate::DnsFacts::resolve)
/// (awaited in `collect`); a `FAKEIP` on a `.ru` name is decided in the facts and
/// recorded here as-is.
#[must_use]
pub fn build_dns_samples(ts_us: i64, resolved: Vec<ResolvedProbe>) -> Vec<DnsSample> {
    resolved
        .into_iter()
        .map(|r| DnsSample {
            ts_us,
            probe: r.probe,
            server: r.server,
            verdict: r.verdict,
            ip: r.ip,
            rtt_ms: r.rtt_ms,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_resolved() -> Vec<ResolvedProbe> {
        vec![
            // A `.ru` control name answered from the fakeip range — always a bug.
            ResolvedProbe {
                probe: "ru".into(),
                server: "sb".into(),
                verdict: DnsVerdict::FakeIp,
                ip: Some("198.18.0.7".into()),
                rtt_ms: Some(3.0),
            },
            ResolvedProbe {
                probe: "nks".into(),
                server: "doh".into(),
                verdict: DnsVerdict::Ok,
                ip: Some("10.0.0.1".into()),
                rtt_ms: Some(9.0),
            },
        ]
    }

    #[test]
    fn one_row_per_resolved_probe() {
        let rows = build_dns_samples(7, sample_resolved());
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| r.ts_us == 7));
    }

    #[test]
    fn fakeip_on_ru_name_is_preserved() {
        let rows = build_dns_samples(7, sample_resolved());
        let ru = rows.iter().find(|r| r.probe == "ru").unwrap();
        assert_eq!(ru.verdict, DnsVerdict::FakeIp);
        assert_eq!(ru.ip.as_deref(), Some("198.18.0.7"));
        assert_eq!(ru.rtt_ms, Some(3.0));
    }
}
