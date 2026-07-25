use types::DnsSample;

use crate::facts::DnsFacts;

/// Pure mapping: one [`DnsSample`] per `(name, server)` probe pair the facts
/// declare. The verdict/ip/rtt come straight from [`DnsFacts::resolve`]; a
/// `FAKEIP` on a `.ru` name is decided in the facts and recorded here as-is.
pub fn build_dns_samples(ts_us: i64, facts: &dyn DnsFacts) -> Vec<DnsSample> {
    facts
        .probes()
        .into_iter()
        .map(|(probe, server)| {
            let (verdict, ip, rtt_ms) = facts.resolve(&probe, &server);
            DnsSample {
                ts_us,
                probe,
                server,
                verdict,
                ip,
                rtt_ms,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use collector_core::Readiness;
    use types::DnsVerdict;

    struct FakeFacts;
    impl DnsFacts for FakeFacts {
        fn resolve(&self, probe: &str, server: &str) -> (DnsVerdict, Option<String>, Option<f64>) {
            match (probe, server) {
                // A `.ru` control name answered from the fakeip range — always a bug.
                ("ru", "sb") => (DnsVerdict::FakeIp, Some("198.18.0.7".into()), Some(3.0)),
                ("nks", "doh") => (DnsVerdict::Ok, Some("10.0.0.1".into()), Some(9.0)),
                _ => (DnsVerdict::Timeout, None, None),
            }
        }
        fn probes(&self) -> Vec<(String, String)> {
            vec![("ru".into(), "sb".into()), ("nks".into(), "doh".into())]
        }
        fn preflight(&self) -> Readiness {
            Readiness::Ready
        }
    }

    #[test]
    fn one_row_per_probe_pair() {
        let rows = build_dns_samples(7, &FakeFacts);
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| r.ts_us == 7));
    }

    #[test]
    fn fakeip_on_ru_name_is_preserved() {
        let rows = build_dns_samples(7, &FakeFacts);
        let ru = rows.iter().find(|r| r.probe == "ru").unwrap();
        assert_eq!(ru.verdict, DnsVerdict::FakeIp);
        assert_eq!(ru.ip.as_deref(), Some("198.18.0.7"));
        assert_eq!(ru.rtt_ms, Some(3.0));
    }
}
