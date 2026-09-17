use std::fmt;
use std::str::FromStr;

macro_rules! token_enum {
    ($(#[$attr:meta])* $name:ident { $($variant:ident => $token:literal),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
        $(#[$attr])*
        pub enum $name { $($variant),+ }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(match self { $(Self::$variant => $token),+ })
            }
        }
        impl FromStr for $name {
            type Err = ParseVerdictError;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                match s { $($token => Ok(Self::$variant),)+ _ => Err(ParseVerdictError(s.to_string())) }
            }
        }
    };
}

#[derive(Debug, thiserror::Error)]
#[error("unknown verdict token: {0}")]
pub struct ParseVerdictError(pub String);

// `Skip` is the withheld-probe token: the passive tier suppressed the gateway
// echo, so the probe did not run. It is NOT a health verdict — neither healthy
// nor failed — and the trigger conditions treat it as "no measurement" rather
// than as a state. What that obliges every reader to do, and why a change
// that happened *under* the passive tier must still be seen: realm
// `net-observer`, node #25.
token_enum!(GwVerdict { Ok => "OK", Fail => "FAIL", NoGw => "NOGW", Skip => "SKIP" });
token_enum!(TcpVerdict { Ok => "OK", Fail => "FAIL", Skip => "SKIP" });
// The `wifi` collector's verdict. `Ok` = the radio was associated and the tick
// carries a real reading; `Skip` = the probe could not run at all (no Wi-Fi
// interface, radio off, not associated) and `WifiSample::reason` says which.
// There is deliberately no `Fail`: a saturated channel is not a failed probe but
// a measurement — the numbers, not the verdict, carry that diagnosis. An
// individual field the API declined to give is `None` inside an `OK` sample, not
// a whole-sample SKIP.
token_enum!(WifiVerdict { Ok => "OK", Skip => "SKIP" });
// The `neighbors` collector's verdict. `Ok` = the neighbour tables were read
// (an empty table is still a reading — a network where nobody else answers is a
// fact); `Skip` = they could not be read at all and `reason` says why.
token_enum!(NeighborsVerdict { Ok => "OK", Skip => "SKIP" });
// The `air` collector's verdict. `Ok` = the radio-environment scan ran and
// `AirSample::aps` is what it heard (an empty list under `Ok` is the real reading
// "nobody else is audible"); `Skip` = the scan could not run at all — radio off,
// the system report failed, or it carried no wireless section — and `reason` says
// which. There is deliberately no `Fail`: a crowded channel is a measurement, not
// a failed probe. SKIP exists so that "could not look" is never rendered as an
// empty list, which would read as clear air.
token_enum!(AirVerdict { Ok => "OK", Skip => "SKIP" });
// How one neighbour came to be known. `Arp`/`Ndp` are the passive kernel caches
// read every tick; `Sweep` and `Mdns` only ever appear from an operator-pressed
// scan, so a row's source says whether the daemon merely listened or spoke.
token_enum!(NeighborSource { Arp => "arp", Ndp => "ndp", Sweep => "sweep", Mdns => "mdns" });
token_enum!(DnsVerdict {
    Ok => "OK", FakeIp => "FAKEIP", Empty => "EMPTY", ServFail => "SERVFAIL",
    NxDomain => "NXDOMAIN", Timeout => "TIMEOUT", Skip => "SKIP",
});
// The medium of the default-route interface a link sample describes, MEASURED
// from the hardware-port table (`networksetup -listallhardwareports`, readable
// by root without Location Services) — never inferred from whether a Wi-Fi
// name could be read: under root the SSID is `<redacted>` and the BSSID line
// is unproven (realm net-observer, nodes #93, #108), so readable names would
// make a Wi-Fi link look wired. Lowercase on the wire and in DuckDB, unlike
// the verdicts, which travel as their variant names. Not a verdict: it is a
// fact about the link, and `None` on the sample is "not determinable".
token_enum!(#[serde(rename_all = "lowercase")] LinkMedium { Wifi => "wifi", Wired => "wired" });

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gw_roundtrip() {
        for (v, s) in [
            (GwVerdict::Ok, "OK"),
            (GwVerdict::Fail, "FAIL"),
            (GwVerdict::NoGw, "NOGW"),
            (GwVerdict::Skip, "SKIP"),
        ] {
            assert_eq!(v.to_string(), s);
            assert_eq!(GwVerdict::from_str(s).unwrap(), v);
        }
    }

    #[test]
    fn tcp_roundtrip() {
        for (v, s) in [
            (TcpVerdict::Ok, "OK"),
            (TcpVerdict::Fail, "FAIL"),
            (TcpVerdict::Skip, "SKIP"),
        ] {
            assert_eq!(v.to_string(), s);
            assert_eq!(TcpVerdict::from_str(s).unwrap(), v);
        }
    }

    #[test]
    fn dns_roundtrip() {
        for (v, s) in [
            (DnsVerdict::Ok, "OK"),
            (DnsVerdict::FakeIp, "FAKEIP"),
            (DnsVerdict::Empty, "EMPTY"),
            (DnsVerdict::ServFail, "SERVFAIL"),
            (DnsVerdict::NxDomain, "NXDOMAIN"),
            (DnsVerdict::Timeout, "TIMEOUT"),
            (DnsVerdict::Skip, "SKIP"),
        ] {
            assert_eq!(v.to_string(), s);
            assert_eq!(DnsVerdict::from_str(s).unwrap(), v);
        }
    }

    #[test]
    fn wifi_roundtrip() {
        for (v, s) in [(WifiVerdict::Ok, "OK"), (WifiVerdict::Skip, "SKIP")] {
            assert_eq!(v.to_string(), s);
            assert_eq!(WifiVerdict::from_str(s).unwrap(), v);
        }
    }

    /// The medium is lowercase both as a DuckDB token and on the wire — the
    /// one token enum whose serde form is not the variant name.
    #[test]
    fn medium_roundtrip_is_lowercase_in_both_forms() {
        for (v, s) in [(LinkMedium::Wifi, "wifi"), (LinkMedium::Wired, "wired")] {
            assert_eq!(v.to_string(), s);
            assert_eq!(LinkMedium::from_str(s).unwrap(), v);
            assert_eq!(serde_json::to_string(&v).unwrap(), format!("\"{s}\""));
            assert_eq!(
                serde_json::from_str::<LinkMedium>(&format!("\"{s}\"")).unwrap(),
                v
            );
        }
    }

    #[test]
    fn unknown_token_errors() {
        assert!(GwVerdict::from_str("BOGUS").is_err());
        assert!(DnsVerdict::from_str("").is_err());
    }
}
