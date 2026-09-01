use std::fmt;
use std::str::FromStr;

macro_rules! token_enum {
    ($name:ident { $($variant:ident => $token:literal),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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

// `Skip` is the quiet-mode token: the operator suppressed the gateway echo, so
// the probe did not run. It is NOT a health verdict — neither healthy nor failed —
// and the trigger conditions treat it as "no measurement" rather than as a state
// (SKIP, never silence).
token_enum!(GwVerdict { Ok => "OK", Fail => "FAIL", NoGw => "NOGW", Skip => "SKIP" });
token_enum!(TcpVerdict { Ok => "OK", Fail => "FAIL", Skip => "SKIP" });
token_enum!(DnsVerdict {
    Ok => "OK", FakeIp => "FAKEIP", Empty => "EMPTY", ServFail => "SERVFAIL",
    NxDomain => "NXDOMAIN", Timeout => "TIMEOUT", Skip => "SKIP",
});

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
    fn unknown_token_errors() {
        assert!(GwVerdict::from_str("BOGUS").is_err());
        assert!(DnsVerdict::from_str("").is_err());
    }
}
