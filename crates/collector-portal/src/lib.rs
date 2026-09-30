//! `collector-portal` — the captive-portal probe's logic (realm net-observer,
//! nodes #177, #178).
//!
//! Reactive, not ticked: a fresh address on a physical interface starts a
//! series of probes with growing pauses, so the probe outlives sing-box's
//! rebind to the new interface — the race that killed the OS's own one-shot
//! probe (realm net-observer, node #173). Everything here is pure and
//! unit-tested: the schedule, the HTTP request and its reading, the DNS
//! packet work. The sockets live in the `macos` adapter behind
//! [`PortalProbe`]; the driving loop lives in the daemon.

pub mod dns;
pub mod http;
pub mod schedule;

use collector_core::{CollectorMeta, Os};
use types::{PortalSample, PortalVerdict, RouteEvent};

use crate::http::ProbeReading;

/// Static metadata for the `portal` prober: macOS-only in v1.
pub const META: CollectorMeta = CollectorMeta {
    name: "portal",
    supported_os: &[Os::MacOs],
};

/// The captive-detect endpoint — Apple's contract: a portal-free network
/// answers `Success`, an intercepting one answers anything else (realm
/// net-observer, node #176).
pub const DETECT_HOST: &str = "captive.apple.com";
/// See [`DETECT_HOST`].
pub const DETECT_PATH: &str = "/hotspot-detect.html";

/// One raw fetch of the captive-detect URL, pinned to `iface` so the tunnel
/// cannot answer for the underlay: DNS at the interface's DHCP resolver, TCP
/// under `IP_BOUND_IF`. Returns the raw HTTP response bytes (bounded by the
/// adapter), or the transport failure as words.
#[allow(async_fn_in_trait)] // internal workspace port, not a published API
pub trait PortalProbe: Send + Sync {
    async fn fetch(&self, iface: &str) -> Result<Vec<u8>, String>;
}

/// The route events that start a probe series: a fresh address on a physical
/// interface (`RTM_NEWADDR` on `en*`) — the moment a captive network can
/// newly stand between this machine and the world. Route-table adds are
/// deliberately NOT triggers: macOS clones host routes constantly, and each
/// would put a probe on the wire; a gateway change without a fresh lease is
/// caught by the passive log path instead (realm net-observer, node #179).
#[must_use]
pub fn series_trigger(e: &RouteEvent) -> Option<&str> {
    let iface = e.iface.as_deref()?;
    if !iface.starts_with("en") {
        return None;
    }
    (e.kind == "addr" && e.detail == "RTM_NEWADDR").then_some(iface)
}

/// Fold one probe attempt's outcome into the sample fields:
/// `(verdict, login_url, reason)`.
///
/// A transport failure and an unreadable answer are both `SKIP` — a probe
/// that died is the absence of a measurement, never a portal (the same rule
/// the killed-before-header egress capture follows).
#[must_use]
pub fn attempt_fields(
    fetched: Result<Vec<u8>, String>,
) -> (PortalVerdict, Option<String>, Option<String>) {
    match fetched {
        Err(reason) => (PortalVerdict::Skip, None, Some(reason)),
        Ok(bytes) => match http::read_response(&bytes) {
            ProbeReading::Clean => (PortalVerdict::Ok, None, None),
            ProbeReading::Intercepted { login_url, shape } => {
                (PortalVerdict::Portal, login_url, Some(shape))
            }
            ProbeReading::Unreadable(reason) => (PortalVerdict::Skip, None, Some(reason)),
        },
    }
}

/// Compose the sample one finished attempt writes.
#[must_use]
pub fn build_sample(
    ts_us: i64,
    iface: &str,
    verdict: PortalVerdict,
    login_url: Option<String>,
    reason: Option<String>,
) -> PortalSample {
    PortalSample {
        ts_us,
        iface: iface.to_string(),
        verdict,
        login_url,
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(kind: &str, iface: Option<&str>, detail: &str) -> RouteEvent {
        RouteEvent {
            ts_us: 1,
            kind: kind.into(),
            iface: iface.map(Into::into),
            detail: detail.into(),
        }
    }

    #[test]
    fn a_fresh_address_on_a_physical_interface_triggers() {
        assert_eq!(
            series_trigger(&event("addr", Some("en0"), "RTM_NEWADDR")),
            Some("en0")
        );
        assert_eq!(
            series_trigger(&event("addr", Some("en13"), "RTM_NEWADDR")),
            Some("en13")
        );
    }

    #[test]
    fn tunnels_deletes_and_route_churn_do_not_trigger() {
        // The tunnel's own address is not a network change underneath us.
        assert_eq!(
            series_trigger(&event("addr", Some("utun6"), "RTM_NEWADDR")),
            None
        );
        // A lost address is a teardown, not a fresh network.
        assert_eq!(
            series_trigger(&event("addr", Some("en0"), "RTM_DELADDR")),
            None
        );
        // Route adds storm (cloned host routes) — never a trigger.
        assert_eq!(
            series_trigger(&event("route", Some("en0"), "RTM_ADD")),
            None
        );
        assert_eq!(
            series_trigger(&event("iface", Some("en0"), "RTM_IFINFO")),
            None
        );
        assert_eq!(series_trigger(&event("addr", None, "RTM_NEWADDR")), None);
    }

    #[test]
    fn attempt_fields_map_the_three_outcomes() {
        // Transport failure → SKIP with the reason.
        let (v, url, reason) = attempt_fields(Err("bound connect failed".into()));
        assert_eq!(v, PortalVerdict::Skip);
        assert!(url.is_none());
        assert_eq!(reason.as_deref(), Some("bound connect failed"));

        // A clean Success → OK, nothing else to say.
        let clean = b"HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n\
            <HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>";
        let (v, url, reason) = attempt_fields(Ok(clean.to_vec()));
        assert_eq!(v, PortalVerdict::Ok);
        assert!(url.is_none() && reason.is_none());

        // A redirect → PORTAL with the login page.
        let redir = b"HTTP/1.0 302 Found\r\nLocation: http://login.wifi.example/\r\n\r\n".to_vec();
        let (v, url, _) = attempt_fields(Ok(redir));
        assert_eq!(v, PortalVerdict::Portal);
        assert_eq!(url.as_deref(), Some("http://login.wifi.example/"));
    }
}
