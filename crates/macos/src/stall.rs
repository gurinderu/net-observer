//! Held reference streams — the established-flow discriminator.
//!
//! [`HeldReferenceStreams`] implements [`collector_proxy::StallProbe`]: it
//! keeps one long-lived TLS session per path open ACROSS ticks (the adapter
//! owns the sockets as state between `collect()` calls) and, each tick, sends
//! one `HEAD` request on each and waits for the response headers. A stream
//! that stops round-tripping is reported dead with its age and dropped, so the
//! next tick re-establishes it; a freshly opened stream reports no measurement
//! (its handshake proves nothing about longevity).
//!
//! Two paths, one reference host:
//! - `direct`: bound to the physical interface (`IP_BOUND_IF`) — the underlay
//!   path's treatment of a long-lived flow, bypassing any default TUN route.
//! - `tun`: on the default route — through the TUN while sing-box is up, so it
//!   holds one long-lived upstream VLESS connection open end-to-end: the exact
//!   flow class that stalls while fresh connections keep succeeding.
//!
//! The per-tick request is real application data on an established stream. An
//! app-silent held socket cannot serve here: every server (a VLESS inbound
//! most of all) times out or closes a connection that stops speaking, which
//! would read as a metronome of false stalls.

use std::sync::Arc;
use std::time::{Duration, Instant};

use collector_proxy::{StallProbe, StallReading, StreamCheck};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls;

use crate::net::open_bound_stream;

/// The reference host every held stream talks to. HTTPS on 1.1.1.1 answers
/// `HEAD /` on a keep-alive connection indefinitely, which is what a held
/// stream needs the far end to tolerate.
const REFERENCE_HOST: &str = "1.1.1.1";
const REFERENCE_PORT: u16 = 443;

/// Per-operation deadline: the TLS handshake, and each tick's request write /
/// response read. A stream that cannot round-trip within this is dead for the
/// purpose of the discriminator — sing-box's own upstream read timeout is far
/// looser, so this errs toward reporting the stall early, not late.
const STALL_TIMEOUT: Duration = Duration::from_secs(3);

/// A held stream is discarded, unmeasured, once the gap since it was last
/// exercised exceeds this many tick intervals. Consecutive ticks are one
/// interval apart, so three intervals cleanly separates ordinary jitter from an
/// unmeasured stretch — an operator `SetObserving(false)` pause (minutes) or a
/// host-starvation stall — across which the far end may have dropped the socket
/// for reasons that are not a fault.
const STALE_INTERVAL_MULTIPLE: u32 = 3;

/// The staleness bound (see [`STALE_INTERVAL_MULTIPLE`]) for a tick `interval`.
/// A pure function so the policy is checkable without a live stream.
fn stale_after(interval: Duration) -> Duration {
    interval.saturating_mul(STALE_INTERVAL_MULTIPLE)
}

/// Whole seconds of `d`, saturated into a `u32` for the wire.
fn secs_u32(d: Duration) -> u32 {
    d.as_secs().min(u64::from(u32::MAX)) as u32
}

/// The outcome of one round-trip attempt on a held stream.
enum Roundtrip {
    /// The stream carried the request and a response came back.
    Alive,
    /// The far end tore the connection down (a clean keep-alive FIN, or a
    /// reset): NOT a stall — a healthy path whose server closed an idle
    /// keep-alive behaves exactly like this. Reconnect and re-measure rather
    /// than fabricate a stall.
    TornDown,
    /// The request or response timed out with the socket still open — silent
    /// packet loss, which is the established-flow stall this signature hunts.
    Stalled,
}

/// One held stream: the TLS session, when it was established, and when it was
/// last exercised (for the staleness gate).
struct Held {
    stream: tokio_rustls::client::TlsStream<TcpStream>,
    opened_at: Instant,
    last_checked: Instant,
}

/// macOS implementation of [`StallProbe`]: two held reference streams, checked
/// each tick. See the module doc for the path semantics.
pub struct HeldReferenceStreams {
    /// Physical interface the `direct` stream binds to; empty ⇒ unbound.
    iface: String,
    /// A held stream idle longer than this is discarded unmeasured.
    stale_after: Duration,
    direct: Mutex<Option<Held>>,
    tun: Mutex<Option<Held>>,
    connector: TlsConnector,
}

impl HeldReferenceStreams {
    /// Build the prober. `iface` is the physical interface for the direct
    /// (underlay) stream; the tunnel stream always uses the default route.
    /// `interval` is the proxy collector's tick cadence, from which the
    /// staleness bound is derived.
    #[must_use]
    pub fn new(iface: impl Into<String>, interval: Duration) -> Self {
        Self {
            iface: iface.into(),
            stale_after: stale_after(interval),
            direct: Mutex::new(None),
            tun: Mutex::new(None),
            connector: build_connector(),
        }
    }

    /// Check one slot against the shared per-tick `now`: discard a stream idle
    /// across a gap larger than [`Self::stale_after`] (unmeasured), establish a
    /// missing one (no measurement this tick), or round-trip the held one. Ages
    /// are measured from `now` so the direct and tun readings of one tick are
    /// comparable.
    async fn check_slot(
        &self,
        slot: &Mutex<Option<Held>>,
        iface: Option<&str>,
        now: Instant,
    ) -> Option<StreamCheck> {
        let mut guard = slot.lock().await;
        // A stream that sat idle across an unmeasured stretch (a pause, a
        // starvation stall) may have been dropped by the far-end NAT/idle
        // timeout for a reason that is NOT a fault. Discard it and re-measure
        // on a fresh one rather than read a stale socket as a stall.
        if guard
            .as_ref()
            .is_some_and(|h| now.saturating_duration_since(h.last_checked) > self.stale_after)
        {
            *guard = None;
        }
        match guard.as_mut() {
            None => {
                *guard = self.establish(iface, now).await;
                None
            }
            Some(held) => {
                let age_s = secs_u32(now.saturating_duration_since(held.opened_at));
                match roundtrip(&mut held.stream).await {
                    Roundtrip::Alive => {
                        held.last_checked = now;
                        Some(StreamCheck { alive: true, age_s })
                    }
                    Roundtrip::Stalled => {
                        *guard = None;
                        Some(StreamCheck {
                            alive: false,
                            age_s,
                        })
                    }
                    Roundtrip::TornDown => {
                        // A torn-down keep-alive is not a fault: reconnect so the
                        // next tick measures a live stream, and report no
                        // measurement this tick.
                        *guard = self.establish(iface, now).await;
                        None
                    }
                }
            }
        }
    }

    /// Open a TCP connection (interface-bound when `iface` is `Some`, and then
    /// STRICTLY so — a failed bind is a failed establish, never a silent
    /// default-route fallback) to the reference host and complete a TLS
    /// handshake over it. `opened_at`/`last_checked` are stamped from the
    /// tick's shared `now`.
    async fn establish(&self, iface: Option<&str>, now: Instant) -> Option<Held> {
        let stream =
            open_bound_stream(REFERENCE_HOST, REFERENCE_PORT, iface, iface.is_some()).await?;
        let server_name = rustls::pki_types::ServerName::try_from(REFERENCE_HOST)
            .ok()?
            .to_owned();
        match timeout(STALL_TIMEOUT, self.connector.connect(server_name, stream)).await {
            Ok(Ok(tls)) => Some(Held {
                stream: tls,
                opened_at: now,
                last_checked: now,
            }),
            _ => {
                tracing::debug!(?iface, "held reference stream failed to establish");
                None
            }
        }
    }
}

impl StallProbe for HeldReferenceStreams {
    async fn check(&self) -> StallReading {
        // ONE monotonic reading for the whole tick, so the direct and tun ages
        // are measured against the same instant and stay comparable.
        let now = Instant::now();
        let iface = (!self.iface.is_empty()).then_some(self.iface.as_str());
        StallReading {
            direct: self.check_slot(&self.direct, iface, now).await,
            tun: self.check_slot(&self.tun, None, now).await,
        }
    }

    /// Drop both held sessions. Dropping the TLS stream closes its socket, so
    /// after this nothing of ours is open toward the reference host; the next
    /// `check` establishes fresh streams and reports no measurement, exactly
    /// as it does after a teardown. Called every passive tick, and a no-op on
    /// an already-empty slot.
    async fn close(&self) {
        *self.direct.lock().await = None;
        *self.tun.lock().await = None;
    }
}

/// One `HEAD` round-trip on the held TLS session, classified into
/// [`Roundtrip`]. A timeout with the socket still open is a stall; a clean EOF
/// or a connection error is a teardown, not a stall (see [`Roundtrip`]).
async fn roundtrip(stream: &mut tokio_rustls::client::TlsStream<TcpStream>) -> Roundtrip {
    let req = b"HEAD / HTTP/1.1\r\nHost: 1.1.1.1\r\nConnection: keep-alive\r\n\r\n";
    match timeout(STALL_TIMEOUT, stream.write_all(req)).await {
        Ok(Ok(())) => {}
        Ok(Err(_)) => return Roundtrip::TornDown, // the far end had already gone
        Err(_) => return Roundtrip::Stalled,      // the write itself hung
    }
    // Read until the header terminator. `HEAD` carries no body, so the response
    // ends at the blank line and nothing is left on the stream for the next
    // tick; a response past the cap still proved the stream carries.
    let mut seen: Vec<u8> = Vec::with_capacity(1024);
    let mut buf = [0u8; 1024];
    loop {
        match timeout(STALL_TIMEOUT, stream.read(&mut buf)).await {
            Ok(Ok(0)) => return Roundtrip::TornDown, // clean FIN before a response
            Ok(Ok(n)) => {
                seen.extend_from_slice(&buf[..n]);
                if seen.windows(4).any(|w| w == b"\r\n\r\n") || seen.len() > 16 * 1024 {
                    return Roundtrip::Alive;
                }
            }
            Ok(Err(_)) => return Roundtrip::TornDown, // reset mid-read
            Err(_) => return Roundtrip::Stalled,      // silent packet loss: the stall
        }
    }
}

/// Build the TLS connector for the held streams: the process-default crypto
/// provider (graviola), and a verifier that accepts any certificate — the
/// probe measures whether the PATH still carries an established stream, not
/// who is at the far end, and no data of value flows on it.
fn build_connector() -> TlsConnector {
    crate::tls::install_default_provider();
    let provider = rustls::crypto::CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls_graviola::default_provider()));
    let config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("the graviola provider supports the default protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

/// Accept-anything certificate verifier (see [`build_connector`]).
#[derive(Debug)]
struct NoVerify(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The staleness bound is three tick intervals — strictly greater than one
    /// interval, so an ordinary tick is never discarded, while a pause (many
    /// intervals) always is. Dies under a multiple of 1 (every tick would look
    /// stale, silencing the signature) or 0.
    #[test]
    fn stale_after_is_three_intervals_and_exceeds_one() {
        let interval = Duration::from_secs(15);
        assert_eq!(stale_after(interval), Duration::from_secs(45));
        assert!(
            stale_after(interval) > interval,
            "the bound must exceed one interval, or every tick discards its own stream"
        );
    }

    /// A gap of one interval is fresh; a gap of many intervals (a pause) is
    /// stale — the exact boundary the pause/resume false-positive turns on.
    #[test]
    fn a_paused_gap_is_stale_a_tick_gap_is_not() {
        let bound = stale_after(Duration::from_secs(15));
        assert!(Duration::from_secs(15) <= bound, "one tick is fresh");
        assert!(
            Duration::from_secs(600) > bound,
            "a minutes-long pause is stale"
        );
    }

    /// Age saturates into `u32` rather than wrapping — a stream held for longer
    /// than `u32::MAX` seconds reports the ceiling, never a small wrapped value.
    #[test]
    fn secs_u32_saturates() {
        assert_eq!(secs_u32(Duration::from_secs(45)), 45);
        assert_eq!(
            secs_u32(Duration::from_secs(u64::from(u32::MAX) + 10)),
            u32::MAX
        );
    }
}
