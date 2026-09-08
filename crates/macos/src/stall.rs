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

/// One held stream: the TLS session and when it was established.
struct Held {
    stream: tokio_rustls::client::TlsStream<TcpStream>,
    opened_at: Instant,
}

/// macOS implementation of [`StallProbe`]: two held reference streams, checked
/// each tick. See the module doc for the path semantics.
pub struct HeldReferenceStreams {
    /// Physical interface the `direct` stream binds to; empty ⇒ unbound.
    iface: String,
    direct: Mutex<Option<Held>>,
    tun: Mutex<Option<Held>>,
    connector: TlsConnector,
}

impl HeldReferenceStreams {
    /// Build the prober. `iface` is the physical interface for the direct
    /// (underlay) stream; the tunnel stream always uses the default route.
    #[must_use]
    pub fn new(iface: impl Into<String>) -> Self {
        Self {
            iface: iface.into(),
            direct: Mutex::new(None),
            tun: Mutex::new(None),
            connector: build_connector(),
        }
    }

    /// Check one slot: establish a missing stream (no measurement this tick),
    /// or round-trip the held one and report alive/dead with its age. A dead
    /// stream is dropped so the next tick re-establishes it.
    async fn check_slot(
        &self,
        slot: &Mutex<Option<Held>>,
        iface: Option<&str>,
    ) -> Option<StreamCheck> {
        let mut guard = slot.lock().await;
        match guard.as_mut() {
            None => {
                *guard = self.establish(iface).await;
                None
            }
            Some(held) => {
                let age_s = held.opened_at.elapsed().as_secs().min(u64::from(u32::MAX)) as u32;
                let alive = roundtrip(&mut held.stream).await;
                if !alive {
                    *guard = None;
                }
                Some(StreamCheck { alive, age_s })
            }
        }
    }

    /// Open a TCP connection (optionally interface-bound) to the reference
    /// host and complete a TLS handshake over it.
    async fn establish(&self, iface: Option<&str>) -> Option<Held> {
        let stream = open_bound_stream(REFERENCE_HOST, REFERENCE_PORT, iface).await?;
        let server_name = rustls::pki_types::ServerName::try_from(REFERENCE_HOST)
            .ok()?
            .to_owned();
        match timeout(STALL_TIMEOUT, self.connector.connect(server_name, stream)).await {
            Ok(Ok(tls)) => Some(Held {
                stream: tls,
                opened_at: Instant::now(),
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
        let iface = (!self.iface.is_empty()).then_some(self.iface.as_str());
        StallReading {
            direct: self.check_slot(&self.direct, iface).await,
            tun: self.check_slot(&self.tun, None).await,
        }
    }
}

/// One `HEAD` round-trip on the held TLS session: write the request, read
/// until the response headers end. `false` on any error, EOF, or timeout —
/// the stream stopped carrying.
async fn roundtrip(stream: &mut tokio_rustls::client::TlsStream<TcpStream>) -> bool {
    let req = b"HEAD / HTTP/1.1\r\nHost: 1.1.1.1\r\nConnection: keep-alive\r\n\r\n";
    match timeout(STALL_TIMEOUT, stream.write_all(req)).await {
        Ok(Ok(())) => {}
        _ => return false,
    }
    // Read until the header terminator. `HEAD` carries no body, so nothing is
    // left on the stream for the next tick; a response longer than the cap
    // still proved the stream carries and counts as alive.
    let mut seen: Vec<u8> = Vec::with_capacity(1024);
    let mut buf = [0u8; 1024];
    loop {
        match timeout(STALL_TIMEOUT, stream.read(&mut buf)).await {
            Ok(Ok(0)) => return false,
            Ok(Ok(n)) => {
                seen.extend_from_slice(&buf[..n]);
                if seen.windows(4).any(|w| w == b"\r\n\r\n") || seen.len() > 16 * 1024 {
                    return true;
                }
            }
            _ => return false,
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
