//! Local socket protocol shared by `observerd` (server) and `observer-bar` (client).
//!
//! The daemon is the sole owner of the DuckDB file; every other process reads
//! live status through a Unix-domain socket. This crate defines the wire types
//! and the newline-delimited JSON framing so both sides agree on the format.
//!
//! Deliberately runtime-agnostic: there is **no** tokio dependency here. The
//! blocking [`query`] client is all the bar needs; the async server in
//! `observerd` reuses [`write_frame`]/[`read_frame`] over its own runtime.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;

use serde::{Serialize, de::DeserializeOwned};
use types::{DnsSample, HostSample, LinkSample, ProxySample};

/// A request from a client (the bar) to the daemon.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum Request {
    /// Fetch the current live [`StatusSnapshot`].
    Status,
    /// Fetch the most recent incidents, newest first, capped at `limit`.
    Incidents { limit: usize },
}

/// A compact, serializable view of one incident for the live API.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct IncidentSummary {
    pub id: String,
    pub opened_us: i64,
    pub closed_us: Option<i64>,
    pub trigger_id: String,
    pub signature: String,
}

/// The live, in-memory status the daemon serves. Each collector's latest sample
/// plus a bounded ring of recent incidents.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct StatusSnapshot {
    pub generated_us: i64,
    pub link: Option<LinkSample>,
    pub proxy: Option<ProxySample>,
    pub dns: Option<DnsSample>,
    pub host: Option<HostSample>,
    pub incidents: Vec<IncidentSummary>,
}

/// A response from the daemon to a client.
///
/// `Status` is the large, hot variant; `Error`/`Incidents` are small. Clippy's
/// `large_enum_variant` would suggest boxing `StatusSnapshot`, but this is the
/// shared wire type both `observerd` (which constructs `Response::Status(..)`
/// directly) and `observer-bar` depend on, so introducing `Box` here would be a
/// cross-crate contract change and add an allocation on the common response path.
/// The size difference is intentional and harmless for a single-response socket
/// reply, so the lint is allowed rather than the type reshaped.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum Response {
    Status(StatusSnapshot),
    Incidents(Vec<IncidentSummary>),
    Error(String),
}

/// Blocking client for the bar: connect, write one newline-JSON request, read one
/// newline-JSON response. Framing = serde_json + `'\n'`. Connection-refused / no
/// socket ⇒ `Err` (the caller renders an "offline" state).
pub fn query(sock_path: &str, req: &Request) -> std::io::Result<Response> {
    let stream = UnixStream::connect(sock_path)?;
    let mut writer = &stream;
    write_frame(&mut writer, req)?;
    let mut reader = BufReader::new(&stream);
    read_frame(&mut reader)
}

/// Write one value as a single newline-terminated JSON frame.
///
/// Kept in one place so both sides share the exact wire format.
pub fn write_frame<W: Write, T: Serialize>(w: &mut W, v: &T) -> std::io::Result<()> {
    let mut buf = serde_json::to_vec(v)?;
    buf.push(b'\n');
    w.write_all(&buf)?;
    w.flush()
}

/// Read one newline-terminated JSON frame into a value.
///
/// Returns an `UnexpectedEof` error if the stream closes before a full frame.
pub fn read_frame<R: BufRead, T: DeserializeOwned>(r: &mut R) -> std::io::Result<T> {
    let mut line = String::new();
    let n = r.read_line(&mut line)?;
    if n == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "connection closed before a full frame was read",
        ));
    }
    serde_json::from_str(&line).map_err(std::io::Error::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::{GwVerdict, TcpVerdict};

    #[test]
    fn frame_round_trip_status_snapshot() {
        let snap = StatusSnapshot {
            generated_us: 1234,
            link: Some(LinkSample {
                ts_us: 1234,
                gw: GwVerdict::Ok,
                gw_rtt_ms: Some(1.5),
                direct: TcpVerdict::Ok,
                direct_rtt_ms: None,
                dhcp_router: Some("10.0.0.1".into()),
                dhcp_dns: None,
                gw_arp_mac: None,
                ssid: Some("home".into()),
                wifi_capture_present: false,
            }),
            proxy: None,
            dns: None,
            host: None,
            incidents: vec![IncidentSummary {
                id: "inc-1".into(),
                opened_us: 1000,
                closed_us: Some(2000),
                trigger_id: "fakeip".into(),
                signature: "sig".into(),
            }],
        };

        let mut buf = Vec::new();
        write_frame(&mut buf, &snap).unwrap();
        // Exactly one frame => exactly one trailing newline.
        assert_eq!(buf.iter().filter(|&&b| b == b'\n').count(), 1);

        let mut reader = std::io::BufReader::new(&buf[..]);
        let back: StatusSnapshot = read_frame(&mut reader).unwrap();

        assert_eq!(back.generated_us, snap.generated_us);
        assert_eq!(back.link, snap.link);
        assert_eq!(back.incidents.len(), 1);
        assert_eq!(back.incidents[0].id, "inc-1");
        assert_eq!(back.incidents[0].closed_us, Some(2000));
    }

    #[test]
    fn frame_round_trip_request() {
        let mut buf = Vec::new();
        write_frame(&mut buf, &Request::Incidents { limit: 7 }).unwrap();
        let mut reader = std::io::BufReader::new(&buf[..]);
        let back: Request = read_frame(&mut reader).unwrap();
        match back {
            Request::Incidents { limit } => assert_eq!(limit, 7),
            other => panic!("unexpected request variant: {other:?}"),
        }
    }

    #[test]
    fn read_frame_empty_stream_is_eof() {
        let empty: &[u8] = b"";
        let mut reader = std::io::BufReader::new(empty);
        let res: std::io::Result<Request> = read_frame(&mut reader);
        assert_eq!(res.unwrap_err().kind(), std::io::ErrorKind::UnexpectedEof);
    }
}
