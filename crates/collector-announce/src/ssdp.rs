//! What an SSDP message (UDP 1900, UPnP Device Architecture) says about its
//! sender. SSDP is HTTP-shaped text: a start line, then `Name: value`
//! headers, ending at a blank line.
//!
//! Three shapes matter:
//!
//! * `NOTIFY * HTTP/1.1` — a device announcing (`ssdp:alive`) or leaving
//!   (`ssdp:byebye`); `NT` names what it announces, `SERVER` how it describes
//!   itself, `USN` its unique name, `LOCATION` its description URL.
//! * `HTTP/1.1 200 OK` — a device answering somebody's search; the same
//!   headers with `ST` in place of `NT`.
//! * `M-SEARCH * HTTP/1.1` — somebody *asking*. Not an announcement: the
//!   sender is still a neighbour (the frame's addresses say so), but nothing
//!   here is a service it offers.

/// An SSDP announcement: the type announced and what the device said of itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsdpFacts {
    /// `NT` (notify) or `ST` (search response): `upnp:rootdevice`,
    /// `urn:schemas-upnp-org:device:MediaRenderer:1`, `uuid:…`.
    pub service: String,
    /// `SERVER` when present, else `LOCATION`, else `USN` — the most
    /// descriptive line the device volunteered, if any.
    pub detail: Option<String>,
}

/// Decode one SSDP payload. `None` for a search (`M-SEARCH`), a `byebye`,
/// a message without a type header, or bytes that are not SSDP at all.
#[must_use]
pub fn decode(payload: &[u8]) -> Option<SsdpFacts> {
    let text = std::str::from_utf8(payload).ok()?;
    let mut lines = text.lines();
    let start = lines.next()?.trim();
    let type_header = if start.starts_with("NOTIFY ") {
        "nt"
    } else if start.starts_with("HTTP/1.") {
        "st"
    } else {
        // M-SEARCH, or not SSDP.
        return None;
    };

    let mut service = None;
    let mut nts = None;
    let mut server = None;
    let mut location = None;
    let mut usn = None;
    for line in lines {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        match name.as_str() {
            n if n == type_header => service = Some(value.to_string()),
            "nts" => nts = Some(value.to_ascii_lowercase()),
            "server" => server = Some(value.to_string()),
            "location" => location = Some(value.to_string()),
            "usn" => usn = Some(value.to_string()),
            _ => {}
        }
    }
    // A device leaving is not offering anything.
    if nts.as_deref() == Some("ssdp:byebye") {
        return None;
    }
    Some(SsdpFacts {
        service: service?,
        detail: server.or(location).or(usn),
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) const NOTIFY_ALIVE: &str = "NOTIFY * HTTP/1.1\r\n\
HOST: 239.255.255.250:1900\r\n\
CACHE-CONTROL: max-age=1800\r\n\
LOCATION: http://192.168.1.1:1900/rootDesc.xml\r\n\
NT: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\
NTS: ssdp:alive\r\n\
SERVER: Linux/3.14 UPnP/1.0 MiniUPnPd/2.1\r\n\
USN: uuid:12345678-0000-0000-0000-000000000001::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\
\r\n";

    pub(crate) const M_SEARCH: &str = "M-SEARCH * HTTP/1.1\r\n\
HOST: 239.255.255.250:1900\r\n\
MAN: \"ssdp:discover\"\r\n\
MX: 1\r\n\
ST: ssdp:all\r\n\
\r\n";

    #[test]
    fn a_notify_alive_names_the_type_and_the_server_string() {
        let f = decode(NOTIFY_ALIVE.as_bytes()).unwrap();
        assert_eq!(
            f.service,
            "urn:schemas-upnp-org:device:InternetGatewayDevice:1"
        );
        assert_eq!(
            f.detail.as_deref(),
            Some("Linux/3.14 UPnP/1.0 MiniUPnPd/2.1")
        );
    }

    #[test]
    fn a_search_response_uses_st_and_falls_back_to_location() {
        let reply = "HTTP/1.1 200 OK\r\n\
Cache-Control: max-age=1800\r\n\
st: upnp:rootdevice\r\n\
Location: http://192.168.1.20:49152/description.xml\r\n\
USN: uuid:abc::upnp:rootdevice\r\n\
\r\n";
        let f = decode(reply.as_bytes()).unwrap();
        assert_eq!(f.service, "upnp:rootdevice");
        assert_eq!(
            f.detail.as_deref(),
            Some("http://192.168.1.20:49152/description.xml")
        );
    }

    #[test]
    fn a_search_a_byebye_and_junk_announce_nothing() {
        assert_eq!(decode(M_SEARCH.as_bytes()), None);
        let bye = NOTIFY_ALIVE.replace("ssdp:alive", "ssdp:byebye");
        assert_eq!(decode(bye.as_bytes()), None);
        assert_eq!(decode(b"NOTIFY * HTTP/1.1\r\nHOST: x\r\n\r\n"), None);
        assert_eq!(decode(&[0xff, 0xfe, 0x00]), None);
        assert_eq!(decode(b""), None);
    }

    /// Headers end at the blank line; a body (never sent by SSDP, but text is
    /// text) must not be read as headers.
    #[test]
    fn headers_stop_at_the_blank_line() {
        let msg = "NOTIFY * HTTP/1.1\r\nNT: upnp:rootdevice\r\n\r\nSERVER: not-a-header\r\n";
        let f = decode(msg.as_bytes()).unwrap();
        assert_eq!(f.detail, None);
    }
}
