//! The captive-detect HTTP exchange, both directions pure: the request bytes
//! the adapter writes, and the reading of whatever came back (realm
//! net-observer, node #176).

/// The request the probe sends: HTTP/1.0 with an explicit `Host`, so the
/// exchange is one round trip ending in EOF — no chunked answers, no
/// keep-alive to time out. The User-Agent names the probe honestly.
#[must_use]
pub fn detect_request(host: &str, path: &str) -> Vec<u8> {
    format!(
        "GET {path} HTTP/1.0\r\n\
         Host: {host}\r\n\
         User-Agent: net-observer-portal-probe\r\n\
         Connection: close\r\n\
         \r\n"
    )
    .into_bytes()
}

/// What one captive-detect answer says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeReading {
    /// `200` with `Success` in the body: the request went through untouched.
    Clean,
    /// Anything else that still parses as HTTP: something answered in the
    /// genuine endpoint's place. A redirect names the login page; `shape`
    /// says what the intercept looked like either way.
    Intercepted {
        login_url: Option<String>,
        shape: String,
    },
    /// Not an HTTP response at all: the probe died mid-answer or something
    /// non-HTTP sits on port 80. The absence of a measurement, never a
    /// portal.
    Unreadable(String),
}

/// Read one raw HTTP response. The genuine endpoint only ever answers
/// `200` + `Success`, so any parseable deviation is an intercept — including
/// a portal that serves its page directly with `200`, and RFC 6585's `511`.
#[must_use]
pub fn read_response(bytes: &[u8]) -> ProbeReading {
    // Headers are ASCII by contract; decode lossily so a stray byte in the
    // body cannot make the whole answer unreadable.
    let text = String::from_utf8_lossy(bytes);
    let (head, body) = match text.split_once("\r\n\r\n") {
        Some(pair) => pair,
        // A header block never terminated: truncated mid-headers.
        None => (text.as_ref(), ""),
    };
    let mut lines = head.lines();
    let status_line = lines.next().unwrap_or_default();
    let Some(status) = parse_status(status_line) else {
        return ProbeReading::Unreadable(format!(
            "not an HTTP response: {:.60}",
            status_line.escape_default()
        ));
    };
    if status == 200 && body.contains("Success") {
        return ProbeReading::Clean;
    }
    // A 200 whose body never arrived (deadline, error, truncation) is
    // indistinguishable from Apple's page cut short: the absence of a
    // reading, never a portal.
    if status == 200 && body.trim().is_empty() {
        return ProbeReading::Unreadable("HTTP 200 with no body read".into());
    }
    let location = lines
        .filter_map(|l| l.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("location"))
        .map(|(_, v)| v.trim().to_string())
        .filter(|v| !v.is_empty());
    let shape = if (300..400).contains(&status) {
        format!("redirect {status}")
    } else {
        format!("HTTP {status} without Success")
    };
    ProbeReading::Intercepted {
        login_url: location,
        shape,
    }
}

/// The status code of an `HTTP/1.x NNN …` line, or `None` when the line is
/// not one.
fn parse_status(line: &str) -> Option<u16> {
    let rest = line.strip_prefix("HTTP/")?;
    let mut parts = rest.split_ascii_whitespace();
    let _version = parts.next()?;
    parts.next()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_request_is_one_closed_http10_exchange() {
        let req =
            String::from_utf8(detect_request("captive.apple.com", "/hotspot-detect.html")).unwrap();
        assert!(req.starts_with("GET /hotspot-detect.html HTTP/1.0\r\n"));
        assert!(req.contains("Host: captive.apple.com\r\n"));
        assert!(req.contains("Connection: close\r\n"));
        assert!(req.ends_with("\r\n\r\n"));
    }

    #[test]
    fn apples_success_page_reads_clean() {
        let resp = b"HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n\
            <HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>\n";
        assert_eq!(read_response(resp), ProbeReading::Clean);
    }

    #[test]
    fn a_redirect_names_the_login_page() {
        let resp = b"HTTP/1.1 302 Found\r\n\
            Server: portal\r\n\
            location: http://login.wifi.smartspb.net/?mac=xx\r\n\r\n";
        assert_eq!(
            read_response(resp),
            ProbeReading::Intercepted {
                login_url: Some("http://login.wifi.smartspb.net/?mac=xx".into()),
                shape: "redirect 302".into(),
            }
        );
    }

    #[test]
    fn a_portal_serving_its_page_directly_is_still_an_intercept() {
        let resp = b"HTTP/1.0 200 OK\r\n\r\n<html>Welcome to SmartSPB WiFi</html>";
        assert_eq!(
            read_response(resp),
            ProbeReading::Intercepted {
                login_url: None,
                shape: "HTTP 200 without Success".into(),
            }
        );
        let resp511 = b"HTTP/1.1 511 Network Authentication Required\r\n\r\n";
        assert_eq!(
            read_response(resp511),
            ProbeReading::Intercepted {
                login_url: None,
                shape: "HTTP 511 without Success".into(),
            }
        );
    }

    #[test]
    fn garbage_and_truncation_are_unreadable_not_a_portal() {
        assert!(matches!(
            read_response(b"SSH-2.0-OpenSSH_9.6\r\n"),
            ProbeReading::Unreadable(_)
        ));
        assert!(matches!(read_response(b""), ProbeReading::Unreadable(_)));
        // A genuine 200 whose body was cut short (read deadline on a slow
        // link) must not fabricate a portal.
        assert!(matches!(
            read_response(b"HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n"),
            ProbeReading::Unreadable(_)
        ));
        assert!(matches!(
            read_response(b"HTTP/1.0 200 OK\r\nContent-Ty"),
            ProbeReading::Unreadable(_)
        ));
        // Truncated mid-headers: the status line alone still reads as an
        // intercepted answer only if it parses — here it does, and carries no
        // Location.
        assert_eq!(
            read_response(b"HTTP/1.1 302 Found\r\nLoca"),
            ProbeReading::Intercepted {
                login_url: None,
                shape: "redirect 302".into(),
            }
        );
    }
}
