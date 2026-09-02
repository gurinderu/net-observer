//! Best-effort, heuristic extraction of a product+version from a service banner.
//!
//! This is explicitly a **guess**. Banners are unstructured and frequently
//! spoofed or truncated; a parse here yields at best a Low/Medium-confidence
//! lead, never a fact. It recognises a few common shapes and gives up honestly
//! on everything else (returning `None`).
//!
//! Recognised shapes:
//! - SSH identification strings: `SSH-2.0-OpenSSH_7.4`, `SSH-2.0-OpenSSH_8.2p1 Ubuntu-4`.
//! - HTTP `Server:` headers: `Server: nginx/1.18.0`, `Apache/2.4.41 (Ubuntu)`,
//!   or a bare `nginx/1.18.0`.

use crate::cpe::Cpe;

/// Try to pull a product+version guess out of a service banner.
///
/// Heuristic and low-confidence by design. Returns `None` when nothing
/// recognisable is found.
pub fn parse_banner(banner: &str) -> Option<Cpe> {
    let banner = banner.trim();
    if banner.is_empty() {
        return None;
    }

    if let Some(cpe) = parse_ssh(banner) {
        return Some(cpe);
    }
    parse_http_server(banner)
}

/// `SSH-2.0-OpenSSH_7.4p1 Debian-10` -> product `openssh`, version `7.4p1`.
fn parse_ssh(banner: &str) -> Option<Cpe> {
    let rest = banner.strip_prefix("SSH-")?;
    // Skip the protocol version field: `2.0-<software>`.
    let dash = rest.find('-')?;
    let software = &rest[dash + 1..];
    // The software field is `<product>_<version>`, then optional space comment.
    let software = software.split_whitespace().next()?;
    let (product, version) = software.split_once('_')?;
    if product.is_empty() || version.is_empty() {
        return None;
    }
    let version = sanitize_version(version)?;
    Some(Cpe {
        vendor: None,
        product: product.to_ascii_lowercase(),
        version: Some(version),
    })
}

/// `Server: nginx/1.18.0` or `Apache/2.4.41 (Ubuntu)` -> product + version.
fn parse_http_server(banner: &str) -> Option<Cpe> {
    let value = match banner.split_once(':') {
        Some((key, v)) if key.eq_ignore_ascii_case("server") => v.trim(),
        _ => banner,
    };
    // Take the first token, of the form `product/version`.
    let token = value.split_whitespace().next()?;
    let (product, version) = token.split_once('/')?;
    if product.is_empty() || version.is_empty() {
        return None;
    }
    let version = sanitize_version(version)?;
    Some(Cpe {
        vendor: None,
        product: product.to_ascii_lowercase(),
        version: Some(version),
    })
}

/// Keep only a leading run that looks like a version (digits, dots and the
/// usual patch suffixes). Returns `None` if it does not start with a digit.
fn sanitize_version(raw: &str) -> Option<String> {
    if !raw.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }
    let v: String = raw
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '.')
        .collect();
    if v.is_empty() { None } else { Some(v) }
}
