//! Request-origin checks and the headers the front derives from the request.
//!
//! Cloudflare Access cookies are sent on cross-site requests, so every
//! authenticated endpoint refuses a browser request whose `Origin` is not the
//! site itself. Requests without an `Origin` (non-browser clients, plain
//! same-origin GETs) are not cross-site script requests and pass through to
//! token verification as before.

use crate::proto::ClientInfo;
use axum::http::HeaderMap;
use axum::http::header::{HOST, ORIGIN};

fn header(headers: &HeaderMap, name: impl axum::http::header::AsHeaderName) -> Option<&str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// False only when the request names an `Origin` whose authority (host and
/// port) differs from the `Host` it was sent to. `Origin: null` never matches.
pub fn is_same_origin(headers: &HeaderMap) -> bool {
    let Some(origin) = header(headers, ORIGIN) else {
        return true;
    };
    let Some(host) = header(headers, HOST) else {
        return false;
    };
    let authority = origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"));
    match authority {
        Some(authority) => !host.is_empty() && authority.eq_ignore_ascii_case(host),
        None => false,
    }
}

/// The `Host` header if it is a plain `name[:port]` (letters, digits, `.`,
/// `-`, and at most one `:port`), so it can be put into a response header.
fn plain_host(headers: &HeaderMap) -> Option<&str> {
    let host = header(headers, HOST)?;
    let (name, port) = match host.split_once(':') {
        Some((name, port)) => (name, Some(port)),
        None => (host, None),
    };
    let name_ok = !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
    let port_ok = port.is_none_or(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()));
    (name_ok && port_ok).then_some(host)
}

/// The Content-Security-Policy for a response to this request. Scripts may
/// connect only to the site itself; its WebSocket endpoint is named
/// explicitly because not every browser lets `'self'` cover `ws:`/`wss:`.
pub fn content_security_policy(headers: &HeaderMap) -> String {
    let connect = match plain_host(headers) {
        Some(host) => format!("'self' ws://{host} wss://{host}"),
        None => "'self'".to_string(),
    };
    format!(
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; \
         connect-src {connect}; img-src 'self'; media-src 'self' blob:; frame-ancestors 'none'"
    )
}

/// Where Cloudflare says the request came from. Informational only (logs and
/// the login notification): the values are validated for shape, not trusted.
pub fn client_info(headers: &HeaderMap) -> ClientInfo {
    {
        let ip = header(headers, "cf-connecting-ip")
            .and_then(|v| v.trim().parse::<std::net::IpAddr>().ok())
            .map(|ip| ip.to_string());
        let country = header(headers, "cf-ipcountry")
            .map(str::trim)
            .filter(|c| c.len() == 2 && c.chars().all(|ch| ch.is_ascii_alphanumeric()))
            .map(str::to_ascii_uppercase);
        ClientInfo { ip, country }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.parse().unwrap(),
            );
        }
        h
    }

    #[test]
    fn no_origin_is_not_a_cross_site_request() {
        assert!(is_same_origin(&headers(&[("host", "term.example.com")])));
        assert!(is_same_origin(&headers(&[])));
    }

    #[test]
    fn matching_origin_passes() {
        for (origin, host) in [
            ("https://term.example.com", "term.example.com"),
            ("https://Term.Example.com", "term.example.com"),
            ("http://127.0.0.1:7681", "127.0.0.1:7681"),
        ] {
            assert!(
                is_same_origin(&headers(&[("origin", origin), ("host", host)])),
                "{origin} vs {host}"
            );
        }
    }

    #[test]
    fn foreign_null_or_malformed_origin_is_refused() {
        for (origin, host) in [
            ("https://evil.example", "term.example.com"),
            ("https://term.example.com.evil.example", "term.example.com"),
            ("https://hud.example.com", "term.example.com"),
            ("https://term.example.com:8443", "term.example.com"),
            ("null", "term.example.com"),
            ("term.example.com", "term.example.com"),
            ("https://", ""),
        ] {
            assert!(
                !is_same_origin(&headers(&[("origin", origin), ("host", host)])),
                "{origin} vs {host}"
            );
        }
        assert!(!is_same_origin(&headers(&[(
            "origin",
            "https://term.example.com"
        )])));
    }

    #[test]
    fn csp_names_only_this_host_for_websockets() {
        let csp = content_security_policy(&headers(&[("host", "term.example.com")]));
        assert!(
            csp.contains("connect-src 'self' ws://term.example.com wss://term.example.com;"),
            "{csp}"
        );
        assert!(!csp.contains("wss:;") && !csp.contains("wss: "), "{csp}");
        assert!(csp.contains("frame-ancestors 'none'"));
    }

    #[test]
    fn csp_ignores_a_host_it_cannot_safely_echo() {
        for host in [
            "evil.example; script-src *",
            "a b",
            ":80",
            "h:port",
            "h:1:2",
        ] {
            let csp = content_security_policy(&headers(&[("host", host)]));
            assert!(csp.contains("connect-src 'self';"), "{host}: {csp}");
        }
        let csp = content_security_policy(&headers(&[]));
        assert!(csp.contains("connect-src 'self';"), "{csp}");
    }

    #[test]
    fn client_info_keeps_only_well_formed_values() {
        let c = client_info(&headers(&[
            ("cf-connecting-ip", "203.0.113.7"),
            ("cf-ipcountry", "ca"),
        ]));
        assert_eq!(c.ip.as_deref(), Some("203.0.113.7"));
        assert_eq!(c.country.as_deref(), Some("CA"));

        let c = client_info(&headers(&[
            ("cf-connecting-ip", "2001:db8::1"),
            ("cf-ipcountry", "T1"),
        ]));
        assert_eq!(c.ip.as_deref(), Some("2001:db8::1"));
        assert_eq!(c.country.as_deref(), Some("T1"));

        let c = client_info(&headers(&[
            ("cf-connecting-ip", "1.2.3.4; rm -rf"),
            ("cf-ipcountry", "Canada"),
        ]));
        assert_eq!(c, ClientInfo::default());
        assert_eq!(client_info(&headers(&[])), ClientInfo::default());
    }
}
