//! Destination parsing and address classification.

use std::net::IpAddr;

/// `host:port` from a `CONNECT` authority or an absolute-form URI.
pub fn split_host_port(authority: &str, default_port: u16) -> Option<(String, u16)> {
    let authority = authority.trim();
    if authority.is_empty() {
        return None;
    }
    // Bracketed IPv6.
    if let Some(rest) = authority.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &rest[..end];
        let port = match rest[end + 1..].strip_prefix(':') {
            Some(p) => p.parse().ok()?,
            None => default_port,
        };
        return Some((host.to_ascii_lowercase(), port));
    }
    match authority.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => Some((normalize_host(h), p.parse().ok()?)),
        _ => Some((normalize_host(authority), default_port)),
    }
}

fn normalize_host(h: &str) -> String {
    h.trim_end_matches('.').to_ascii_lowercase()
}

/// Loopback, private, link-local, unspecified, multicast, or otherwise not
/// a public unicast address (threat model N5).
pub fn is_non_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_documentation()
                || v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1]) // CGNAT
                || v4.octets()[0] == 0
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // unique local
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // link local
                || v6.to_ipv4_mapped().is_some_and(|v4| is_non_public(IpAddr::V4(v4)))
        }
    }
}

/// Cloud instance-metadata and other link-local service addresses. These
/// hand out credentials to anything that asks, so the proxy refuses them
/// unconditionally: `network.allow_private` does not lift this (N5).
pub fn is_metadata(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_link_local() // 169.254.0.0/16: AWS, GCP, Azure, OpenStack, ECS
                || v4.octets() == [100, 100, 100, 200] // Alibaba Cloud
        }
        IpAddr::V6(v6) => {
            v6.segments() == [0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254] // AWS IPv6 IMDS
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // link local
                || v6.to_ipv4_mapped().is_some_and(|v4| is_metadata(IpAddr::V4(v4)))
        }
    }
}

/// The host part of a `Host` header value, lower-cased, without a port or
/// IPv6 brackets.
pub fn host_header_name(value: &str) -> Option<String> {
    split_host_port(value, 0).map(|(h, _)| h)
}

/// Does `pattern` (`host`, `*.suffix`, optionally `:port`) match?
pub fn pattern_matches(pattern: &str, host: &str, port: u16) -> bool {
    let (pat_host, pat_port) = match pattern.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => match p.parse::<u16>() {
            Ok(p) => (h, Some(p)),
            Err(_) => (pattern, None),
        },
        _ => (pattern, None),
    };
    if pat_port.is_some_and(|p| p != port) {
        return false;
    }
    let pat_host = pat_host.to_ascii_lowercase();
    if let Some(suffix) = pat_host.strip_prefix("*.") {
        host.len() > suffix.len() + 1
            && host.ends_with(suffix)
            && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
    } else {
        pat_host == host
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_authorities() {
        assert_eq!(
            split_host_port("Api.Example.com:443", 80),
            Some(("api.example.com".into(), 443))
        );
        assert_eq!(
            split_host_port("example.com", 80),
            Some(("example.com".into(), 80))
        );
        assert_eq!(
            split_host_port("[::1]:8080", 80),
            Some(("::1".into(), 8080))
        );
        assert_eq!(split_host_port("[::1]", 443), Some(("::1".into(), 443)));
        assert_eq!(split_host_port("host:notaport", 80), None);
        assert_eq!(split_host_port("", 80), None);
    }

    #[test]
    fn classifies_addresses() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "192.168.1.1",
            "172.16.0.9",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:10.0.0.1",
        ] {
            assert!(is_non_public(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["8.8.8.8", "1.1.1.1", "2606:4700::1111", "203.0.113.1"] {
            // 203.0.113.0/24 is documentation space: treated as non-public.
            let expect = ip != "203.0.113.1";
            assert_eq!(!is_non_public(ip.parse().unwrap()), expect, "{ip}");
        }
    }

    #[test]
    fn metadata_addresses() {
        for ip in [
            "169.254.169.254",
            "169.254.170.2",
            "100.100.100.200",
            "fd00:ec2::254",
            "fe80::1",
            "::ffff:169.254.169.254",
        ] {
            assert!(is_metadata(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["10.0.0.1", "127.0.0.1", "8.8.8.8", "::1"] {
            assert!(!is_metadata(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn host_header_names() {
        assert_eq!(
            host_header_name("Example.com:8443").as_deref(),
            Some("example.com")
        );
        assert_eq!(host_header_name("[::1]:80").as_deref(), Some("::1"));
        assert_eq!(host_header_name("").as_deref(), None);
    }

    #[test]
    fn patterns() {
        assert!(pattern_matches("*.npmjs.org", "registry.npmjs.org", 443));
        assert!(!pattern_matches("*.npmjs.org", "npmjs.org", 443));
        assert!(!pattern_matches("*.npmjs.org", "evilnpmjs.org", 443));
        assert!(pattern_matches("localhost:8080", "localhost", 8080));
        assert!(!pattern_matches("localhost:8080", "localhost", 80));
        assert!(pattern_matches("API.example.com", "api.example.com", 1));
    }

    proptest::proptest! {
        #[test]
        fn split_never_panics(s in "\\PC{0,40}") {
            let _ = split_host_port(&s, 443);
        }
        #[test]
        fn pattern_never_panics(p in "\\PC{0,30}", h in "\\PC{0,30}") {
            let _ = pattern_matches(&p, &h, 443);
        }
    }
}
