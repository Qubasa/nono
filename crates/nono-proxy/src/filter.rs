//! Async host filtering wrapping the library's [`HostFilter`](nono::HostFilter).
//!
//! Checks the hostname against the allowlist/deny list before resolving DNS,
//! then resolves and checks the resulting IPs against the link-local range
//! (cloud metadata SSRF protection).

use crate::config::{is_proxy_denied_metadata_ip, parse_host_ip_literal};
use crate::error::Result;
use nono::net_filter::{FilterResult, HostFilter};
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use tracing::debug;

/// Result of a filter check including resolved socket addresses.
///
/// When the filter allows a host, `resolved_addrs` contains the DNS-resolved
/// addresses. Callers MUST connect to these addresses (not re-resolve the
/// hostname) to prevent DNS rebinding TOCTOU attacks.
pub struct CheckResult {
    /// The filter decision
    pub result: FilterResult,
    /// DNS-resolved addresses (empty if denied or DNS failed)
    pub resolved_addrs: Vec<SocketAddr>,
}

/// Async wrapper around `HostFilter` that performs DNS resolution.
#[derive(Debug, Clone)]
pub struct ProxyFilter {
    inner: HostFilter,
    ssh_pins: SshPins,
}

/// Port-exact SSH endpoints: every port named here is closed on every host
/// that is not listed, whatever the allowlist says.
///
/// This is what makes `network.allow_ssh` narrowing. The allowlist alone
/// cannot express it: an empty allowlist means allow-all, so adding the
/// endpoint to it would either change nothing or, if it were the only
/// entry, close every other destination too.
#[derive(Debug, Clone, Default)]
struct SshPins {
    ports: BTreeSet<u16>,
    authorities: BTreeSet<String>,
}

impl SshPins {
    fn denies(&self, authority: &str, port: u16) -> bool {
        self.ports.contains(&port) && !self.authorities.contains(authority)
    }
}

impl ProxyFilter {
    /// Create a new proxy filter with the given allowed hosts.
    #[must_use]
    pub fn new(allowed_hosts: &[String]) -> Self {
        Self {
            inner: HostFilter::new(allowed_hosts),
            ssh_pins: SshPins::default(),
        }
    }

    /// Create a strict proxy filter: an empty allowlist denies every host.
    #[must_use]
    pub fn new_strict(allowed_hosts: &[String]) -> Self {
        Self {
            inner: HostFilter::new_strict(allowed_hosts),
            ssh_pins: SshPins::default(),
        }
    }

    /// Create a filter that allows all hosts (except cloud metadata).
    #[must_use]
    pub fn allow_all() -> Self {
        Self {
            inner: HostFilter::allow_all(),
            ssh_pins: SshPins::default(),
        }
    }

    /// Append user-configured deny entries. Evaluated before the allowlist.
    ///
    /// Supports the same wildcard syntax as the allowlist (`*.example.com`).
    #[must_use]
    pub fn with_denied_hosts(self, denied: &[String]) -> Self {
        if denied.is_empty() {
            return self;
        }
        Self {
            inner: self.inner.with_denied_hosts(denied),
            ssh_pins: self.ssh_pins,
        }
    }

    /// Pin the ports named by `network.allow_ssh` to the hosts listed.
    ///
    /// Entries are `host:port`. Each port becomes unreachable on every other
    /// host, so a lone SSH allowance narrows port 22 without closing any
    /// other port. An entry that is not `host:port` is dropped with a
    /// warning: it can only ever have contributed a deny, so dropping it
    /// leaves the port as open as it was, never more open.
    #[must_use]
    pub fn with_ssh_endpoints(mut self, endpoints: &[String]) -> Self {
        for entry in endpoints {
            let Some((host, port)) = split_authority(entry) else {
                tracing::warn!("ignoring malformed allow_ssh endpoint: {entry}");
                continue;
            };
            self.ssh_pins.ports.insert(port);
            self.ssh_pins.authorities.insert(authority(&host, port));
        }
        self
    }

    /// Check a host against the filter with async DNS resolution.
    ///
    /// The allowlist/deny check runs on the hostname alone before any DNS
    /// lookup, since resolution itself sends a query to the domain's
    /// nameserver and would leak the hostname even for a denied host.
    ///
    /// Once resolved, all resolved IPs are checked against the link-local
    /// deny range (cloud metadata SSRF / DNS rebinding protection).
    ///
    /// On success, returns both the filter result and the resolved socket
    /// addresses. Callers MUST use `resolved_addrs` to connect to the upstream
    /// instead of re-resolving the hostname, eliminating the DNS rebinding
    /// TOCTOU window.
    pub async fn check_host(&self, host: &str, port: u16) -> Result<CheckResult> {
        let pre_check = proxy_metadata_filter_result(host, &[])
            .unwrap_or_else(|| self.check_host_result(host, port, &[]));

        if !pre_check.is_allowed() {
            return Ok(CheckResult {
                result: pre_check,
                resolved_addrs: Vec::new(),
            });
        }

        let addr_str = format!("{}:{}", host, port);
        let resolved: Vec<SocketAddr> = match tokio::net::lookup_host(&addr_str).await {
            Ok(addrs) => addrs.collect(),
            Err(e) => {
                debug!("DNS resolution failed for {}: {}", host, e);
                Vec::new()
            }
        };

        let resolved_ips: Vec<IpAddr> = resolved.iter().map(|a| a.ip()).collect();
        let result = proxy_metadata_filter_result(host, &resolved_ips)
            .unwrap_or_else(|| self.check_host_result(host, port, &resolved_ips));

        // Only return resolved addrs on allow to prevent misuse
        let addrs = if result.is_allowed() {
            resolved
        } else {
            Vec::new()
        };

        Ok(CheckResult {
            result,
            resolved_addrs: addrs,
        })
    }

    /// Check a host with pre-resolved IPs (no DNS lookup).
    #[must_use]
    pub fn check_host_with_ips(&self, host: &str, resolved_ips: &[IpAddr]) -> FilterResult {
        proxy_metadata_filter_result(host, resolved_ips)
            .unwrap_or_else(|| self.inner.check_host(host, resolved_ips))
    }

    /// Checks the SSH pins and deny (incl. `host:port`) before the allowlist,
    /// so neither a wildcard `allow_domain: ["*"]` nor an empty allowlist can
    /// shadow a port-scoped refusal.
    fn check_host_result(&self, host: &str, port: u16, resolved_ips: &[IpAddr]) -> FilterResult {
        let host_port = authority(host, port);

        if self.ssh_pins.denies(&host_port, port) {
            return FilterResult::DenyNotAllowed { host: host_port };
        }

        if let Some(deny) = self.inner.check_deny(&host_port) {
            return deny;
        }
        if let Some(deny) = self.inner.check_deny(host) {
            return deny;
        }

        let result = self.inner.check_host(host, resolved_ips);
        if !matches!(result, FilterResult::DenyNotAllowed { .. }) {
            return result;
        }

        self.inner.check_host(&host_port, resolved_ips)
    }

    /// Number of allowed hosts configured.
    #[must_use]
    pub fn allowed_count(&self) -> usize {
        self.inner.allowed_count()
    }
}

/// Canonical `host:port`, normalized and IPv6-bracketed.
///
/// Normalize before appending the port: a raw trailing dot would otherwise
/// land mid-string (e.g. "evil.com.:443"), past where normalization looks.
/// Brackets keep an IPv6 literal's own colons out of the port separator
/// (e.g. "[::1]:8975", not "::1:8975").
fn authority(host: &str, port: u16) -> String {
    let normalized = HostFilter::normalize_authority_host(host);
    if normalized.parse::<Ipv6Addr>().is_ok() {
        format!("[{normalized}]:{port}")
    } else {
        format!("{normalized}:{port}")
    }
}

/// Split `host:port`, tolerating a bracketed IPv6 literal.
fn split_authority(entry: &str) -> Option<(String, u16)> {
    let (host, port) = entry.rsplit_once(':')?;
    let port: u16 = port.parse().ok()?;
    let host = match host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        Some(inner) => inner,
        None => host,
    };
    Some((host.to_string(), port))
}

fn proxy_metadata_filter_result(host: &str, resolved_ips: &[IpAddr]) -> Option<FilterResult> {
    if parse_host_ip_literal(host).is_some_and(|ip| is_proxy_denied_metadata_ip(&ip))
        || resolved_ips.iter().any(is_proxy_denied_metadata_ip)
    {
        return Some(FilterResult::DenyHost {
            host: host.to_string(),
        });
    }
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_proxy_filter_delegates_to_host_filter() {
        let filter = ProxyFilter::new(&["api.openai.com".to_string()]);
        let public_ip = vec![IpAddr::V4(Ipv4Addr::new(104, 18, 7, 96))];

        let result = filter.check_host_with_ips("api.openai.com", &public_ip);
        assert!(result.is_allowed());

        let result = filter.check_host_with_ips("evil.com", &public_ip);
        assert!(!result.is_allowed());
    }

    #[test]
    fn test_proxy_filter_allows_host_port_entries() {
        let filter = ProxyFilter::new(&["platform.claude.com:443".to_string()]);
        let public_ip = vec![IpAddr::V4(Ipv4Addr::new(160, 79, 104, 10))];

        let result = filter.check_host_result("platform.claude.com", 443, &public_ip);
        assert!(result.is_allowed());

        let result = filter.check_host_result("platform.claude.com", 8443, &public_ip);
        assert!(!result.is_allowed());
    }

    /// The whole point of `allow_ssh`: on an open policy it must close the
    /// SSH port everywhere else without closing any other port.
    #[test]
    fn test_ssh_pins_narrow_only_their_own_port() {
        let ip = vec![IpAddr::V4(Ipv4Addr::new(5, 9, 99, 136))];
        let filter =
            ProxyFilter::allow_all().with_ssh_endpoints(&["5.9.99.136:22".to_string()]);

        assert!(filter.check_host_result("5.9.99.136", 22, &ip).is_allowed());
        assert!(!filter.check_host_result("gchq.icu", 22, &ip).is_allowed());
        assert!(filter.check_host_result("gchq.icu", 443, &ip).is_allowed());
        assert!(
            filter.check_host_result("5.9.99.136", 443, &ip).is_allowed(),
            "a pin closes its port, not its host: HTTPS to that host is \
             no more restricted than HTTPS anywhere else"
        );
    }

    /// A wildcard allowlist entry must not reopen a pinned port.
    #[test]
    fn test_ssh_pins_outrank_a_wildcard_allowlist() {
        let ip = vec![IpAddr::V4(Ipv4Addr::new(104, 18, 7, 96))];
        let filter = ProxyFilter::new(&["*".to_string()])
            .with_ssh_endpoints(&["build.example.com:22".to_string()]);

        assert!(!filter.check_host_result("evil.com", 22, &ip).is_allowed());
        assert!(filter.check_host_result("evil.com", 80, &ip).is_allowed());
    }

    /// Entries and incoming hosts are normalized the same way, so a trailing
    /// dot or a different case cannot slip past the pin.
    #[test]
    fn test_ssh_pins_normalize_both_sides() {
        let ip = vec![IpAddr::V4(Ipv4Addr::new(104, 18, 7, 96))];
        let filter = ProxyFilter::allow_all()
            .with_ssh_endpoints(&["Build.Example.com.:22".to_string()]);

        assert!(filter.check_host_result("build.example.com", 22, &ip).is_allowed());
        assert!(filter.check_host_result("BUILD.example.com.", 22, &ip).is_allowed());
        assert!(!filter.check_host_result("build.example.com.evil.com", 22, &ip).is_allowed());
    }

    #[test]
    fn test_ssh_pins_accept_bracketed_ipv6_entries() {
        let ip = vec![IpAddr::V6(Ipv6Addr::LOCALHOST)];
        let filter = ProxyFilter::allow_all().with_ssh_endpoints(&["[::1]:2222".to_string()]);

        assert!(filter.check_host_result("::1", 2222, &ip).is_allowed());
        assert!(!filter.check_host_result("::2", 2222, &ip).is_allowed());
    }

    #[test]
    fn test_proxy_filter_host_port_entries_do_not_override_metadata_deny() {
        let filter = ProxyFilter::new(&["metadata.google.internal:443".to_string()]);
        let public_ip = vec![IpAddr::V4(Ipv4Addr::new(104, 18, 7, 96))];

        let result = filter.check_host_result("metadata.google.internal", 443, &public_ip);
        assert!(!result.is_allowed());
        assert!(matches!(result, FilterResult::DenyHost { .. }));
    }

    #[test]
    fn test_proxy_filter_with_denied_hosts() {
        let filter = ProxyFilter::allow_all().with_denied_hosts(&["evil.com".to_string()]);
        let public_ip = vec![IpAddr::V4(Ipv4Addr::new(104, 18, 7, 96))];

        let result = filter.check_host_with_ips("evil.com", &public_ip);
        assert!(!result.is_allowed());

        let result = filter.check_host_with_ips("good.com", &public_ip);
        assert!(result.is_allowed());
    }

    #[test]
    fn test_proxy_filter_with_denied_hosts_wildcard() {
        let filter = ProxyFilter::allow_all().with_denied_hosts(&["*.ads.example.com".to_string()]);
        let public_ip = vec![IpAddr::V4(Ipv4Addr::new(104, 18, 7, 96))];

        let result = filter.check_host_with_ips("tracker.ads.example.com", &public_ip);
        assert!(!result.is_allowed());

        // bare domain must NOT match wildcard
        let result = filter.check_host_with_ips("ads.example.com", &public_ip);
        assert!(result.is_allowed());
    }

    #[test]
    fn test_proxy_filter_denied_host_port_honored_under_wildcard_allow() {
        // A port-scoped deny must hold under a wildcard allow, without
        // affecting other ports on the same host.
        let filter =
            ProxyFilter::new(&["*".to_string()]).with_denied_hosts(&["127.0.0.1:8975".to_string()]);
        let loopback = vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))];

        let result = filter.check_host_result("127.0.0.1", 8975, &loopback);
        assert!(!result.is_allowed(), "denied port must not be allowed");
        assert!(matches!(result, FilterResult::DenyHost { .. }));

        let result = filter.check_host_result("127.0.0.1", 8787, &loopback);
        assert!(
            result.is_allowed(),
            "unrelated port on the same host must remain allowed"
        );
    }

    #[test]
    fn test_proxy_filter_denied_host_port_honored_for_trailing_dot_fqdn() {
        // A trailing-dot FQDN must not bypass a port-scoped deny via
        // unnormalized host:port construction (see check_host_result).
        let filter =
            ProxyFilter::new(&["*".to_string()]).with_denied_hosts(&["evil.com:443".to_string()]);

        let result = filter.check_host_result("evil.com.", 443, &[]);
        assert!(
            !result.is_allowed(),
            "trailing-dot form must still be denied"
        );
        assert!(matches!(result, FilterResult::DenyHost { .. }));
    }

    #[test]
    fn test_proxy_filter_denied_host_port_honored_for_ipv6_literal() {
        // An IPv6 host:port deny must match the bracketed authority form,
        // not "::1:8975" (ambiguous with the port separator).
        let filter =
            ProxyFilter::new(&["*".to_string()]).with_denied_hosts(&["[::1]:8975".to_string()]);

        let result = filter.check_host_result("::1", 8975, &[]);
        assert!(!result.is_allowed(), "IPv6 host:port form must be denied");
        assert!(matches!(result, FilterResult::DenyHost { .. }));

        let result = filter.check_host_result("::1", 8787, &[]);
        assert!(
            result.is_allowed(),
            "unrelated port on the same IPv6 host must remain allowed"
        );
    }

    #[test]
    fn test_proxy_filter_allow_all() {
        let filter = ProxyFilter::allow_all();
        let public_ip = vec![IpAddr::V4(Ipv4Addr::new(104, 18, 7, 96))];
        let result = filter.check_host_with_ips("anything.com", &public_ip);
        assert!(result.is_allowed());
    }

    #[test]
    fn test_proxy_filter_allows_private_networks() {
        let filter = ProxyFilter::allow_all();
        let private_ip = vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))];
        let result = filter.check_host_with_ips("corp.internal", &private_ip);
        assert!(result.is_allowed());
    }

    #[test]
    fn test_proxy_filter_denies_link_local() {
        let filter = ProxyFilter::allow_all();
        let link_local = vec![IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))];
        let result = filter.check_host_with_ips("evil.com", &link_local);
        assert!(!result.is_allowed());
    }

    #[test]
    fn test_proxy_filter_denies_aws_ipv6_metadata_literals() {
        let filter = ProxyFilter::allow_all();
        for host in [
            "fd00:ec2::254",
            "fd00:0ec2::254",
            "fd00:ec2:0:0:0:0:0:254",
            "[fd00:ec2::254]",
        ] {
            let result = filter.check_host_with_ips(host, &[]);
            assert!(
                !result.is_allowed(),
                "AWS IPv6 metadata literal {host:?} must be denied"
            );
        }
    }

    #[test]
    fn test_pre_resolution_check_denies_disallowed_host_without_ips() {
        let filter = ProxyFilter::new(&["api.openai.com".to_string()]);
        let result = filter.check_host_result("evil.com", 443, &[]);
        assert!(!result.is_allowed());
        assert!(matches!(result, FilterResult::DenyNotAllowed { .. }));
    }

    #[test]
    fn test_pre_resolution_check_allows_allowed_host_without_ips() {
        let filter = ProxyFilter::new(&["api.openai.com".to_string()]);
        let result = filter.check_host_result("api.openai.com", 443, &[]);
        assert!(result.is_allowed());
    }

    #[test]
    fn test_pre_resolution_check_host_port_fallback_without_ips() {
        let filter = ProxyFilter::new(&["platform.claude.com:443".to_string()]);
        let result = filter.check_host_result("platform.claude.com", 443, &[]);
        assert!(result.is_allowed());

        let result = filter.check_host_result("platform.claude.com", 8443, &[]);
        assert!(!result.is_allowed());
    }

    #[tokio::test]
    async fn test_check_host_denies_disallowed_host_without_dns_resolution() {
        // .invalid (RFC 2606) never resolves, so a hang/error here would mean
        // DNS was attempted before the allowlist check.
        let filter = ProxyFilter::new(&["api.openai.com".to_string()]);
        let result = filter
            .check_host("data-exfiltration-secret.example.invalid", 443)
            .await
            .unwrap();
        assert!(!result.result.is_allowed());
        assert!(matches!(result.result, FilterResult::DenyNotAllowed { .. }));
        assert!(result.resolved_addrs.is_empty());
    }

    #[test]
    fn test_proxy_filter_denies_trailing_dot_metadata_hostname() {
        // CONNECT-path callers pass the raw wire hostname straight through
        // with no normalization; the filter itself must catch this.
        let filter = ProxyFilter::allow_all();
        let result = filter.check_host_with_ips("metadata.google.internal.", &[]);
        assert!(!result.is_allowed());
        assert!(matches!(result, FilterResult::DenyHost { .. }));
    }

    #[test]
    fn test_proxy_filter_denies_unicode_form_of_punycode_deny_entry() {
        let filter = ProxyFilter::allow_all().with_denied_hosts(&["xn--mnchen-3ya.de".to_string()]);
        let result = filter.check_host_with_ips("münchen.de", &[]);
        assert!(!result.is_allowed());
    }

    #[test]
    fn test_proxy_filter_denies_resolved_aws_ipv6_metadata_ip() {
        let filter = ProxyFilter::allow_all();
        let resolved = vec![IpAddr::V6(Ipv6Addr::new(
            0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254,
        ))];
        let result = filter.check_host_with_ips("allowed.example", &resolved);
        assert!(!result.is_allowed());
    }
}
