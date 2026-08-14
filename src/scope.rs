//! Host scope matching.
//!
//! Scope decides what the proxy holds for intercept, what the history list shows
//! under "In scope", and which hosts the site map marks. That decision used to be
//! implemented three times — in `runtime`, `store` and `websocket` — with the
//! copies free to drift. It lives here once.
//!
//! A host is in scope when it matches an include pattern (or there are none, which
//! means everything) and matches no exclude pattern. Excludes therefore work on
//! their own: with no includes, everything except the excluded hosts is in scope.

/// Pattern forms, in the order they are tried:
///
/// - `*.example.com` — the domain and anything under it, so `example.com` and
///   `api.example.com` both match. This is the common case and predates the rest.
/// - `aem-*.example.com` — `*` stands for any run of characters. Useful for
///   excluding a family of hosts that share a prefix.
/// - `api.example.com` — exactly that host.
///
/// Matching ignores case, a port, and a trailing DNS root dot.
pub fn host_matches_pattern(host: &str, pattern: &str) -> bool {
    let hostname = normalize_host_for_matching(host);
    let normalized = normalize_host_for_matching(pattern);

    if let Some(suffix) = normalized.strip_prefix("*.") {
        // Kept distinct from the glob below: a plain glob would not match the bare
        // domain, and `*.example.com` has always included `example.com`.
        if !suffix.contains('*') {
            return hostname == suffix || hostname.ends_with(&format!(".{suffix}"));
        }
    }

    if normalized.contains('*') {
        return glob_matches(&hostname, &normalized);
    }

    hostname == normalized
}

pub fn host_matches_any(host: &str, patterns: &[String]) -> bool {
    patterns
        .iter()
        .any(|pattern| host_matches_pattern(host, pattern))
}

/// Whether `host` is in scope given the include and exclude lists.
///
/// An empty include list means every host is included, so an exclude list alone
/// still narrows scope.
pub fn is_host_in_scope(host: &str, include: &[String], exclude: &[String]) -> bool {
    let included = include.is_empty() || host_matches_any(host, include);
    included && !host_matches_any(host, exclude)
}

/// `*` matches any run of characters, including dots. Anchored at both ends, so
/// `aem-*.example.com` does not match `x-aem-y.example.com`.
fn glob_matches(value: &str, pattern: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return value == pattern;
    }

    let first = parts[0];
    let last = parts[parts.len() - 1];
    if !value.starts_with(first) || !value.ends_with(last) {
        return false;
    }
    // The leading and trailing literals may overlap when the value is short, e.g.
    // "ab" against "a*b" — the remaining span must be non-negative.
    if first.len() + last.len() > value.len() {
        return false;
    }

    let mut rest = &value[first.len()..value.len() - last.len()];
    for middle in &parts[1..parts.len() - 1] {
        if middle.is_empty() {
            continue;
        }
        match rest.find(middle) {
            Some(at) => rest = &rest[at + middle.len()..],
            None => return false,
        }
    }
    true
}

pub fn normalize_host_for_matching(host: &str) -> String {
    let mut value = host.trim().to_ascii_lowercase();
    if let Some((_, rest)) = value.split_once("://") {
        value = rest.to_string();
    } else if let Some(rest) = value.strip_prefix("//") {
        value = rest.to_string();
    }
    let host = value.split(['/', '?', '#']).next().unwrap_or("").trim();
    strip_dns_root_dot(host_without_port(host)).to_string()
}

fn strip_dns_root_dot(host: &str) -> &str {
    host.strip_suffix('.').unwrap_or(host)
}

pub fn host_without_port(host: &str) -> &str {
    let trimmed = host.trim();
    if let Some(rest) = trimmed.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            return &rest[..end];
        }
    }
    if trimmed.matches(':').count() == 1 {
        return trimmed.split_once(':').map(|(host, _)| host).unwrap_or(trimmed);
    }
    trimmed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    #[test]
    fn wildcard_domain_covers_the_domain_and_everything_under_it() {
        assert!(host_matches_pattern("example.com", "*.example.com"));
        assert!(host_matches_pattern("api.example.com", "*.example.com"));
        assert!(host_matches_pattern("a.b.example.com", "*.example.com"));
        assert!(!host_matches_pattern("notexample.com", "*.example.com"));
        assert!(!host_matches_pattern("example.com.evil.net", "*.example.com"));
    }

    #[test]
    fn a_star_inside_a_label_matches_that_family_of_hosts() {
        // The case this was added for: exclude every aem- host under a domain.
        assert!(host_matches_pattern(
            "aem-kakao-collector.onkakao.net",
            "aem-*.onkakao.net"
        ));
        assert!(host_matches_pattern("aem-x.onkakao.net", "aem-*.onkakao.net"));
        assert!(!host_matches_pattern("cdn.onkakao.net", "aem-*.onkakao.net"));
        // Anchored: a host that merely contains the prefix does not match.
        assert!(!host_matches_pattern(
            "x-aem-y.onkakao.net",
            "aem-*.onkakao.net"
        ));
    }

    #[test]
    fn matching_ignores_case_port_and_the_root_dot() {
        assert!(host_matches_pattern("API.Example.COM:443", "*.example.com"));
        assert!(host_matches_pattern("api.example.com.", "*.example.com"));
        assert!(host_matches_pattern(
            "AEM-Collector.OnKakao.net:443",
            "aem-*.onkakao.net"
        ));
    }

    #[test]
    fn an_exclude_narrows_an_include() {
        let include = list(&["*.onkakao.net"]);
        let exclude = list(&["aem-*.onkakao.net"]);
        assert!(is_host_in_scope("api.onkakao.net", &include, &exclude));
        assert!(!is_host_in_scope(
            "aem-kakao-collector.onkakao.net",
            &include,
            &exclude
        ));
        assert!(!is_host_in_scope("example.com", &include, &exclude));
    }

    #[test]
    fn an_exclude_works_with_no_includes_at_all() {
        // No includes means everything is in scope, so an exclude list on its own
        // has to still take hosts out of it.
        let exclude = list(&["aem-kakao-collector.onkakao.net"]);
        assert!(is_host_in_scope("api.onkakao.net", &[], &exclude));
        assert!(!is_host_in_scope(
            "aem-kakao-collector.onkakao.net",
            &[],
            &exclude
        ));
    }

    #[test]
    fn everything_is_in_scope_when_both_lists_are_empty() {
        assert!(is_host_in_scope("anything.example", &[], &[]));
    }
}
