//! One Info finding per page host, library and version that the data lists
//! advisories for. A finding stores the product and version only; its
//! advisory list is joined from the current data whenever it is read, so new
//! data never duplicates or stales it.

use std::borrow::Cow;

use chrono::Utc;
use uuid::Uuid;

use super::index::VulnIndex;
use crate::model::{BodyEncoding, TransactionRecord};
use crate::scanner::{ScannerFinding, Severity};
use crate::service_map_libraries::{detect, detect_url, merge, scan_text, Kind, MAX_ROW_BYTES};

pub const RULE_PREFIX: &str = "known-cve:";
pub const CATEGORY: &str = "known_cve";
const TITLE_PREFIX: &str = "Known vulnerabilities: ";

/// A script or a page body, or a script or stylesheet URL: the records that
/// can name a front-end library, as the Service Map reads them.
pub fn may_name_a_library(record: &TransactionRecord) -> bool {
    body_kind(record).is_some()
        || matches!(
            crate::service_map::request_kind(record),
            "script" | "static"
        )
}

fn body_kind(record: &TransactionRecord) -> Option<Kind> {
    let content_type = record
        .response
        .as_ref()?
        .content_type
        .as_deref()?
        .to_ascii_lowercase();
    if content_type.contains("javascript") || content_type.contains("ecmascript") {
        Some(Kind::Script)
    } else if content_type.contains("html") {
        Some(Kind::Page)
    } else {
        None
    }
}

pub fn for_record(index: &VulnIndex, record: &TransactionRecord) -> Vec<ScannerFinding> {
    let kind = body_kind(record);
    let mut found = Vec::new();
    if matches!(
        crate::service_map::request_kind(record),
        "script" | "static"
    ) {
        let host = crate::store::host_without_default_port(&record.host, &record.scheme);
        for detection in detect_url(&format!("{}://{host}{}", record.scheme, record.path)) {
            merge(&mut found, detection);
        }
    }
    if let (Some(kind), Some(response)) = (kind, record.response.as_ref()) {
        if response.body_preview.len() <= MAX_ROW_BYTES {
            let body = match response.body_encoding {
                BodyEncoding::Utf8 => Some(Cow::Borrowed(response.body_preview.as_str())),
                BodyEncoding::Base64 => {
                    scan_text(response.body_preview.clone(), BodyEncoding::Base64).map(Cow::Owned)
                }
            };
            for detection in body.map(|body| detect(&body, kind)).unwrap_or_default() {
                merge(&mut found, detection);
            }
        }
    }
    let (scheme, host, path) = owner(record, kind);
    found
        .into_iter()
        .filter_map(|detection| {
            let version = detection.version?;
            index.summary(&detection.product_id, &version)?;
            Some(ScannerFinding {
                id: Uuid::new_v4(),
                record_id: record.id,
                found_at: Utc::now(),
                rule_id: format!("{RULE_PREFIX}{}", detection.product_id),
                severity: Severity::Info,
                category: CATEGORY.into(),
                title: format!("{TITLE_PREFIX}{} {version}", detection.name),
                detail: caveat(&format!("{} {version}", detection.name)),
                evidence: format!("{}@{version}", detection.product_id),
                scheme: scheme.clone(),
                host: host.clone(),
                path: path.clone(),
                location: None,
            })
        })
        .collect()
}

/// A script or asset belongs to the page that loaded it, as in the Service
/// Map, so the In scope filter keeps a library a CDN served; a page, or an
/// asset with no page, belongs to its own host. The host drops its default
/// port, as a Referer does, or a page and the script it loaded would hold two
/// findings for one library.
fn owner(record: &TransactionRecord, kind: Option<Kind>) -> (String, String, String) {
    if kind != Some(Kind::Page) {
        if let Some(page) = referer(record) {
            return page;
        }
    }
    let host = crate::store::host_without_default_port(&record.host, &record.scheme);
    (record.scheme.clone(), host.to_string(), record.path.clone())
}

fn referer(record: &TransactionRecord) -> Option<(String, String, String)> {
    let value = &record
        .request
        .headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("referer"))?
        .value;
    let url = url::Url::parse(value.trim()).ok()?;
    if !matches!(url.scheme(), "http" | "https") {
        return None;
    }
    let host = url.host_str()?;
    let host = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    };
    Some((url.scheme().to_string(), host, url.path().to_string()))
}

fn caveat(named: &str) -> String {
    format!("Tentative: matched on the version string alone ({named}). Confirm before reporting.")
}

/// The caveat, then the advisories the current data lists, exploited ones
/// first, then where the data came from.
pub fn detail(index: Option<&VulnIndex>, finding: &ScannerFinding) -> String {
    let named = finding
        .title
        .strip_prefix(TITLE_PREFIX)
        .unwrap_or(&finding.evidence);
    let mut lines = vec![caveat(named)];
    let Some(index) = index else {
        lines.push("Vulnerability data has not been fetched yet.".into());
        return lines.join("\n");
    };
    let (product, version) = finding.evidence.split_once('@').unwrap_or_default();
    let advisories = index.advisories(product, version);
    if advisories.is_empty() {
        lines.push("The current data lists no advisories for this version.".into());
    }
    for advisory in advisories {
        let mut head = format!("{} · {}", advisory.id, advisory.severity);
        if advisory.kev {
            head.push_str(" · KEV");
        }
        if let Some(epss) = advisory.epss {
            head.push_str(&format!(" · EPSS {epss:.2}"));
        }
        head.push_str(&format!(" · fixed in {}", advisory.fixed_in));
        lines.push(String::new());
        lines.push(head);
        lines.extend(advisory.summary);
        lines.extend(advisory.urls);
    }
    let fetched = index
        .fetched_at
        .map(|at| format!("; fetched {}", at.format("%Y-%m-%d")))
        .unwrap_or_default();
    lines.push(String::new());
    lines.push(format!(
        "Data: retire.js (Apache-2.0), CISA KEV (CC0), FIRST EPSS (https://www.first.org/epss){fetched}."
    ));
    lines.join("\n")
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::model::{BodyEncoding, HeaderRecord, MessageRecord};
    use crate::scanner::Severity;
    use crate::vulndata::index::RetireAdvisory;
    use std::collections::{HashMap, HashSet};

    fn advisory(cve: &str, from: Option<&str>, below: &str) -> RetireAdvisory {
        RetireAdvisory {
            component: "jquery".into(),
            at_or_above: from.map(str::to_string),
            below: below.into(),
            severity: "medium".into(),
            cves: vec![cve.into()],
            ghsa: None,
            summary: Some(format!("{cve} summary")),
            urls: vec![format!("https://example.com/{cve}")],
        }
    }

    pub(crate) fn jquery_index(extra: bool) -> VulnIndex {
        let mut retire = vec![
            advisory("CVE-2020-11023", Some("1.0.3"), "3.5.0"),
            advisory("CVE-2019-11358", None, "3.4.0"),
        ];
        if extra {
            retire.push(advisory("CVE-2025-00001", None, "3.6.0"));
        }
        VulnIndex::build(
            retire,
            HashSet::from(["CVE-2020-11023".to_string()]),
            HashMap::from([("CVE-2020-11023".to_string(), 0.94)]),
            "test".into(),
        )
    }

    /// A script a page loaded from a CDN.
    pub(crate) fn script(path: &str, referer: Option<&str>) -> TransactionRecord {
        let header = |name: &str, value: &str| HeaderRecord {
            name: name.into(),
            value: value.into(),
        };
        let message = |headers, content_type: Option<&str>| MessageRecord {
            headers,
            body_preview: "/*! a library */".into(),
            body_encoding: BodyEncoding::Utf8,
            body_size: 16,
            decoded_body_size: None,
            preview_truncated: false,
            content_type: content_type.map(str::to_string),
            content_decoded: false,
        };
        let mut request = vec![header("Sec-Fetch-Dest", "script")];
        if let Some(referer) = referer {
            request.push(header("Referer", referer));
        }
        TransactionRecord::http(
            chrono::Utc::now(),
            "GET".into(),
            "https".into(),
            "cdn.example.com:443".into(),
            path.into(),
            Some(200),
            1,
            message(request, None),
            Some(message(Vec::new(), Some("application/javascript"))),
            Vec::new(),
            None,
            None,
        )
    }

    #[test]
    fn a_library_a_page_loaded_is_one_info_finding_on_the_page() {
        let index = jquery_index(false);
        let record = script(
            "/npm/jquery@3.4.1/dist/jquery.min.js",
            Some("https://app.example.com/shop"),
        );
        let found = for_record(&index, &record);
        assert_eq!(found.len(), 1);
        let finding = &found[0];
        assert_eq!(finding.host, "app.example.com");
        assert_eq!(finding.path, "/shop");
        assert_eq!(finding.scheme, "https");
        assert_eq!(finding.evidence, "jquery@3.4.1");
        assert_eq!(finding.title, "Known vulnerabilities: jQuery 3.4.1");
        assert_eq!(finding.severity, Severity::Info);
        assert_eq!(finding.category, "known_cve");
        assert_eq!(finding.rule_id, "known-cve:jquery");
        assert_eq!(finding.record_id, record.id);
    }

    #[test]
    fn a_partial_version_or_no_page_changes_what_is_found() {
        let index = jquery_index(false);
        let partial = script(
            "/npm/jquery@3/dist/jquery.min.js",
            Some("https://app.example.com/shop"),
        );
        assert!(for_record(&index, &partial).is_empty());
        let alone = script("/npm/jquery@3.4.1/dist/jquery.min.js", None);
        assert_eq!(for_record(&index, &alone)[0].host, "cdn.example.com");
    }

    #[test]
    fn a_page_and_a_script_it_loaded_name_its_host_alike() {
        let index = jquery_index(false);
        let alone = script("/npm/jquery@3.4.1/dist/jquery.min.js", None);
        let loaded = script(
            "/npm/jquery@3.4.1/dist/jquery.min.js",
            Some("https://cdn.example.com/demo"),
        );
        assert_eq!(
            for_record(&index, &alone)[0].host,
            for_record(&index, &loaded)[0].host
        );
    }

    #[test]
    fn the_detail_lists_the_current_advisories_exploited_first() {
        let record = script(
            "/npm/jquery@3.4.1/dist/jquery.min.js",
            Some("https://app.example.com/shop"),
        );
        let stored = for_record(&jquery_index(false), &record).remove(0);
        assert!(stored
            .detail
            .starts_with("Tentative: matched on the version string alone (jQuery 3.4.1)."));
        assert!(!stored.detail.contains("CVE-"));

        let detail = detail(Some(&jquery_index(false)), &stored);
        assert!(detail.contains("CVE-2020-11023 · medium · KEV · EPSS 0.94 · fixed in 3.5.0"));
        assert!(!detail.contains("CVE-2025-00001"));
        // The same stored finding, read against newer data.
        let newer = super::detail(Some(&jquery_index(true)), &stored);
        assert!(newer.contains("CVE-2020-11023") && newer.contains("CVE-2025-00001"));
        assert!(newer.find("CVE-2020-11023") < newer.find("CVE-2025-00001"));
        assert!(
            super::detail(None, &stored).contains("Vulnerability data has not been fetched yet.")
        );
    }
}
