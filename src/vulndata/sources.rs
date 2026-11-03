//! The three data files, read as untrusted input. Each has a size limit, a
//! row limit and field rules; a file that breaks a limit is refused whole, so
//! the previous one stays.

use std::collections::{HashMap, HashSet};
use std::io::Read as _;
use std::sync::LazyLock;

use anyhow::{bail, Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::version::Version;

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
#[serde(rename_all = "snake_case")]
pub enum SourceId {
    Retire,
    Kev,
    Epss,
}

impl SourceId {
    pub const ALL: [SourceId; 3] = [SourceId::Retire, SourceId::Kev, SourceId::Epss];

    pub fn name(self) -> &'static str {
        match self {
            SourceId::Retire => "retire.js",
            SourceId::Kev => "CISA KEV",
            SourceId::Epss => "FIRST EPSS",
        }
    }

    pub fn url(self) -> &'static str {
        match self {
            SourceId::Retire => "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository-v4.json",
            SourceId::Kev => "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            SourceId::Epss => "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
        }
    }

    pub fn license(self) -> &'static str {
        match self {
            SourceId::Retire => "Apache-2.0",
            SourceId::Kev => "CC0",
            SourceId::Epss => "FIRST EPSS usage agreement; see EPSS at https://www.first.org/epss",
        }
    }

    /// The most a download or an import may be.
    pub fn max_bytes(self) -> usize {
        match self {
            SourceId::Retire | SourceId::Kev => 8 << 20,
            SourceId::Epss => 16 << 20,
        }
    }
}

const MAX_EPSS_UNPACKED: u64 = 128 << 20;
const MAX_ADVISORIES: usize = 20_000;
const MAX_EPSS_ROWS: usize = 400_000;
const MAX_SUMMARY_CHARS: usize = 300;
const MAX_URL_BYTES: usize = 2048;
const MAX_URLS: usize = 5;

static CVE_ID: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^CVE-\d{4}-\d{4,}$").unwrap());
static GHSA_ID: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^GHSA(-[2-9cfghjmpqrvwx]{4}){3}$").unwrap());

/// One retire.js advisory for one component: `at_or_above <= version < below`.
#[derive(Clone, Debug, PartialEq)]
pub struct RetireAdvisory {
    pub component: String,
    pub at_or_above: Option<String>,
    pub below: String,
    pub severity: String,
    pub cves: Vec<String>,
    pub ghsa: Option<String>,
    pub summary: Option<String>,
    pub urls: Vec<String>,
}

#[derive(Deserialize)]
struct RawVulnerability {
    #[serde(rename = "atOrAbove")]
    at_or_above: Option<String>,
    below: String,
    severity: Option<String>,
    #[serde(default)]
    identifiers: RawIdentifiers,
    #[serde(default)]
    info: Vec<String>,
}

#[derive(Default, Deserialize)]
struct RawIdentifiers {
    #[serde(rename = "CVE", default)]
    cve: Vec<String>,
    #[serde(rename = "githubID")]
    github_id: Option<String>,
    summary: Option<String>,
}

/// Gzip is EPSS, and so is its text; KEV has a `catalogVersion`; retire.js
/// is an object of components that hold `vulnerabilities`.
pub fn identify(bytes: &[u8]) -> Option<SourceId> {
    if bytes.starts_with(&[0x1f, 0x8b])
        || bytes.starts_with(b"#model_version")
        || bytes.starts_with(b"cve,epss")
    {
        return Some(SourceId::Epss);
    }
    let Value::Object(map) = serde_json::from_slice(bytes).ok()? else {
        return None;
    };
    if map.contains_key("catalogVersion") {
        return Some(SourceId::Kev);
    }
    map.values()
        .any(|value| value.get("vulnerabilities").is_some_and(Value::is_array))
        .then_some(SourceId::Retire)
}

pub fn parse_retire(bytes: &[u8]) -> Result<Vec<RetireAdvisory>> {
    within_limit(bytes, SourceId::Retire)?;
    let components: serde_json::Map<String, Value> =
        serde_json::from_slice(bytes).context("retire.js data is not a JSON object")?;
    let mut advisories = Vec::new();
    for (component, entry) in &components {
        let Some(Value::Array(vulnerabilities)) = entry.get("vulnerabilities") else {
            continue;
        };
        // A row this reader does not understand is skipped, not guessed at.
        for vulnerability in vulnerabilities {
            let Ok(raw) = RawVulnerability::deserialize(vulnerability) else {
                continue;
            };
            if let Some(advisory) = advisory(component, raw) {
                advisories.push(advisory);
            }
            if advisories.len() > MAX_ADVISORIES {
                bail!("retire.js data has more than {MAX_ADVISORIES} advisories");
            }
        }
    }
    if advisories.is_empty() {
        bail!("retire.js data has no advisories this version of Sniper can read");
    }
    Ok(advisories)
}

/// None when a bound does not parse: a range read wrong would match the wrong
/// versions.
fn advisory(component: &str, raw: RawVulnerability) -> Option<RetireAdvisory> {
    let below = raw.below.trim().to_string();
    Version::parse(&below)?;
    let at_or_above = match raw.at_or_above {
        Some(bound) => {
            Version::parse(&bound)?;
            Some(bound.trim().to_string())
        }
        None => None,
    };
    let severity = raw
        .severity
        .map(|severity| severity.to_ascii_lowercase())
        .filter(|severity| matches!(severity.as_str(), "low" | "medium" | "high" | "critical"))
        .unwrap_or_else(|| "unknown".into());
    let mut cves: Vec<String> = Vec::new();
    for cve in raw.identifiers.cve {
        if CVE_ID.is_match(&cve) && !cves.contains(&cve) {
            cves.push(cve);
        }
    }
    Some(RetireAdvisory {
        component: component.to_string(),
        at_or_above,
        below,
        severity,
        cves,
        ghsa: raw.identifiers.github_id.filter(|id| GHSA_ID.is_match(id)),
        summary: raw.identifiers.summary.as_deref().and_then(plain_text),
        urls: raw
            .info
            .into_iter()
            .filter(|url| safe_link(url))
            .take(MAX_URLS)
            .collect(),
    })
}

/// Control characters go: line breaks and tabs become spaces, the rest are
/// dropped. Kept as text; the display escapes it.
fn plain_text(text: &str) -> Option<String> {
    let text: String = text
        .chars()
        .filter_map(|c| match c {
            '\n' | '\r' | '\t' => Some(' '),
            c if c.is_control() => None,
            c => Some(c),
        })
        .take(MAX_SUMMARY_CHARS)
        .collect();
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_string())
}

fn safe_link(url: &str) -> bool {
    url.len() <= MAX_URL_BYTES
        && url
            .get(..8)
            .is_some_and(|scheme| scheme.eq_ignore_ascii_case("https://"))
        && !url.chars().any(|c| c.is_whitespace() || c.is_control())
}

#[derive(Deserialize)]
struct RawKev {
    vulnerabilities: Vec<RawKevEntry>,
}

#[derive(Deserialize)]
struct RawKevEntry {
    #[serde(rename = "cveID")]
    cve_id: String,
}

pub fn parse_kev(bytes: &[u8]) -> Result<HashSet<String>> {
    within_limit(bytes, SourceId::Kev)?;
    let catalog: RawKev =
        serde_json::from_slice(bytes).context("KEV data is not the expected JSON")?;
    if catalog.vulnerabilities.len() > MAX_ADVISORIES {
        bail!("KEV data has more than {MAX_ADVISORIES} entries");
    }
    let kev: HashSet<String> = catalog
        .vulnerabilities
        .into_iter()
        .map(|entry| entry.cve_id)
        .filter(|id| CVE_ID.is_match(id))
        .collect();
    if kev.is_empty() {
        bail!("KEV data lists no CVE");
    }
    Ok(kev)
}

/// Gzip or plain CSV: `#` lines and the `cve,epss,percentile` header are
/// skipped.
pub fn parse_epss(bytes: &[u8]) -> Result<HashMap<String, f32>> {
    within_limit(bytes, SourceId::Epss)?;
    let text = if bytes.starts_with(&[0x1f, 0x8b]) {
        let mut unpacked = Vec::new();
        flate2::read::GzDecoder::new(bytes)
            .take(MAX_EPSS_UNPACKED + 1)
            .read_to_end(&mut unpacked)
            .context("EPSS data is not valid gzip")?;
        if unpacked.len() as u64 > MAX_EPSS_UNPACKED {
            bail!(
                "EPSS data unpacks to more than {} MiB",
                MAX_EPSS_UNPACKED >> 20
            );
        }
        String::from_utf8(unpacked).context("EPSS data is not UTF-8 text")?
    } else {
        String::from_utf8(bytes.to_vec()).context("EPSS data is not UTF-8 text")?
    };
    let mut scores = HashMap::new();
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') || line.starts_with("cve,") {
            continue;
        }
        let mut fields = line.split(',');
        let (Some(cve), Some(score)) = (fields.next(), fields.next()) else {
            bail!("EPSS data has a row without a score");
        };
        let score: f32 = score
            .trim()
            .parse()
            .context("EPSS data has a score that is not a number")?;
        if CVE_ID.is_match(cve) && (0.0..=1.0).contains(&score) {
            scores.insert(cve.to_string(), score);
        }
        if scores.len() > MAX_EPSS_ROWS {
            bail!("EPSS data has more than {MAX_EPSS_ROWS} rows");
        }
    }
    if scores.is_empty() {
        bail!("EPSS data has no scores");
    }
    Ok(scores)
}

fn within_limit(bytes: &[u8], source: SourceId) -> Result<()> {
    if bytes.len() > source.max_bytes() {
        bail!(
            "{} data is over {} MiB",
            source.name(),
            source.max_bytes() >> 20
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    const RETIRE_FIXTURE: &str = r#"{
        "retire-example": {"vulnerabilities": []},
        "jquery": {
            "npmname": "jquery",
            "vulnerabilities": [{
                "atOrAbove": "1.0.3", "below": "3.5.0", "severity": "medium",
                "identifiers": {
                    "CVE": ["CVE-2020-11023", "not-a-cve"],
                    "githubID": "GHSA-jpcq-cgw6-v4j6",
                    "summary": "<img src=x onerror=alert(1)>\u0007"
                },
                "info": ["javascript:alert(1)", "http://example.com/a", "https://example.com/b"]
            }]
        }
    }"#;
    const KEV_FIXTURE: &str = r#"{"catalogVersion": "2026.10.27", "vulnerabilities": [
        {"cveID": "CVE-2020-11023"}, {"cveID": "CVE-1-2"}]}"#;
    const EPSS_FIXTURE: &str =
        "#model_version:v2025.03.14,score_date:2026-10-27T00:00:00+0000\ncve,epss,percentile\nCVE-2020-11023,0.94000,0.99900\n";

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn identifies_each_source_and_nothing_else() {
        assert_eq!(identify(RETIRE_FIXTURE.as_bytes()), Some(SourceId::Retire));
        assert_eq!(identify(KEV_FIXTURE.as_bytes()), Some(SourceId::Kev));
        assert_eq!(
            identify(&gzip(EPSS_FIXTURE.as_bytes())),
            Some(SourceId::Epss)
        );
        assert_eq!(identify(b"{}"), None);
    }

    #[test]
    fn a_retire_advisory_keeps_only_safe_links_and_plain_text() {
        let advisories = parse_retire(RETIRE_FIXTURE.as_bytes()).unwrap();
        assert_eq!(advisories.len(), 1);
        let advisory = &advisories[0];
        assert_eq!(advisory.component, "jquery");
        assert_eq!(advisory.at_or_above.as_deref(), Some("1.0.3"));
        assert_eq!(advisory.below, "3.5.0");
        assert_eq!(advisory.severity, "medium");
        assert_eq!(advisory.cves, ["CVE-2020-11023"]);
        assert_eq!(advisory.ghsa.as_deref(), Some("GHSA-jpcq-cgw6-v4j6"));
        assert_eq!(advisory.urls, ["https://example.com/b"]);
        // Kept as text; the display escapes it.
        assert_eq!(
            advisory.summary.as_deref(),
            Some("<img src=x onerror=alert(1)>")
        );
    }

    #[test]
    fn kev_keeps_only_well_formed_cve_ids() {
        let kev = parse_kev(KEV_FIXTURE.as_bytes()).unwrap();
        assert!(kev.contains("CVE-2020-11023"));
        assert!(!kev.contains("CVE-1-2"));
    }

    #[test]
    fn epss_reads_gzip_or_plain_text() {
        for bytes in [
            EPSS_FIXTURE.as_bytes().to_vec(),
            gzip(EPSS_FIXTURE.as_bytes()),
        ] {
            let scores = parse_epss(&bytes).unwrap();
            assert_eq!(scores.len(), 1);
            assert!((scores["CVE-2020-11023"] - 0.94).abs() < 1e-6);
        }
    }

    #[test]
    fn a_gzip_that_unpacks_past_its_limit_is_refused() {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        let zeros = vec![0u8; 1 << 20];
        for _ in 0..129 {
            encoder.write_all(&zeros).unwrap();
        }
        assert!(parse_epss(&encoder.finish().unwrap()).is_err());
    }

    #[test]
    fn truncated_json_is_refused() {
        let cut = &RETIRE_FIXTURE[..RETIRE_FIXTURE.len() / 2];
        assert!(parse_retire(cut.as_bytes()).is_err());
        let cut = &KEV_FIXTURE[..KEV_FIXTURE.len() / 2];
        assert!(parse_kev(cut.as_bytes()).is_err());
    }
}
