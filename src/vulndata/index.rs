//! The advisories each product version carries, from the parsed files.

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};

use serde::Serialize;

use super::products::retire_components;
pub use super::sources::RetireAdvisory;
use super::version::{in_range, Version};

/// One row of a version's advisory list. The unit is the advisory, not the
/// CVE: about a fifth of retire.js advisories carry no CVE id.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Advisory {
    pub id: String,
    pub cves: Vec<String>,
    pub severity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    pub fixed_in: String,
    pub urls: Vec<String>,
    pub kev: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epss: Option<f32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Summary {
    pub count: usize,
    pub kev_count: usize,
    pub highest_severity: String,
}

struct Entry {
    from: Option<Version>,
    below: Version,
    advisory: RetireAdvisory,
}

pub struct VulnIndex {
    by_component: HashMap<String, Vec<Entry>>,
    kev: HashSet<String>,
    epss: HashMap<String, f32>,
    /// Changes whenever a source file does, so caches keyed on it go stale.
    pub revision: String,
}

impl VulnIndex {
    pub fn build(
        retire: Vec<RetireAdvisory>,
        mut kev: HashSet<String>,
        mut epss: HashMap<String, f32>,
        revision: String,
    ) -> Self {
        // EPSS scores every published CVE; keep the few the advisories name.
        let named: HashSet<&str> = retire
            .iter()
            .flat_map(|advisory| advisory.cves.iter().map(String::as_str))
            .collect();
        kev.retain(|cve| named.contains(cve.as_str()));
        epss.retain(|cve, _| named.contains(cve.as_str()));
        let mut by_component: HashMap<String, Vec<Entry>> = HashMap::new();
        for advisory in retire {
            let from = match &advisory.at_or_above {
                Some(bound) => match Version::parse(bound) {
                    Some(version) => Some(version),
                    None => continue,
                },
                None => None,
            };
            let Some(below) = Version::parse(&advisory.below) else {
                continue;
            };
            by_component
                .entry(advisory.component.clone())
                .or_default()
                .push(Entry {
                    from,
                    below,
                    advisory,
                });
        }
        Self {
            by_component,
            kev,
            epss,
            revision,
        }
    }

    /// Exploited ones first, then by EPSS, severity and id. Empty when the
    /// version does not parse or no range is sure to hold it.
    pub fn advisories(&self, product_id: &str, version: &str) -> Vec<Advisory> {
        let Some(version) = Version::parse(version) else {
            return Vec::new();
        };
        let mut rows: Vec<Advisory> = Vec::new();
        for component in retire_components(product_id, &version) {
            for entry in self.by_component.get(component).into_iter().flatten() {
                if in_range(&version, entry.from.as_ref(), &entry.below) != Some(true) {
                    continue;
                }
                let row = self.row(&entry.advisory);
                if !rows.iter().any(|existing| existing.id == row.id) {
                    rows.push(row);
                }
            }
        }
        rows.sort_by(|a, b| {
            b.kev
                .cmp(&a.kev)
                .then_with(|| match (a.epss, b.epss) {
                    (Some(a), Some(b)) => b.partial_cmp(&a).unwrap_or(Ordering::Equal),
                    (Some(_), None) => Ordering::Less,
                    (None, Some(_)) => Ordering::Greater,
                    (None, None) => Ordering::Equal,
                })
                .then_with(|| severity_rank(&a.severity).cmp(&severity_rank(&b.severity)))
                .then_with(|| a.id.cmp(&b.id))
        });
        rows
    }

    pub fn summary(&self, product_id: &str, version: &str) -> Option<Summary> {
        let rows = self.advisories(product_id, version);
        let highest = rows
            .iter()
            .min_by_key(|row| severity_rank(&row.severity))?
            .severity
            .clone();
        Some(Summary {
            count: rows.len(),
            kev_count: rows.iter().filter(|row| row.kev).count(),
            highest_severity: highest,
        })
    }

    fn row(&self, advisory: &RetireAdvisory) -> Advisory {
        let id = advisory
            .cves
            .first()
            .or(advisory.ghsa.as_ref())
            .cloned()
            .unwrap_or_else(|| format!("retire:{}:{}", advisory.component, advisory.below));
        Advisory {
            id,
            cves: advisory.cves.clone(),
            severity: advisory.severity.clone(),
            summary: advisory.summary.clone(),
            fixed_in: advisory.below.clone(),
            urls: advisory.urls.clone(),
            kev: advisory.cves.iter().any(|cve| self.kev.contains(cve)),
            epss: advisory
                .cves
                .iter()
                .filter_map(|cve| self.epss.get(cve).copied())
                .reduce(f32::max),
        }
    }
}

fn severity_rank(severity: &str) -> u8 {
    match severity {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        _ => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn advisory(component: &str, from: Option<&str>, below: &str, cve: &str) -> RetireAdvisory {
        RetireAdvisory {
            component: component.into(),
            at_or_above: from.map(str::to_string),
            below: below.into(),
            severity: "medium".into(),
            cves: vec![cve.into()],
            ghsa: None,
            summary: Some(format!("{cve} summary")),
            urls: vec![format!("https://example.com/{cve}")],
        }
    }

    pub(crate) fn fixture_index() -> VulnIndex {
        VulnIndex::build(
            vec![
                advisory("jquery", Some("1.0.3"), "3.5.0", "CVE-2020-11023"),
                advisory("jquery", None, "3.4.0", "CVE-2019-11358"),
                advisory("react", Some("16.0.0"), "16.0.1", "CVE-2018-6341"),
                advisory("react-dom", Some("16.0.0"), "16.0.1", "CVE-2018-6341"),
            ],
            HashSet::from(["CVE-2020-11023".to_string()]),
            HashMap::from([("CVE-2020-11023".to_string(), 0.94)]),
            "test".into(),
        )
    }

    #[test]
    fn a_version_gets_the_advisories_whose_range_holds_it_exploited_first() {
        let index = fixture_index();
        let one = index.advisories("jquery", "3.4.1");
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].id, "CVE-2020-11023");
        assert!(one[0].kev);
        assert_eq!(one[0].epss, Some(0.94));
        assert_eq!(one[0].fixed_in, "3.5.0");

        let two = index.advisories("jquery", "3.3.1");
        assert_eq!(two.len(), 2);
        assert_eq!(two[0].id, "CVE-2020-11023");
        assert_eq!(two[1].id, "CVE-2019-11358");
        assert!(!two[1].kev);
        assert_eq!(two[1].epss, None);

        assert!(index.advisories("jquery", "3").is_empty());
        assert_eq!(index.advisories("react", "16.0.0").len(), 1);
    }

    // EPSS scores every published CVE, some 300,000 of them; only the few the
    // advisories name are ever read.
    #[test]
    fn the_index_keeps_only_the_scores_its_advisories_name() {
        let index = VulnIndex::build(
            vec![advisory("jquery", None, "3.5.0", "CVE-2020-11023")],
            HashSet::from(["CVE-2020-11023".to_string(), "CVE-2021-44228".to_string()]),
            HashMap::from([
                ("CVE-2020-11023".to_string(), 0.94),
                ("CVE-2021-44228".to_string(), 0.97),
            ]),
            "test".into(),
        );
        assert_eq!(index.epss.len(), 1);
        assert_eq!(index.kev.len(), 1);
    }

    #[test]
    fn a_summary_counts_advisories_and_exploited_ones() {
        let index = fixture_index();
        assert_eq!(
            index.summary("jquery", "3.3.1"),
            Some(Summary {
                count: 2,
                kev_count: 1,
                highest_severity: "medium".into(),
            })
        );
        assert_eq!(index.summary("jquery", "3.5.0"), None);
    }
}
