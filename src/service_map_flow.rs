//! The Map's Flow view: one origin's retained requests and those of the
//! origins it links to directly, in time order, one phase per page load.

use std::collections::{hash_map::Entry, BTreeMap, BTreeSet, HashMap};

use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

use crate::scope;
use crate::service_map::{path_group, BoundedScope, MetadataSnapshot, ServiceMapRow};

/// The selected origin and up to five origins it links to directly.
pub const MAX_LANES: usize = 6;
/// Steps after folding; the newest are kept.
pub const MAX_STEPS: usize = 300;

#[derive(Debug, Serialize)]
pub struct ServiceMapFlow {
    pub schema_version: u32,
    pub session_id: Uuid,
    pub origin: String,
    /// The selected origin first, then its neighbours, most linked first.
    pub lanes: Vec<String>,
    pub phases: Vec<FlowPhase>,
    /// Rows in the window, and how many of them the flow shows.
    pub considered_rows: usize,
    pub flow_rows: usize,
    pub complete: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub stopped_by: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct FlowPhase {
    /// The navigation that started this page load; absent for the rows
    /// before the first one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page: Option<FlowTarget>,
    pub steps: Vec<FlowStep>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
pub struct FlowTarget {
    pub origin: String,
    pub path: String,
}

#[derive(Debug, Serialize)]
pub struct FlowStep {
    /// The lane the request went to.
    pub origin: String,
    pub method: String,
    /// The path with IDs grouped, as the API list shows it.
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    pub request_kind: &'static str,
    /// Rows folded into this step: the same request in the same page load.
    pub count: usize,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    /// The first and the newest row's evidence; one entry for one row.
    pub evidence: Vec<String>,
    /// The newest row, for opening it in HTTP history.
    pub record_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect: Option<FlowTarget>,
}

pub(crate) fn build(
    session_id: Uuid,
    snapshot: MetadataSnapshot,
    origin: &str,
    in_scope_only: bool,
    include: &[String],
    exclude: &[String],
) -> Result<ServiceMapFlow, scope::ScopeWorkLimit> {
    let MetadataSnapshot {
        rows: window,
        considered_rows,
        stopped_by: window_stops,
        ..
    } = snapshot;
    let mut scope = BoundedScope::new(include, exclude)?;
    let mut rows = Vec::new();
    let mut stopped_by: BTreeSet<String> = window_stops;
    for row in window {
        if !row.is_websocket && (!in_scope_only || scope.contains(&row.scope_host)?) {
            // A suppressed header link can hide a neighbour, so inspect these
            // reasons before choosing lanes, not only in the rows they retain.
            stopped_by.extend(
                row.omitted
                    .iter()
                    .filter(|reason| affects_flow(&row, reason))
                    .cloned(),
            );
            rows.push(row);
        }
    }
    let lanes = lanes(&rows, origin, &mut stopped_by);
    rows.retain(|row| lanes.contains(&row.origin));
    rows.sort_by_key(|row| {
        (
            row.started_at,
            row.sequence.parse::<u64>().unwrap_or(u64::MAX),
        )
    });
    let mut phases = fold_rows(rows);
    // The newest steps are the ones being looked at; drop from the oldest.
    let mut total: usize = phases.iter().map(|phase| phase.steps.len()).sum();
    while total > MAX_STEPS {
        stopped_by.insert("steps_limit".into());
        let excess = total - MAX_STEPS;
        if phases[0].steps.len() <= excess {
            total -= phases.remove(0).steps.len();
        } else {
            phases[0].steps.drain(..excess);
            total -= excess;
        }
    }
    let flow_rows = phases
        .iter()
        .flat_map(|phase| &phase.steps)
        .map(|step| step.count)
        .sum();
    Ok(ServiceMapFlow {
        schema_version: 1,
        session_id,
        origin: origin.into(),
        lanes,
        phases,
        considered_rows,
        flow_rows,
        complete: stopped_by.is_empty(),
        stopped_by: stopped_by.into_iter().collect(),
    })
}

// The index belongs to one page load. Keys retain only the exact fields the
// old linear search compared, never bodies, headers, or whole metadata rows.
// There is at most one key per distinct step in the current phase, bounded by
// the projected row window. Only a new step duplicates its grouped identity.
#[derive(Eq, Hash, PartialEq)]
struct StepKey {
    origin: String,
    method: String,
    path: String,
    status: Option<u16>,
    request_kind: &'static str,
    redirect: Option<FlowTarget>,
}

fn fold_rows(rows: Vec<ServiceMapRow>) -> Vec<FlowPhase> {
    let mut phases: Vec<FlowPhase> = Vec::new();
    let mut index = HashMap::<StepKey, usize>::new();
    for row in rows {
        if row.request_kind == "navigation" {
            phases.push(FlowPhase {
                page: Some(FlowTarget {
                    origin: row.origin.clone(),
                    path: row.path.clone(),
                }),
                steps: Vec::new(),
            });
            index.clear();
        } else if phases.is_empty() {
            phases.push(FlowPhase {
                page: None,
                steps: Vec::new(),
            });
        }
        let steps = &mut phases.last_mut().expect("a phase was pushed").steps;
        let key = StepKey {
            origin: row.origin,
            method: row.method,
            path: path_group(&row.path).unwrap_or(row.path),
            status: row.status,
            request_kind: row.request_kind,
            redirect: row.redirect.map(|target| FlowTarget {
                path: path_group(&target.target_path).unwrap_or(target.target_path),
                origin: target.target_origin,
            }),
        };
        match index.entry(key) {
            Entry::Occupied(entry) => {
                let step = &mut steps[*entry.get()];
                step.count += 1;
                step.last_seen = row.started_at;
                step.record_id = row.record_id;
                step.evidence.truncate(1);
                step.evidence.push(row.evidence_id);
            }
            Entry::Vacant(entry) => {
                let key = entry.key();
                steps.push(FlowStep {
                    origin: key.origin.clone(),
                    method: key.method.clone(),
                    path: key.path.clone(),
                    status: key.status,
                    request_kind: key.request_kind,
                    count: 1,
                    first_seen: row.started_at,
                    last_seen: row.started_at,
                    evidence: vec![row.evidence_id],
                    record_id: row.record_id,
                    redirect: key.redirect.clone(),
                });
                entry.insert(steps.len() - 1);
            }
        }
    }
    phases
}

fn affects_flow(row: &ServiceMapRow, reason: &str) -> bool {
    match reason {
        "request_header_scan_limit"
        | "request_header_value_limit"
        | "ambiguous_origin_header"
        | "ambiguous_referer_header"
        | "ambiguous_location_headers"
        | "unsupported_location" => true,
        "header_scan_limit" => {
            row.redirect.is_none()
                && row
                    .status
                    .is_some_and(|status| matches!(status, 300 | 301 | 302 | 303 | 307 | 308))
        }
        "header_value_limit" => row.redirect_value_omitted,
        // Technology, content-type and unnamed-signal omissions do not change
        // Flow's lanes or arrows. An unrelated oversized response header says
        // nothing about whether a Location was present or could be read.
        _ => false,
    }
}

/// The selected origin, then the origins its rows link to directly by an
/// Origin or Referer header or a redirect, either way, most rows first.
fn lanes(rows: &[ServiceMapRow], origin: &str, stopped_by: &mut BTreeSet<String>) -> Vec<String> {
    let mut links: BTreeMap<&str, usize> = BTreeMap::new();
    for row in rows {
        if row.origin == origin {
            let sources = row
                .header_links
                .iter()
                .map(|link| link.source_origin.as_str());
            let target = row
                .redirect
                .as_ref()
                .map(|target| target.target_origin.as_str());
            for other in sources.chain(target).collect::<BTreeSet<_>>() {
                if other != origin {
                    *links.entry(other).or_default() += 1;
                }
            }
        } else if row
            .header_links
            .iter()
            .any(|link| link.source_origin == origin)
            || row
                .redirect
                .as_ref()
                .is_some_and(|target| target.target_origin == origin)
        {
            *links.entry(row.origin.as_str()).or_default() += 1;
        }
    }
    let mut neighbours: Vec<_> = links.into_iter().collect();
    neighbours.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
    if neighbours.len() > MAX_LANES - 1 {
        stopped_by.insert("lanes_limit".into());
    }
    std::iter::once(origin.to_string())
        .chain(
            neighbours
                .into_iter()
                .take(MAX_LANES - 1)
                .map(|(other, _)| other.to_string()),
        )
        .collect()
}

#[cfg(test)]
#[path = "service_map_flow_tests.rs"]
mod tests;
