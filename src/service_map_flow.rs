//! The Map's Flow view: one origin's retained requests and those of the
//! origins it links to directly, in time order, one phase per page load.

use std::collections::{BTreeMap, BTreeSet};

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

#[derive(Clone, Debug, PartialEq, Serialize)]
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
        stopped_by: window_stops,
        ..
    } = snapshot;
    let considered_rows = window.len();
    let mut scope = BoundedScope::new(include, exclude)?;
    let mut rows = Vec::new();
    for row in window {
        if !row.is_websocket && (!in_scope_only || scope.contains(&row.scope_host)?) {
            rows.push(row);
        }
    }
    let mut stopped_by: BTreeSet<String> = window_stops;
    let lanes = lanes(&rows, origin, &mut stopped_by);
    rows.retain(|row| lanes.contains(&row.origin));
    rows.sort_by_key(|row| {
        (
            row.started_at,
            row.sequence.parse::<u64>().unwrap_or(u64::MAX),
        )
    });
    let flow_rows = rows.len();

    let mut phases: Vec<FlowPhase> = Vec::new();
    for row in rows {
        if row.request_kind == "navigation" {
            phases.push(FlowPhase {
                page: Some(FlowTarget {
                    origin: row.origin.clone(),
                    path: row.path.clone(),
                }),
                steps: Vec::new(),
            });
        } else if phases.is_empty() {
            phases.push(FlowPhase {
                page: None,
                steps: Vec::new(),
            });
        }
        let steps = &mut phases.last_mut().expect("a phase was pushed").steps;
        let path = path_group(&row.path).unwrap_or(row.path);
        let redirect = row.redirect.map(|target| FlowTarget {
            path: path_group(&target.target_path).unwrap_or(target.target_path),
            origin: target.target_origin,
        });
        let same = |step: &&mut FlowStep| {
            step.origin == row.origin
                && step.method == row.method
                && step.path == path
                && step.status == row.status
                && step.request_kind == row.request_kind
                && step.redirect == redirect
        };
        if let Some(step) = steps.iter_mut().find(same) {
            step.count += 1;
            step.last_seen = row.started_at;
            step.record_id = row.record_id;
            step.evidence.truncate(1);
            step.evidence.push(row.evidence_id);
        } else {
            steps.push(FlowStep {
                origin: row.origin,
                method: row.method,
                path,
                status: row.status,
                request_kind: row.request_kind,
                count: 1,
                first_seen: row.started_at,
                last_seen: row.started_at,
                evidence: vec![row.evidence_id],
                record_id: row.record_id,
                redirect,
            });
        }
    }
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
