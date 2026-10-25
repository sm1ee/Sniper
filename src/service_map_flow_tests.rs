use super::*;
use crate::model::{MessageRecord, TransactionRecord};
use crate::service_map::RedirectTarget;

fn row(sequence: u64) -> ServiceMapRow {
    let message = MessageRecord::from_headers_and_body(&http::HeaderMap::new(), b"", 0);
    let mut record = TransactionRecord::http(
        DateTime::<Utc>::from_timestamp(1_760_000_000 + sequence as i64, 0).unwrap(),
        "GET".into(),
        "https".into(),
        "www.example.com".into(),
        "/items/1".into(),
        Some(200),
        1,
        message.clone(),
        Some(message),
        vec![],
        None,
        None,
    );
    record.id = Uuid::from_u128(sequence as u128 + 1);
    record.sequence = sequence;
    let mut row =
        crate::service_map::project_record(&record, format!("evidence-{sequence}")).unwrap();
    row.request_kind = "api";
    row
}

// The linear folding loop from154e1a1 is the compatibility oracle. It is kept
// independent of StepKey, so missing fields, delimiter keys, or a stale phase
// index cannot make the implementation and expected result fail alike.
fn linear_fold(rows: Vec<ServiceMapRow>) -> Vec<FlowPhase> {
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
    phases
}

fn assert_equivalent(rows: Vec<ServiceMapRow>) {
    let indexed = fold_rows(rows.clone());
    let linear = linear_fold(rows);
    assert_eq!(
        serde_json::to_value(indexed).unwrap(),
        serde_json::to_value(linear).unwrap()
    );
}

#[test]
fn indexed_folding_keeps_full_identity_and_newest_evidence() {
    let mut rows = vec![row(1), row(2)];
    rows[1].path = "/items/2".into();
    for sequence in 3..=12 {
        let mut item = row(sequence);
        match sequence {
            3 => item.origin = "https://api.example.com".into(),
            4 => item.method = "POST".into(),
            5 => item.status = Some(201),
            6 => item.request_kind = "script",
            7 => item.path = "/accounts/1".into(),
            _ => {
                item.status = Some(302);
                item.redirect = match sequence {
                    8 => None,
                    9 | 10 => Some(RedirectTarget {
                        target_origin: "https://www.example.com".into(),
                        target_path: format!("/next/{sequence}"),
                    }),
                    11 => Some(RedirectTarget {
                        target_origin: "https://api.example.com".into(),
                        target_path: "/next/1".into(),
                    }),
                    _ => Some(RedirectTarget {
                        target_origin: "https://www.example.com".into(),
                        target_path: "/other/1".into(),
                    }),
                };
            }
        }
        rows.push(item);
    }
    rows.push(row(13));
    let mut navigation = row(14);
    navigation.request_kind = "navigation";
    navigation.path = "/page".into();
    rows.extend([navigation, row(15), row(16)]);
    assert_equivalent(rows.clone());
    let phases = fold_rows(rows);
    assert_eq!(phases.len(), 2);
    assert_eq!(phases[0].steps.len(), 10);
    assert_eq!(phases[1].steps.len(), 2);
    assert_eq!(
        phases
            .iter()
            .flat_map(|p| &p.steps)
            .map(|s| s.count)
            .sum::<usize>(),
        16
    );
    let first = &phases[0].steps[0];
    assert_eq!(first.path, "/items/{number}");
    assert_eq!(first.count, 3);
    assert_eq!(first.evidence, ["evidence-1", "evidence-13"]);
    assert_eq!(first.record_id, row(13).record_id);
    assert_eq!(first.first_seen, row(1).started_at);
    assert_eq!(first.last_seen, row(13).started_at);
    let redirect = &phases[0].steps[7];
    assert_eq!(redirect.count, 2);
    assert_eq!(redirect.evidence, ["evidence-9", "evidence-10"]);
    assert_eq!(redirect.redirect.as_ref().unwrap().path, "/next/{number}");
    let after_navigation = &phases[1].steps[1];
    assert_eq!(after_navigation.count, 2);
    assert_eq!(after_navigation.evidence, ["evidence-15", "evidence-16"]);
    assert_eq!(after_navigation.first_seen, row(15).started_at);
}

#[test]
fn indexed_folding_matches_linear_sequences_with_delimiter_like_values() {
    let origins = ["https://www.example.com", "https://api.example.com:8443"];
    let methods = ["GET", "POST", "GET|HEAD"];
    let paths = [
        "/items/1",
        "/items/2",
        "/literal|200|api",
        "/colon:GET",
        "/spaces%20and%7Cpipes",
        "/unicode/한글",
    ];
    let kinds = ["api", "script", "static", "other"];
    for seed in 0..32usize {
        let mut rows = Vec::new();
        for i in 0..180usize {
            let mut item = row(i as u64 + 1);
            let value = (i / 3 + seed * 17) % 61;
            item.origin = origins[value % origins.len()].into();
            item.method = methods[(value / 2) % methods.len()].into();
            item.path = paths[(value / 3) % paths.len()].into();
            item.status = [None, Some(200), Some(302), Some(404)][(value / 5) % 4];
            item.request_kind = if i % (seed + 7) == 0 {
                "navigation"
            } else {
                kinds[(value / 7) % kinds.len()]
            };
            item.redirect = (value % 4 != 0).then(|| RedirectTarget {
                target_origin: origins[(value / 11) % origins.len()].into(),
                target_path: paths[(value / 13) % paths.len()].into(),
            });
            rows.push(item);
        }
        assert_equivalent(rows);
    }
    assert_equivalent(vec![]);
    let duplicate = row(1);
    assert_equivalent(vec![duplicate.clone(), duplicate.clone()]);
    let phases = fold_rows(vec![duplicate.clone(), duplicate]);
    assert_eq!(phases[0].steps[0].evidence, ["evidence-1", "evidence-1"]);
}
