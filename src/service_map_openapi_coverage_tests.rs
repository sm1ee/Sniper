//! The cap signal describes source tallies, not overall schema completeness
//! or a count of distinct fields missing after path variants are merged.
use chrono::{DateTime, Utc};
use http::HeaderMap;
use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::{
    model::{MessageRecord, TransactionRecord},
    store::TransactionStore,
};

const ORIGIN: &str = "https://api.example.com";
const CAP_SIGNAL: &str = "x-sniper-parameter-cap-truncated";
const PRIVATE_VALUE: &str = "SYNTHETIC_PRIVATE_PARAMETER_VALUE";

fn names(prefix: &str, count: usize) -> Vec<String> {
    (0..count)
        .map(|index| format!("{prefix}{index:03}"))
        .collect()
}

fn record(
    sequence: u64,
    method: &str,
    path: &str,
    query: Vec<String>,
    body_fields: Option<Vec<String>>,
) -> TransactionRecord {
    let mut request_headers = HeaderMap::new();
    request_headers.insert(
        "authorization",
        "Bearer SYNTHETIC_PRIVATE_TOKEN".parse().unwrap(),
    );
    let body = body_fields.map_or_else(Vec::new, |fields| {
        request_headers.insert("content-type", "application/json".parse().unwrap());
        serde_json::to_vec(
            &fields
                .into_iter()
                .map(|name| (name, json!(PRIVATE_VALUE)))
                .collect::<Map<_, _>>(),
        )
        .unwrap()
    });
    let mut response_headers = HeaderMap::new();
    response_headers.insert("content-type", "application/json".parse().unwrap());
    let path = if query.is_empty() {
        path.to_string()
    } else {
        format!(
            "{path}?{}",
            query
                .into_iter()
                .map(|name| format!("{name}={PRIVATE_VALUE}"))
                .collect::<Vec<_>>()
                .join("&")
        )
    };
    let mut record = TransactionRecord::http(
        DateTime::<Utc>::from_timestamp(1_760_000_000 + sequence as i64, 0).unwrap(),
        method.into(),
        "https".into(),
        "api.example.com".into(),
        path,
        Some(200),
        1,
        MessageRecord::from_headers_and_body(&request_headers, &body, 64 * 1024),
        Some(MessageRecord::from_headers_and_body(
            &response_headers,
            b"{}",
            1024,
        )),
        Vec::new(),
        None,
        None,
    );
    record.id = Uuid::from_u128(sequence as u128);
    record.sequence = sequence;
    record
}

fn store(mut chronological: Vec<TransactionRecord>) -> TransactionStore {
    chronological.reverse();
    TransactionStore::from_records(chronological)
}

async fn exported(store: &TransactionStore) -> Value {
    let document = store
        .service_map_openapi(Uuid::nil(), ORIGIN)
        .await
        .unwrap();
    assert_eq!(document["openapi"], "3.1.0");
    assert_eq!(document["servers"], json!([{"url": ORIGIN}]));
    assert!(!document.to_string().contains("SYNTHETIC_PRIVATE"));
    document
}

#[tokio::test]
async fn parameter_cap_signal_distinguishes_query_and_body_boundaries() {
    for location in ["query", "json"] {
        for count in [0, 199, 200, 201] {
            let method = if location == "query" { "GET" } else { "POST" };
            let row = if location == "query" {
                record(1, method, "/fields", names("p", count), None)
            } else {
                record(1, method, "/fields", vec![], Some(names("p", count)))
            };
            let store = store(vec![row]);
            let parameters = store
                .service_map_parameters(Uuid::nil(), ORIGIN, method, "/fields")
                .await;
            assert!(parameters.available);
            assert_eq!(parameters.rows, 1);
            assert!(!parameters.more_rows);
            assert_eq!(parameters.parameters.len(), count.min(200));
            assert_eq!(parameters.omitted_parameters, count.saturating_sub(200));
            let document = exported(&store).await;
            let operation = &document["paths"]["/fields"][method.to_ascii_lowercase()];
            let retained = if location == "query" {
                operation["parameters"].as_array().map_or(0, Vec::len)
            } else {
                operation["requestBody"]["content"]["application/json"]["schema"]["properties"]
                    .as_object()
                    .map_or(0, Map::len)
            };
            assert_eq!(retained, count.min(200));
            assert_eq!(operation["x-sniper-requests"], 1);
            assert_eq!(
                operation.get(CAP_SIGNAL),
                (count > 200).then_some(&Value::Bool(true)),
                "{location} {count}"
            );
        }
    }
}

fn merged_rows(truncated: bool) -> Vec<TransactionRecord> {
    let count = if truncated { 201 } else { 200 };
    vec![
        record(1, "GET", "/items/42", names("p", count), None),
        record(
            2,
            "GET",
            "/items/507f1f77bcf86cd799439011",
            names("p", count),
            None,
        ),
        // This variant recovers the same name omitted by both capped tallies.
        record(
            3,
            "GET",
            "/items/550e8400-e29b-41d4-a716-446655440000",
            vec!["p200".into()],
            None,
        ),
        record(4, "PATCH", "/items/42", names("p", 200), None),
        record(5, "GET", "/other", names("p", 200), None),
    ]
}

#[tokio::test]
async fn parameter_cap_signal_survives_merged_variants_without_claiming_missing_names() {
    let mut document = exported(&store(merged_rows(true))).await;
    let control = exported(&store(merged_rows(false))).await;
    let paths = document["paths"].as_object().unwrap();
    assert_eq!(
        paths.keys().map(String::as_str).collect::<Vec<_>>(),
        ["/items/{id}", "/other"]
    );
    let item = &paths["/items/{id}"];
    assert_eq!(item["parameters"][0]["name"], "id");
    assert_eq!(
        item["parameters"][0]["schema"]["anyOf"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    let get = &item["get"];
    assert_eq!(get["parameters"].as_array().unwrap().len(), 201);
    assert_eq!(get["parameters"][200]["name"], "p200");
    assert_eq!(get["x-sniper-requests"], 3);
    assert_eq!(
        get["x-sniper-newest-transaction"],
        Uuid::from_u128(3).to_string()
    );
    assert!(item["patch"].get(CAP_SIGNAL).is_none());
    assert!(paths["/other"]["get"].get(CAP_SIGNAL).is_none());
    assert_eq!(get.get(CAP_SIGNAL), Some(&Value::Bool(true)));
    // No invented warning paths/fields, count, status, type, auth or ID change.
    assert_eq!(
        document["paths"]["/items/{id}"]["get"]
            .as_object_mut()
            .unwrap()
            .remove(CAP_SIGNAL),
        Some(Value::Bool(true))
    );
    assert_eq!(document, control);
}

#[tokio::test]
async fn parameter_cap_signal_does_not_cap_the_union_of_uncapped_variants() {
    let store = store(vec![
        record(1, "GET", "/items/42", names("p", 200), None),
        record(
            2,
            "GET",
            "/items/550e8400-e29b-41d4-a716-446655440000",
            names("q", 200),
            None,
        ),
    ]);
    let document = exported(&store).await;
    let operation = &document["paths"]["/items/{id}"]["get"];
    assert_eq!(operation["parameters"].as_array().unwrap().len(), 400);
    assert!(operation.get(CAP_SIGNAL).is_none());
}

#[tokio::test]
async fn parameter_cap_signal_is_not_an_overall_sampling_completeness_claim() {
    let store = store(
        (0..21)
            .map(|index| {
                record(
                    index + 1,
                    "GET",
                    "/sampled",
                    vec![format!("p{index:03}")],
                    None,
                )
            })
            .collect(),
    );
    let parameters = store
        .service_map_parameters(Uuid::nil(), ORIGIN, "GET", "/sampled")
        .await;
    assert_eq!(parameters.rows, 21);
    assert_eq!(parameters.parameters.len(), 21);
    assert_eq!(parameters.omitted_parameters, 0);
    let document = exported(&store).await;
    let operation = &document["paths"]["/sampled"]["get"];
    let names: Vec<_> = operation["parameters"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["name"].as_str().unwrap())
        .collect();
    assert_eq!(names.len(), 20);
    assert!(
        !names.contains(&"p000"),
        "oldest row is outside the documented parameter sample"
    );
    assert_eq!(operation["x-sniper-requests"], 21);
    assert!(operation.get(CAP_SIGNAL).is_none());
}
