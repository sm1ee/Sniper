use super::*;
use crate::{
    model::{HeaderRecord, MessageRecord},
    store::TransactionStore,
};
use std::time::Instant;

fn fixture_record(host: &str, sequence: u64) -> TransactionRecord {
    let message = MessageRecord::from_headers_and_body(&http::HeaderMap::new(), b"", 0);
    let mut record = TransactionRecord::http(
        DateTime::<Utc>::from_timestamp(1_760_000_000, 0).unwrap(),
        "GET".into(),
        "https".into(),
        host.into(),
        "/items/1?synthetic=1".into(),
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
    record.response.as_mut().unwrap().headers = vec![HeaderRecord {
        name: "Server".into(),
        value: "nginx/1.28.0 Caddy/2.9.1".into(),
    }];
    record
}

fn same_output(mut legacy: ServiceMap, mut bounded: ServiceMap) {
    legacy.snapshot.id = Uuid::nil();
    bounded.snapshot.id = Uuid::nil();
    assert_eq!(
        serde_json::to_vec(&legacy).unwrap(),
        serde_json::to_vec(&bounded).unwrap()
    );
}

fn expensive_scope() -> (Vec<String>, Vec<String>) {
    let include = vec!["*.example.com".into()];
    let exclude = (0..500)
        .map(|i| format!("{}z{i:03}*", "*a".repeat(230)))
        .collect();
    (include, exclude)
}

fn long_host(index: usize) -> String {
    format!(
        "{index:03}.{}.{}.{}.{}.example.com",
        "a".repeat(63),
        "a".repeat(63),
        "a".repeat(63),
        "a".repeat(43)
    )
}

#[test]
fn bounded_scope_raw_semantics_include_ipv6_malformed_and_empty() {
    let values = [
        "",
        " ",
        "*",
        "*.",
        "**",
        "*.*",
        "a*b",
        "ab",
        "a..",
        "*.EXAMPLE.com.",
        "https://API.Example.com:443/path?synthetic#fragment",
        "//api.example.com",
        "API.Example.com.:8443",
        "[2001:db8::1]:443",
        "[::1]ignored",
        "a:invalid",
        "\u{2003}API.example.com\u{2003}",
        "2001:db8::1",
        "[::1",
        "[::1]",
        "127.0.0.1:443",
        "127.1",
        "Ä.Example.com",
        "ä.example.com",
        "example.com@other.example.com",
        "a*b*c",
        "a**b",
        "a*b*",
        "*a*b",
    ];
    for host in values {
        for pattern in values {
            for (include, exclude) in [
                (vec![pattern.to_owned()], vec![]),
                (vec![], vec![pattern.to_owned()]),
            ] {
                let expected = scope::is_host_in_scope(host, &include, &exclude);
                let mut bounded = BoundedScope::new(&include, &exclude).unwrap();
                assert_eq!(
                    bounded.contains(host),
                    Ok(expected),
                    "{host:?}, {pattern:?}"
                );
                let remaining = bounded.remaining;
                assert_eq!(bounded.contains(host), Ok(expected));
                assert_eq!(bounded.remaining, remaining);
            }
        }
    }
    let mut empty = BoundedScope::new(&[], &[]).unwrap();
    empty.remaining = 0;
    for host in values {
        assert_eq!(empty.contains(host), Ok(true));
    }
    assert!(empty.cache.is_empty());
    assert_eq!(empty.cache_key_bytes, 0);
}

#[test]
fn bounded_scope_budget_boundaries_and_completed_true_false_cache() {
    let include = vec!["*.example.com".into()];
    let exclude = vec!["*.blocked.example.com".into()];
    let mut bounded = BoundedScope::new(&include, &exclude).unwrap();
    for (host, expected) in [("api.example.com", true), ("a.blocked.example.com", false)] {
        assert_eq!(bounded.contains(host), Ok(expected));
        let remaining = bounded.remaining;
        assert_eq!(bounded.contains(host), Ok(expected));
        assert_eq!(bounded.remaining, remaining);
        assert_eq!(bounded.cache.get(host), Some(&expected));
    }
    // Canonical aliases must not accidentally reuse the raw-host cache key.
    assert_eq!(bounded.contains("API.Example.com.:443"), Ok(true));
    assert_eq!(bounded.cache.len(), 3);
    let host = "api.example.com";
    let mut measured = BoundedScope::new(&include, &exclude).unwrap();
    measured.contains(host).unwrap();
    let cost = MAX_SCOPE_WORK - measured.remaining;
    assert!(cost > 0);
    let mut exact = BoundedScope::new(&include, &exclude).unwrap();
    exact.remaining = cost;
    assert_eq!(exact.contains(host), Ok(true));
    assert_eq!(exact.remaining, 0);
    assert_eq!(exact.contains(host), Ok(true));
    let mut short = BoundedScope::new(&include, &exclude).unwrap();
    short.remaining = cost - 1;
    assert_eq!(short.contains(host), Err(scope::ScopeWorkLimit));
    assert!(short.cache.is_empty());
    assert_eq!(short.cache_key_bytes, 0);
}

#[test]
fn bounded_scope_cache_entry_and_byte_limits_keep_charging_uncached_hosts() {
    let exclude = vec!["*.blocked.example.com".into()];
    for fill_bytes in [false, true] {
        let mut bounded = BoundedScope::new(&[], &exclude).unwrap();
        let count = if fill_bytes {
            MAX_SCOPE_CACHE_KEY_BYTES / 512
        } else {
            MAX_SCOPE_CACHE_ENTRIES
        };
        for index in 0..count {
            let prefix = format!("{index:03}.");
            let host = if fill_bytes {
                format!("{prefix}{}", "a".repeat(512 - prefix.len()))
            } else {
                format!("{prefix}example.com")
            };
            assert_eq!(bounded.contains(&host), Ok(true));
        }
        assert_eq!(bounded.cache.len(), count);
        if fill_bytes {
            assert_eq!(bounded.cache_key_bytes, MAX_SCOPE_CACHE_KEY_BYTES);
        }
        let bytes = bounded.cache_key_bytes;
        let host = "uncached.example.com";
        let cost = host.len() + exclude[0].len() + 16;
        bounded.remaining = cost * 2;
        assert_eq!(bounded.contains(host), Ok(true));
        assert_eq!(bounded.remaining, cost);
        assert_eq!(bounded.contains(host), Ok(true));
        assert_eq!(bounded.remaining, 0);
        assert_eq!(bounded.contains(host), Err(scope::ScopeWorkLimit));
        assert_eq!(bounded.cache.len(), count);
        assert_eq!(bounded.cache_key_bytes, bytes);
        assert!(!bounded.cache.contains_key(host));
    }
}

#[tokio::test]
async fn bounded_scope_preparation_rejects_instead_of_truncating() {
    let session = Uuid::from_u128(90);
    let store = TransactionStore::from_records(vec![fixture_record("api.example.com", 1)]);
    let snapshot = store.service_map_snapshot(session, 10).await;
    for (include, exclude) in [
        (vec!["example.com".into(); 501], vec![]),
        (vec![], vec!["example.com".into(); 501]),
        (vec!["x".repeat(513)], vec![]),
        (vec![], vec!["x".repeat(513)]),
    ] {
        assert!(matches!(
            build_bounded(
                session,
                snapshot.clone(),
                10,
                false,
                None,
                &include,
                &exclude
            ),
            Err(scope::ScopeWorkLimit)
        ));
    }
    let boundary = vec!["x".repeat(512); 500];
    assert!(build_bounded(session, snapshot, 10, false, None, &boundary, &boundary).is_ok());
}

#[tokio::test]
async fn bounded_scope_complete_v1_v2_outputs_equal_legacy_bytes() {
    let session = Uuid::from_u128(92);
    let hosts = [
        "API.Example.com.:443",
        "api.example.com:8443",
        "outside.example.com",
        "excluded.example.com",
        "[2001:db8::1]:443",
        "[2001:0db8:0:0:0:0:0:1]:443",
        "127.0.0.1:443",
        "Ä.example.com",
        "xn--4ca.example.com",
        "nested.api.example.com",
        "example.com/path",
        "[::1",
        "",
        "user:synthetic@example.com",
    ];
    let store = TransactionStore::from_records(
        hosts
            .iter()
            .enumerate()
            .map(|(index, host)| fixture_record(host, index as u64 + 1))
            .collect(),
    );
    let scopes = [
        (vec![], vec![]),
        (
            vec!["*.EXAMPLE.COM.:443".to_owned()],
            vec!["excluded.example.com".to_owned()],
        ),
        (vec![], vec!["*.example.com".to_owned()]),
        (
            vec!["*a*i*.example.com".to_owned()],
            vec!["nested.*".to_owned()],
        ),
        (vec!["[2001:0db8:0:0:0:0:0:1]:443".to_owned()], vec![]),
        (
            vec!["Ä.example.com".to_owned(), "api.example.com".to_owned()],
            vec!["ä.example.com".to_owned()],
        ),
    ];
    for catalog in [
        technology::CatalogVersion::V1,
        technology::CatalogVersion::V2,
    ] {
        let snapshot = store
            .service_map_snapshot_for_catalog(session, DEFAULT_MAX_RECORDS, catalog)
            .await;
        assert!(snapshot.omitted_rows > 0);
        for (include, exclude) in &scopes {
            for in_scope_only in [false, true] {
                for origin in [
                    None,
                    Some("https://api.example.com".into()),
                    Some("https://absent.example.com".into()),
                ] {
                    let legacy = build(
                        session,
                        snapshot.clone(),
                        DEFAULT_MAX_RECORDS,
                        in_scope_only,
                        origin.clone(),
                        include,
                        exclude,
                    );
                    let bounded = build_bounded(
                        session,
                        snapshot.clone(),
                        DEFAULT_MAX_RECORDS,
                        in_scope_only,
                        origin,
                        include,
                        exclude,
                    )
                    .unwrap();
                    same_output(legacy, bounded);
                }
            }
        }
    }
}

#[tokio::test]
async fn bounded_scope_distinct_host_exhaustion_returns_no_partial_map() {
    let session = Uuid::from_u128(93);
    let (include, exclude) = expensive_scope();
    let store = TransactionStore::from_records(
        (1..=40)
            .map(|i| fixture_record(&long_host(i), i as u64))
            .collect(),
    );
    let snapshot = store
        .service_map_snapshot(session, DEFAULT_MAX_RECORDS)
        .await;
    assert_eq!(snapshot.rows.len(), 40);
    assert!(matches!(
        build_bounded(
            session,
            snapshot,
            DEFAULT_MAX_RECORDS,
            false,
            None,
            &include,
            &exclude
        ),
        Err(scope::ScopeWorkLimit)
    ));
    let store = TransactionStore::from_records(
        (1..=1000)
            .map(|i| fixture_record(&long_host(1), i))
            .collect(),
    );
    let snapshot = store
        .service_map_snapshot(session, DEFAULT_MAX_RECORDS)
        .await;
    let expected = snapshot.rows.len();
    let bounded = build_bounded(
        session,
        snapshot,
        DEFAULT_MAX_RECORDS,
        false,
        None,
        &include,
        &exclude,
    )
    .unwrap();
    assert_eq!(bounded.snapshot.included_rows, expected);
    assert_eq!(bounded.snapshot.excluded_rows, 0);
    assert_eq!(bounded.origins[0].request_count, expected);
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "local synthetic bounded-path measurement; no timing thresholds"]
async fn bounded_scope_cost_measurement() {
    let session = Uuid::from_u128(94);
    for max_records in [DEFAULT_MAX_RECORDS, MAX_RECORDS] {
        for scenario in [
            "empty",
            "common",
            "dense_exact",
            "long_glob_repeated",
            "long_glob_unique",
        ] {
            let (include, exclude) = match scenario {
                "empty" => (vec![], vec![]),
                "common" => (
                    vec!["*.example.com".into()],
                    vec!["*.blocked.example.com".into()],
                ),
                "dense_exact" => {
                    let mut include: Vec<_> = (0..499)
                        .map(|i| format!("i-{i:03}.{}.example.com", "a".repeat(478)))
                        .collect();
                    include.push("api.example.com".into());
                    let exclude = (0..500)
                        .map(|i| format!("e-{i:03}.{}.example.com", "a".repeat(478)))
                        .collect();
                    (include, exclude)
                }
                _ => {
                    let mut include = (0..499)
                        .map(|i| format!("missing-{i:03}.example.com"))
                        .collect::<Vec<_>>();
                    include.push("*.example.com".into());
                    (include, expensive_scope().1)
                }
            };
            let baseline_long_host = format!(
                "{}.{}.{}.{}.example.com",
                "a".repeat(63),
                "a".repeat(63),
                "a".repeat(63),
                "a".repeat(47),
            );
            let store = std::sync::Arc::new(TransactionStore::from_records(
                (1..=MAX_RECORDS)
                    .rev()
                    .map(|i| {
                        let host = match scenario {
                            "long_glob_repeated" => baseline_long_host.clone(),
                            "long_glob_unique" => format!("{i:05}{}", &baseline_long_host[5..]),
                            _ => "api.example.com".into(),
                        };
                        let mut record = fixture_record(&host, i as u64);
                        // Match the earlier scope-cost audit's header-free rows.
                        record.response.as_mut().unwrap().headers.clear();
                        record
                    })
                    .collect(),
            ));
            for repetition in 1..=2 {
                let worker_store = std::sync::Arc::clone(&store);
                let include = include.clone();
                let exclude = exclude.clone();
                let (measurement, epoch) = tokio::task::spawn_blocking(move || {
                    // The uncontended wrapper timing includes read-lock acquisition,
                    // the coherent projection, and guard drop, but no queue delay.
                    let started = Instant::now();
                    let (snapshot, epoch) = worker_store.service_map_snapshot_blocking_for_catalog(session, max_records, technology::CatalogVersion::V1, &crate::store::ListFilters::default());
                    let projection = started.elapsed();
                    let projected_rows = snapshot.rows.len();
                    let legacy_snapshot = matches!(scenario, "empty" | "common").then(|| snapshot.clone());
                    let started = Instant::now();
                    let bounded = build_bounded(session, snapshot, max_records, false, None, &include, &exclude);
                    let bounded_elapsed = started.elapsed();
                    let result = if bounded.is_ok() { "ok" } else { "scope_work_limit" };
                    let serialization = bounded.as_ref().ok().map(|map| {
                        let started = Instant::now();
                        let bytes = serde_json::to_vec(map).unwrap().len();
                        (started.elapsed().as_secs_f64(), bytes)
                    });
                    let legacy_elapsed = legacy_snapshot.map(|snapshot| {
                        let started = Instant::now();
                        let legacy = build(session, snapshot, max_records, false, None, &include, &exclude);
                        let elapsed = started.elapsed();
                        same_output(legacy, bounded.unwrap());
                        elapsed.as_secs_f64()
                    });
                    assert_eq!(result, if scenario == "long_glob_unique" { "scope_work_limit" } else { "ok" });
                    (serde_json::json!({
                        "scenario": scenario, "repetition": repetition, "requested_rows": max_records,
                        "projected_rows": projected_rows, "projection_worker_seconds": projection.as_secs_f64(),
                        "bounded_build_seconds": bounded_elapsed.as_secs_f64(), "scope_preparation_included": true,
                        "legacy_build_seconds": legacy_elapsed, "serialization_seconds_and_bytes": serialization,
                        "result": result, "timing_claim": "local synthetic observation only; no native latency or deadline guarantee"
                    }), epoch)
                }).await.unwrap();
                assert!(store.service_map_metadata_epoch_matches(epoch).await);
                eprintln!("BOUNDED_SCOPE_MEASUREMENT {measurement}");
            }
        }
    }
}

#[tokio::test]
async fn bounded_scope_full_caches_never_omit_rows() {
    let session = Uuid::from_u128(95);
    for byte_limit in [false, true] {
        let base = if byte_limit {
            // Synthetic userinfo remains internal, while all rows have the same
            // canonical origin. This exercises 512-byte raw keys without the
            // map's unrelated origin or endpoint caps affecting the assertion.
            format!("{}@example.com", "a".repeat(500))
        } else {
            "api.example.com".into()
        };
        let count = if byte_limit { 300 } else { 600 };
        let records = (0..count)
            .map(|index| {
                let mut bit = 0;
                let host: String = base
                    .chars()
                    .map(|character| {
                        if character.is_ascii_alphabetic() && bit < 10 {
                            let upper = index & (1 << bit) != 0;
                            bit += 1;
                            if upper {
                                character.to_ascii_uppercase()
                            } else {
                                character
                            }
                        } else {
                            character
                        }
                    })
                    .collect();
                fixture_record(&host, index as u64 + 1)
            })
            .collect();
        let store = TransactionStore::from_records(records);
        let snapshot = store
            .service_map_snapshot(session, DEFAULT_MAX_RECORDS)
            .await;
        assert_eq!(snapshot.rows.len(), count);
        let include = vec!["*example.com".into()];
        let legacy = build(
            session,
            snapshot.clone(),
            DEFAULT_MAX_RECORDS,
            false,
            None,
            &include,
            &[],
        );
        let bounded = build_bounded(
            session,
            snapshot,
            DEFAULT_MAX_RECORDS,
            false,
            None,
            &include,
            &[],
        )
        .unwrap();
        assert_eq!(bounded.snapshot.included_rows, count);
        assert_eq!(bounded.snapshot.omitted_rows, 0);
        assert_eq!(bounded.snapshot.excluded_rows, 0);
        assert_eq!(bounded.origins.len(), 1);
        assert_eq!(bounded.origins[0].request_count, count);
        same_output(legacy, bounded);
    }
}

fn filter_fixture(
    host: &str,
    path: &str,
    status: u16,
    content_type: &str,
    referer: Option<&str>,
    sequence: u64,
) -> TransactionRecord {
    // MessageRecord derives its content type when built, so build it from headers.
    let mut response = http::HeaderMap::new();
    response.insert(http::header::CONTENT_TYPE, content_type.parse().unwrap());
    let mut request = http::HeaderMap::new();
    if let Some(value) = referer {
        request.insert(http::header::REFERER, value.parse().unwrap());
    }
    let mut record = fixture_record(host, sequence);
    record.path = path.into();
    record.status = Some(status);
    record.request = MessageRecord::from_headers_and_body(&request, b"", 0);
    record.response = Some(MessageRecord::from_headers_and_body(&response, b"", 0));
    record
}

// The Service Map display filter reuses HTTP history's row matcher, so a page's
// image CDN disappears with its rows and its Referer arrow, while the newest-row
// window that bounds the work stays the same size.
#[test]
fn display_filter_drops_rows_as_history_does_and_counts_them() {
    use crate::store::ListFilters;
    let session = Uuid::from_u128(97);
    let page = "https://www.example.com/";
    let store = TransactionStore::from_records(vec![
        filter_fixture("www.example.com", "/", 200, "text/html", None, 1),
        filter_fixture(
            "cdn.example.com",
            "/logo.png",
            200,
            "image/png",
            Some(page),
            2,
        ),
        filter_fixture(
            "api.example.com",
            "/v1/items",
            200,
            "application/json",
            Some(page),
            3,
        ),
        filter_fixture(
            "api.example.com",
            "/v1/missing",
            404,
            "application/json",
            Some(page),
            4,
        ),
    ]);
    let read = |filters: ListFilters| {
        let (snapshot, _) = store.service_map_snapshot_blocking_for_catalog(
            session,
            DEFAULT_MAX_RECORDS,
            technology::CatalogVersion::V1,
            &filters,
        );
        build_bounded(
            session,
            snapshot,
            DEFAULT_MAX_RECORDS,
            false,
            None,
            &[],
            &[],
        )
        .unwrap()
    };
    let origins = |map: &ServiceMap| -> Vec<String> {
        let mut ids: Vec<String> = map.origins.iter().map(|o| o.origin.clone()).collect();
        ids.sort();
        ids
    };
    let cdn = "https://cdn.example.com".to_string();

    let all = read(ListFilters::default());
    assert!(origins(&all).contains(&cdn));
    assert_eq!(all.snapshot.filtered_rows, 0);

    let static_hidden = read(ListFilters {
        hidden_extensions: vec!["png".into()],
        ..ListFilters::default()
    });
    assert!(!origins(&static_hidden).contains(&cdn));
    assert_eq!(static_hidden.snapshot.filtered_rows, 1);
    assert_eq!(static_hidden.snapshot.considered_rows, 4);
    assert_eq!(static_hidden.snapshot.included_rows, 3);

    let images_off = read(ListFilters {
        mime_types: Some(vec!["html".into(), "json".into()]),
        ..ListFilters::default()
    });
    assert_eq!(origins(&images_off), origins(&static_hidden));

    let success_only = read(ListFilters {
        status_classes: Some(vec!["success".into()]),
        ..ListFilters::default()
    });
    let api = success_only
        .origins
        .iter()
        .find(|origin| origin.origin == "https://api.example.com")
        .unwrap();
    assert!(api
        .endpoints
        .iter()
        .all(|endpoint| endpoint.path != "/v1/missing"));
    assert_eq!(success_only.snapshot.filtered_rows, 1);
}

fn with_request_headers(
    mut record: TransactionRecord,
    headers: &[(&str, &str)],
) -> TransactionRecord {
    for (name, value) in headers {
        record.request.headers.push(HeaderRecord {
            name: (*name).into(),
            value: (*value).into(),
        });
    }
    record
}

#[test]
fn request_kind_reads_sec_fetch_dest_then_the_response_type() {
    let kind = |dest: Option<&str>, content_type: &str, method: &str, origin: bool| {
        let mut headers = vec![];
        if let Some(dest) = dest {
            headers.push(("Sec-Fetch-Dest", dest));
        }
        if origin {
            headers.push(("Origin", "https://b.example.com"));
        }
        let mut record = with_request_headers(
            filter_fixture("a.example.com", "/", 200, content_type, None, 1),
            &headers,
        );
        record.method = method.into();
        request_kind(&record)
    };
    assert_eq!(
        kind(Some("empty"), "text/html", "GET", false),
        "api",
        "the browser's own declaration wins"
    );
    assert_eq!(
        kind(Some("document"), "application/json", "GET", false),
        "navigation"
    );
    assert_eq!(kind(Some("iframe"), "text/html", "GET", false), "frame");
    assert_eq!(
        kind(Some("serviceworker"), "text/plain", "GET", false),
        "script"
    );
    assert_eq!(kind(Some("Font"), "text/plain", "GET", false), "static");
    assert_eq!(kind(Some("report"), "text/plain", "POST", false), "other");
    assert_eq!(kind(None, "application/problem+json", "GET", false), "api");
    assert_eq!(kind(None, "text/html", "GET", false), "navigation");
    assert_eq!(kind(None, "image/webp", "GET", false), "static");
    assert_eq!(
        kind(None, "image/svg+xml", "GET", false),
        "static",
        "an SVG image is not XML data"
    );
    assert_eq!(kind(None, "text/javascript", "GET", false), "script");
    assert_eq!(
        kind(None, "application/octet-stream", "GET", true),
        "api",
        "an Origin header marks a cross-origin call"
    );
    assert_eq!(kind(None, "application/octet-stream", "POST", false), "api");
    assert_eq!(
        kind(None, "application/octet-stream", "GET", false),
        "other"
    );
}

// A page loading an image and a page calling an API used to be the same arrow.
// Each link now counts its rows and what kind of request each one was.
#[test]
fn links_count_their_rows_by_request_kind() {
    let session = Uuid::from_u128(98);
    let page = "https://www.example.com/";
    let dest = |record, value| with_request_headers(record, &[("Sec-Fetch-Dest", value)]);
    let store = TransactionStore::from_records(vec![
        dest(
            filter_fixture(
                "cdn.example.com",
                "/logo.png",
                200,
                "image/png",
                Some(page),
                1,
            ),
            "image",
        ),
        dest(
            filter_fixture(
                "cdn.example.com",
                "/app.js",
                200,
                "application/javascript",
                Some(page),
                2,
            ),
            "script",
        ),
        dest(
            filter_fixture(
                "api.example.com",
                "/v1/items",
                200,
                "application/json",
                Some(page),
                3,
            ),
            "empty",
        ),
        dest(
            filter_fixture(
                "api.example.com",
                "/v1/items",
                200,
                "application/json",
                Some(page),
                4,
            ),
            "empty",
        ),
        // An app sends no Sec-Fetch-Dest: the JSON response marks its API call.
        filter_fixture(
            "api.example.com",
            "/v1/app",
            200,
            "application/json",
            Some(page),
            5,
        ),
        dest(
            filter_fixture("login.example.com", "/", 200, "text/html", Some(page), 6),
            "document",
        ),
    ]);
    let (snapshot, _) = store.service_map_snapshot_blocking_for_catalog(
        session,
        DEFAULT_MAX_RECORDS,
        technology::CatalogVersion::V1,
        &crate::store::ListFilters::default(),
    );
    let map = build_bounded(
        session,
        snapshot,
        DEFAULT_MAX_RECORDS,
        false,
        None,
        &[],
        &[],
    )
    .unwrap();
    let link = |host: &str| {
        map.origins
            .iter()
            .find(|origin| origin.origin == format!("https://{host}"))
            .unwrap()
            .header_links[0]
            .clone()
    };
    let kinds = |pairs: &[(&str, usize)]| -> BTreeMap<String, usize> {
        pairs
            .iter()
            .map(|(kind, count)| ((*kind).into(), *count))
            .collect()
    };
    let cdn = link("cdn.example.com");
    assert_eq!(
        (cdn.request_count, cdn.request_kinds),
        (2, kinds(&[("script", 1), ("static", 1)]))
    );
    let api = link("api.example.com");
    assert_eq!(
        (api.request_count, api.request_kinds),
        (3, kinds(&[("api", 3)]))
    );
    assert_eq!(
        link("login.example.com").request_kinds,
        kinds(&[("navigation", 1)])
    );
}

// A link also counts the rows whose response let its source origin read them,
// judged as a browser judges: one Access-Control-Allow-Origin, compared as
// written, and credentials only with a named origin.
#[test]
fn links_count_rows_whose_response_allowed_the_source_origin() {
    let session = Uuid::from_u128(99);
    let page = "https://www.example.com";
    let long = "x".repeat(crate::service_map::MAX_HEADER_VALUE_BYTES + 1);
    let call = |sequence, response_headers: &[(&str, &str)]| {
        let mut record = with_request_headers(
            filter_fixture(
                "api.example.com",
                "/v1/items",
                200,
                "application/json",
                Some("https://www.example.com/"),
                sequence,
            ),
            &[("Origin", page), ("Sec-Fetch-Dest", "empty")],
        );
        for (name, value) in response_headers {
            record
                .response
                .as_mut()
                .unwrap()
                .headers
                .push(HeaderRecord {
                    name: (*name).into(),
                    value: (*value).into(),
                });
        }
        record
    };
    let store = TransactionStore::from_records(vec![
        call(
            1,
            &[
                ("Access-Control-Allow-Origin", page),
                ("Access-Control-Allow-Credentials", "true"),
            ],
        ),
        call(
            2,
            &[
                ("Access-Control-Allow-Origin", "*"),
                ("Access-Control-Allow-Credentials", "true"),
            ],
        ),
        call(
            3,
            &[("Access-Control-Allow-Origin", "https://other.example.com")],
        ),
        call(
            4,
            &[
                ("Access-Control-Allow-Origin", page),
                ("Access-Control-Allow-Origin", "*"),
            ],
        ),
        call(
            5,
            &[("Access-Control-Allow-Origin", "https://WWW.example.com:443")],
        ),
        call(6, &[]),
        // A long policy hides no second Access-Control-Allow-Origin; an unread
        // one may be one.
        call(
            7,
            &[
                ("Access-Control-Allow-Origin", page),
                ("Content-Security-Policy", long.as_str()),
            ],
        ),
        call(
            8,
            &[
                ("Access-Control-Allow-Origin", page),
                ("Access-Control-Allow-Origin", long.as_str()),
            ],
        ),
    ]);
    let (snapshot, _) = store.service_map_snapshot_blocking_for_catalog(
        session,
        DEFAULT_MAX_RECORDS,
        technology::CatalogVersion::V1,
        &crate::store::ListFilters::default(),
    );
    let map = build_bounded(
        session,
        snapshot,
        DEFAULT_MAX_RECORDS,
        false,
        None,
        &[],
        &[],
    )
    .unwrap();
    let api = map
        .origins
        .iter()
        .find(|origin| origin.origin == "https://api.example.com")
        .unwrap();
    assert_eq!(api.header_links.len(), 2, "Origin and Referer");
    for link in &api.header_links {
        assert_eq!(
            (
                link.request_count,
                link.cors_allowed_count,
                link.cors_credentials_count
            ),
            (8, 3, 1),
            "{}: the named origin and * allow, two values or another spelling do not",
            link.relationship
        );
    }
    // Each row names the page in both headers: eight requests, not sixteen.
    assert_eq!(api.header_sources.len(), 1);
    let source = &api.header_sources[0];
    assert_eq!(source.source_origin, page);
    assert_eq!(
        (
            source.request_count,
            source.request_kinds.values().sum::<usize>(),
            source.cors_allowed_count,
            source.cors_credentials_count
        ),
        (8, 8, 3, 1)
    );
}

// Bundles, pages and asset URLs name front-end technologies; the map gives an
// asset's to the page that loaded it, to the asset's own origin when no page did,
// and keeps a page's with the page.
#[test]
fn front_technologies_go_to_the_page_that_loaded_the_asset() {
    let session = Uuid::from_u128(100);
    let asset =
        |host: &str, path: &str, kind: &str, referer: Option<&str>, body: &str, sequence| {
            let mut record = filter_fixture(host, path, 200, kind, referer, sequence);
            record.response.as_mut().unwrap().body_preview = body.into();
            record
        };
    let next = "/_next/static/chunks/main-app.js";
    let js = "application/javascript";
    let store = TransactionStore::from_records(vec![
        filter_fixture("www.example.com", "/", 200, "text/html", None, 1),
        asset(
            "cdn.example.com",
            next,
            js,
            Some("https://www.example.com/"),
            r#"n()}window.next={version:"14.2.3",appDir:!0}"#,
            2,
        ),
        asset(
            "cdn.example.com",
            next,
            js,
            Some("https://www.example.com/shop"),
            r#"window.next={version:"14.2.3",appDir:!0}"#,
            3,
        ),
        asset(
            "api.example.com",
            next,
            js,
            None,
            r#"let s="13.4.7";window.next={version:s,router:r}"#,
            4,
        ),
        // Its URL alone says Next.js built it; its body names no version.
        asset("img.example.com", next, js, None, "console.log(1)", 5),
        // A stylesheet is read by its URL only.
        asset(
            "cdn.example.com",
            "/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css",
            "text/css",
            Some("https://www.example.com/"),
            "",
            6,
        ),
        // A page's markup and generator stay with the page, whatever its Referer.
        asset(
            "blog.example.com",
            "/",
            "text/html",
            Some("https://www.example.com/"),
            r#"<meta name="generator" content="WordPress 6.5.2"><div data-v-1a2b3c4d>"#,
            7,
        ),
    ]);
    let (snapshot, _) = store.service_map_snapshot_blocking_for_catalog(
        session,
        DEFAULT_MAX_RECORDS,
        technology::CatalogVersion::V1,
        &crate::store::ListFilters::default(),
    );
    let map = build_bounded(
        session,
        snapshot,
        DEFAULT_MAX_RECORDS,
        false,
        None,
        &[],
        &[],
    )
    .unwrap();
    let found = |host: &str| {
        map.origins
            .iter()
            .find(|origin| origin.origin == format!("https://{host}"))
            .unwrap()
            .front_technologies
            .iter()
            .map(|item| {
                (
                    item.product_id.clone(),
                    item.version.clone(),
                    item.source_origin
                        .trim_start_matches("https://")
                        .to_string(),
                    item.row_count,
                )
            })
            .collect::<Vec<_>>()
    };
    let one = |id: &str, version: Option<&str>, source: &str, rows| {
        (
            id.to_string(),
            version.map(str::to_string),
            source.to_string(),
            rows,
        )
    };
    assert_eq!(
        found("www.example.com"),
        [
            one("next_js", Some("14.2.3"), "cdn.example.com", 2),
            one("bootstrap", Some("5.3.2"), "cdn.example.com", 1),
        ],
        "each bundle counts once though its URL and body both name Next.js"
    );
    assert!(
        found("cdn.example.com").is_empty(),
        "the CDN only served them"
    );
    assert_eq!(
        found("api.example.com"),
        [one("next_js", Some("13.4.7"), "api.example.com", 1)]
    );
    assert_eq!(
        found("img.example.com"),
        [one("next_js", None, "img.example.com", 1)]
    );
    assert_eq!(
        found("blog.example.com"),
        [
            one("wordpress", Some("6.5.2"), "blog.example.com", 1),
            one("vue", None, "blog.example.com", 1),
        ],
        "a CMS leads a framework"
    );
    // A one-origin or in-scope map leaves the CDN out, but not what the page
    // took from it.
    let whole = |map: &ServiceMap| {
        let www = map
            .origins
            .iter()
            .find(|origin| origin.origin == "https://www.example.com")
            .unwrap();
        serde_json::to_value(&www.front_technologies).unwrap()
    };
    for (in_scope_only, origin_filter, include) in [
        (false, Some("https://www.example.com".to_string()), vec![]),
        (true, None, vec!["www.example.com".to_string()]),
    ] {
        let (snapshot, _) = store.service_map_snapshot_blocking_for_catalog(
            session,
            DEFAULT_MAX_RECORDS,
            technology::CatalogVersion::V1,
            &crate::store::ListFilters::default(),
        );
        let narrow = build_bounded(
            session,
            snapshot,
            DEFAULT_MAX_RECORDS,
            in_scope_only,
            origin_filter,
            &include,
            &[],
        )
        .unwrap();
        assert_eq!(narrow.origins.len(), 1);
        assert_eq!(whole(&narrow), whole(&map), "{include:?}");
    }
}

// A page may load one library from several origins. Each source button must
// keep the origin that actually served its evidence, even for the same version.
#[test]
fn front_technologies_keep_evidence_with_each_source_origin() {
    let session = Uuid::from_u128(102);
    let mut records = vec![filter_fixture(
        "www.example.com",
        "/",
        200,
        "text/html",
        None,
        1,
    )];
    for (sequence, host) in [
        (2, "cdn-a.example.com"),
        (3, "cdn-b.example.com"),
        (4, "cdn-a.example.com"),
    ] {
        let mut record = filter_fixture(
            host,
            "/_next/static/chunks/main-app.js",
            200,
            "application/javascript",
            Some("https://www.example.com/"),
            sequence,
        );
        record.response.as_mut().unwrap().body_preview =
            r#"window.next={version:"14.2.3",appDir:!0}"#.into();
        records.push(record);
    }
    let store = TransactionStore::from_records(records);
    let filters = crate::store::ListFilters::default();
    for catalog in [
        technology::CatalogVersion::V1,
        technology::CatalogVersion::V2,
    ] {
        let (snapshot, _) = store.service_map_snapshot_blocking_for_catalog(
            session,
            DEFAULT_MAX_RECORDS,
            catalog,
            &filters,
        );
        let evidence_origins: BTreeMap<_, _> = snapshot
            .rows
            .iter()
            .map(|row| (row.evidence_id.clone(), row.origin.clone()))
            .collect();
        let bounded = build_bounded(
            session,
            snapshot,
            DEFAULT_MAX_RECORDS,
            false,
            None,
            &[],
            &[],
        )
        .unwrap();
        let (all, _) = store
            .service_map_all_rows_blocking(session, catalog, &filters, false, None, &[], &[])
            .unwrap();
        for map in [bounded, all] {
            let page = map
                .origins
                .iter()
                .find(|origin| origin.origin == "https://www.example.com")
                .unwrap();
            let found = &page.front_technologies;
            assert_eq!(found.len(), 2, "one source group per CDN");
            for (item, (host, count)) in found.iter().zip([
                ("https://cdn-a.example.com", 2),
                ("https://cdn-b.example.com", 1),
            ]) {
                assert_eq!(item.product_id, "next_js");
                assert_eq!(item.version.as_deref(), Some("14.2.3"));
                assert_eq!(item.source_origin, host);
                assert_eq!(item.row_count, count);
                assert_eq!(item.evidence.len(), count);
                for evidence in &item.evidence {
                    assert_eq!(
                        evidence_origins[evidence], item.source_origin,
                        "View source must select the evidence's own origin"
                    );
                }
            }
        }
    }
}

#[test]
fn front_technology_source_groups_keep_the_origin_output_bound() {
    let session = Uuid::from_u128(103);
    let mut records = vec![filter_fixture(
        "www.example.com",
        "/",
        200,
        "text/html",
        None,
        1,
    )];
    for index in 0..=MAX_FRONT_TECHNOLOGIES_PER_ORIGIN {
        records.push(filter_fixture(
            &format!("cdn-{index:02}.example.com"),
            "/_next/static/chunks/main-app.js",
            200,
            "application/javascript",
            Some("https://www.example.com/"),
            index as u64 + 2,
        ));
    }
    let store = TransactionStore::from_records(records);
    let (map, _) = store
        .service_map_all_rows_blocking(
            session,
            technology::CatalogVersion::V1,
            &crate::store::ListFilters::default(),
            false,
            None,
            &[],
            &[],
        )
        .unwrap();
    let page = map
        .origins
        .iter()
        .find(|origin| origin.origin == "https://www.example.com")
        .unwrap();
    assert_eq!(
        page.front_technologies.len(),
        MAX_FRONT_TECHNOLOGIES_PER_ORIGIN
    );
    assert!(!map.snapshot.complete);
    assert!(map
        .snapshot
        .stopped_by
        .contains(&"front_technologies_limit".into()));
    for (index, item) in page.front_technologies.iter().enumerate() {
        assert_eq!(
            item.source_origin,
            format!("https://cdn-{index:02}.example.com")
        );
        assert_eq!(item.row_count, 1);
        assert_eq!(item.evidence.len(), 1);
    }
}

// The UI's whole-history map folds every retained row, newest first, keeping
// none: where the windowed map holds every row it is the same map, and past
// the window's row and byte caps every row still counts. The window held only
// 6,202 of these rows before its 8 MiB projection cap stopped it.
#[test]
fn whole_history_map_matches_the_window_and_reads_past_it() {
    let session = Uuid::from_u128(101);
    let store = |rows: u64| {
        TransactionStore::from_records(
            (1..=rows)
                .rev()
                .map(|i| fixture_record(&format!("h{}.example.com", i % 7), i))
                .collect(),
        )
    };
    let filters = crate::store::ListFilters::default();
    let all_rows = |store: &TransactionStore| {
        store
            .service_map_all_rows_blocking(
                session,
                technology::CatalogVersion::V2,
                &filters,
                false,
                None,
                &[],
                &[],
            )
            .unwrap()
    };
    let small = store(3_000);
    let (snapshot, _) = small.service_map_snapshot_blocking_for_catalog(
        session,
        3_000,
        technology::CatalogVersion::V2,
        &filters,
    );
    assert!(snapshot.stopped_by.is_empty());
    let windowed = build_bounded(session, snapshot, 3_000, false, None, &[], &[]).unwrap();
    let (mut all, complete) = all_rows(&small);
    assert!(complete, "no script or page body was left to read");
    all.snapshot.captured_at = windowed.snapshot.captured_at;
    same_output(windowed, all);

    let large = store(12_000);
    let (snapshot, _) = large.service_map_snapshot_blocking_for_catalog(
        session,
        DEFAULT_MAX_RECORDS,
        technology::CatalogVersion::V2,
        &filters,
    );
    assert!(snapshot.stopped_by.contains("metadata_bytes"));
    let (all, _) = all_rows(&large);
    assert_eq!(
        (all.snapshot.considered_rows, all.snapshot.included_rows),
        (12_000, 12_000)
    );
    assert!(all.snapshot.complete, "{:?}", all.snapshot.stopped_by);
}

// The whole-history cache serves an unchanged history, or a recent map unless
// a fresh one is asked for, whatever changed since.
#[test]
fn whole_history_cache_serves_an_unchanged_or_recent_map() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let store = TransactionStore::from_records(vec![
        fixture_record("a.example.com", 2),
        fixture_record("b.example.com", 1),
    ]);
    let cache = |cost: u64, complete: bool| {
        store.store_service_map(
            "key".into(),
            store.service_map_history_token(),
            std::time::Duration::from_secs(cost),
            complete,
            bytes::Bytes::from_static(b"{}"),
        )
    };
    cache(0, true);
    let unchanged = store.service_map_history_token();
    assert!(store.cached_service_map("key", true).is_some(), "unchanged");
    assert!(store.cached_service_map("other", false).is_none());
    cache(0, false);
    assert!(
        store.cached_service_map("key", true).is_none(),
        "bodies left to read"
    );

    cache(60, true);
    runtime.block_on(store.insert(fixture_record("c.example.com", 3)));
    let appended = store.service_map_history_token();
    assert_ne!(appended, unchanged, "an append changes the history");
    runtime.block_on(store.update_record(Uuid::from_u128(2), |record| record.status = Some(204)));
    assert_ne!(
        store.service_map_history_token(),
        appended,
        "so does an update"
    );
    assert!(
        store.cached_service_map("key", false).is_some(),
        "a recent map serves a poll"
    );
    assert!(
        store.cached_service_map("key", true).is_none(),
        "a fresh read rebuilds"
    );
}

// A client lists the addresses it connected to the proxy from, at most eight;
// a row from before addresses were kept adds none.
#[test]
fn clients_name_the_addresses_they_connected_from() {
    let session = Uuid::from_u128(110);
    let chrome = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36";
    let row = |user_agent: &str, address: Option<&str>, sequence| {
        let mut record = filter_fixture("www.example.com", "/", 200, "text/html", None, sequence);
        let mut request = http::HeaderMap::new();
        request.insert(http::header::USER_AGENT, user_agent.parse().unwrap());
        record.request = MessageRecord::from_headers_and_body(&request, b"", 0);
        record.client_address = address.map(|value| value.parse().unwrap());
        record
    };
    let mut records = vec![
        row(chrome, Some("127.0.0.1"), 1),
        row(chrome, Some("192.168.0.12"), 2),
        row(chrome, Some("127.0.0.1"), 3),
        row(chrome, None, 4),
    ];
    records.extend((0..10).map(|index| {
        row(
            "okhttp/4.12.0",
            Some(&format!("192.168.0.{}", 30 + index)),
            10 + index,
        )
    }));
    let store = TransactionStore::from_records(records);
    let (map, _) = store
        .service_map_all_rows_blocking(
            session,
            technology::CatalogVersion::V2,
            &crate::store::ListFilters::default(),
            false,
            None,
            &[],
            &[],
        )
        .unwrap();
    let addresses = |name: &str| {
        map.clients
            .iter()
            .find(|client| client.name == name)
            .unwrap()
            .addresses
            .clone()
    };
    assert_eq!(addresses("Chrome"), ["127.0.0.1", "192.168.0.12"]);
    assert_eq!(addresses("OkHttp").len(), 8, "at most eight");
}

// Each row's User-Agent names its client; the map counts its rows per origin,
// and apart those it sent itself, with no Origin or Referer.
#[test]
fn clients_count_their_rows_and_their_own_visits() {
    let session = Uuid::from_u128(103);
    let chrome = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36";
    let row =
        |host: &str, kind: &str, user_agent: Option<&str>, referer: Option<&str>, sequence| {
            let mut record = filter_fixture(host, "/", 200, kind, None, sequence);
            let mut request = http::HeaderMap::new();
            if let Some(value) = user_agent {
                request.insert(http::header::USER_AGENT, value.parse().unwrap());
            }
            if let Some(value) = referer {
                request.insert(http::header::REFERER, value.parse().unwrap());
            }
            record.request = MessageRecord::from_headers_and_body(&request, b"", 0);
            record
        };
    let store = TransactionStore::from_records(vec![
        row("www.example.com", "text/html", Some(chrome), None, 1),
        row(
            "api.example.com",
            "application/json",
            Some(chrome),
            Some("https://www.example.com/"),
            2,
        ),
        row(
            "api.example.com",
            "application/json",
            Some(chrome),
            Some("https://www.example.com/"),
            3,
        ),
        row(
            "api.example.com",
            "application/json",
            Some("okhttp/4.12.0"),
            None,
            4,
        ),
        row("api.example.com", "application/json", None, None, 5),
        // The same browser a version older is the same client.
        row(
            "www.example.com",
            "text/html",
            Some(&chrome.replace("Chrome/141", "Chrome/140")),
            None,
            6,
        ),
    ]);
    let (snapshot, _) = store.service_map_snapshot_blocking_for_catalog(
        session,
        DEFAULT_MAX_RECORDS,
        technology::CatalogVersion::V2,
        &crate::store::ListFilters::default(),
    );
    let map = build_bounded(
        session,
        snapshot,
        DEFAULT_MAX_RECORDS,
        false,
        None,
        &[],
        &[],
    )
    .unwrap();
    let clients: Vec<_> = map
        .clients
        .iter()
        .map(|client| {
            (
                client.name.as_str(),
                client.versions.clone(),
                client.os.as_deref(),
                client.request_count,
                client
                    .origins
                    .iter()
                    .map(|origin| {
                        (
                            origin.origin.trim_start_matches("https://"),
                            origin.request_count,
                            origin.entry_kinds.clone().into_iter().collect::<Vec<_>>(),
                        )
                    })
                    .collect::<Vec<_>>(),
            )
        })
        .collect();
    let kinds = |kind: &str, rows| vec![(kind.to_string(), rows)];
    assert_eq!(
        clients,
        [
            (
                "Chrome",
                vec![141, 140],
                Some("macOS"),
                4,
                vec![
                    ("api.example.com", 2, vec![]),
                    ("www.example.com", 2, kinds("navigation", 2)),
                ]
            ),
            (
                "OkHttp",
                vec![4],
                None,
                1,
                vec![("api.example.com", 1, kinds("api", 1))]
            ),
            (
                "No User-Agent",
                vec![],
                None,
                1,
                vec![("api.example.com", 1, kinds("api", 1))]
            ),
        ],
        "a page's calls are not the browser's own visits; an app's are"
    );
    assert!(map.snapshot.complete);
}

// What a response's own headers, cookies and error body say about its servers
// stays with the origin that responded, even when a page's Referer loaded it.
#[test]
fn server_technologies_stay_with_the_origin_that_responded() {
    let session = Uuid::from_u128(104);
    let response =
        |host: &str, status, kind: &str, headers: &[(&str, &str)], body: &str, sequence| {
            let mut record = filter_fixture(
                host,
                "/v1/items",
                status,
                kind,
                Some("https://www.example.com/"),
                sequence,
            );
            let mut map = http::HeaderMap::new();
            map.insert(http::header::CONTENT_TYPE, kind.parse().unwrap());
            for (name, value) in headers {
                map.append(
                    http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                    value.parse().unwrap(),
                );
            }
            record.response = Some(MessageRecord::from_headers_and_body(
                &map,
                body.as_bytes(),
                1024,
            ));
            record
        };
    let store = TransactionStore::from_records(vec![
        filter_fixture("www.example.com", "/", 200, "text/html", None, 1),
        response(
            "api.example.com",
            404,
            "application/json",
            &[("CF-RAY", "8d2c1e9a7b3f1a2b-ICN"), ("Set-Cookie", "JSESSIONID=abc; Path=/"), ("Set-Cookie", "BIGipServerpool=1677787402.20480.0000; path=/")],
            r#"{"timestamp":"2026-10-16T09:00:00.000+00:00","status":404,"error":"Not Found","path":"/v1/items"}"#,
            2,
        ),
        response(
            "api.example.com",
            500,
            "text/html",
            &[],
            "<pre>\tat org.springframework.web.servlet.DispatcherServlet.doDispatch(DispatcherServlet.java:1089)</pre>",
            3,
        ),
    ]);
    let (snapshot, _) = store.service_map_snapshot_blocking_for_catalog(
        session,
        DEFAULT_MAX_RECORDS,
        technology::CatalogVersion::V2,
        &crate::store::ListFilters::default(),
    );
    let map = build_bounded(
        session,
        snapshot,
        DEFAULT_MAX_RECORDS,
        false,
        None,
        &[],
        &[],
    )
    .unwrap();
    let origin = |host: &str| {
        map.origins
            .iter()
            .find(|origin| origin.origin == format!("https://{host}"))
            .unwrap()
    };
    let servers: Vec<_> = origin("api.example.com")
        .server_technologies
        .iter()
        .map(|item| {
            (
                item.product_id.as_str(),
                item.category.as_str(),
                item.signals.join("+"),
                item.row_count,
            )
        })
        .collect();
    assert_eq!(
        servers,
        [
            ("backend_address", "exposure", "cookie".to_string(), 1),
            ("java_stack_trace", "exposure", "body".to_string(), 1),
            ("cloudflare", "edge", "header".to_string(), 1),
            ("f5_big_ip", "gateway", "cookie".to_string(), 1),
            ("java_servlet", "app_server", "cookie".to_string(), 1),
            ("spring_boot", "backend", "body".to_string(), 1),
            ("java", "language", "body".to_string(), 1),
        ],
        "exposures first, then outermost layer to innermost"
    );
    let www = origin("www.example.com");
    assert!(
        www.server_technologies.is_empty() && www.front_technologies.is_empty(),
        "the page only loaded them"
    );
}

// An origin keeps its newest icon even when the display filter hides `ico` and
// `png` rows, as it does by default. Only a GET answered 200 with a raster
// image at an icon path counts, and only bytes that are an image are served.
#[test]
fn origins_keep_their_newest_icon_whatever_the_display_filter_hides() {
    use crate::store::ListFilters;
    let session = Uuid::from_u128(105);
    let png: &[u8] = b"\x89PNG\r\n\x1a\nIHDR";
    let icon = |host: &str, path: &str, status, kind: &str, body: &[u8], sequence| {
        let mut record = filter_fixture(host, path, status, kind, None, sequence);
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::CONTENT_TYPE, kind.parse().unwrap());
        record.response = Some(MessageRecord::from_headers_and_body(&headers, body, 1024));
        record
    };
    // Newest first, as `from_records` takes them.
    let store = TransactionStore::from_records(vec![
        filter_fixture("www.example.com", "/", 200, "text/html", None, 1),
        icon(
            "www.example.com",
            "/static/Favicon-32x32.png",
            200,
            "image/png",
            png,
            2,
        ),
        icon(
            "www.example.com",
            "/favicon.ico",
            200,
            "image/x-icon",
            png,
            3,
        ),
        filter_fixture(
            "api.example.com",
            "/v1/items",
            200,
            "application/json",
            None,
            4,
        ),
        icon(
            "api.example.com",
            "/favicon.ico",
            404,
            "image/x-icon",
            png,
            5,
        ),
        icon(
            "api.example.com",
            "/favicon.svg",
            200,
            "image/svg+xml",
            b"<svg/>",
            6,
        ),
        icon("api.example.com", "/logo.png", 200, "image/png", png, 7),
        icon(
            "api.example.com",
            "/favicon.ico",
            200,
            "text/html",
            b"<html>",
            8,
        ),
        filter_fixture(
            "cdn.example.com",
            "/app.js",
            200,
            "text/javascript",
            None,
            9,
        ),
        icon(
            "cdn.example.com",
            "/apple-touch-icon.png",
            200,
            "image/png",
            b"<html>no</html>",
            10,
        ),
    ]);
    let hidden = ListFilters {
        hidden_extensions: vec!["ico".into(), "png".into()],
        ..ListFilters::default()
    };
    let (snapshot, _) = store.service_map_snapshot_blocking_for_catalog(
        session,
        DEFAULT_MAX_RECORDS,
        technology::CatalogVersion::V2,
        &hidden,
    );
    let windowed = build_bounded(
        session,
        snapshot,
        DEFAULT_MAX_RECORDS,
        false,
        None,
        &[],
        &[],
    )
    .unwrap();
    let (all, _) = store
        .service_map_all_rows_blocking(
            session,
            technology::CatalogVersion::V2,
            &hidden,
            false,
            None,
            &[],
            &[],
        )
        .unwrap();
    for map in [&windowed, &all] {
        let favicon = |host: &str| {
            map.origins
                .iter()
                .find(|origin| origin.origin == format!("https://{host}"))
                .unwrap()
                .favicon
                .clone()
        };
        // The evidence ends with the row's record ID: the fixture's sequence + 1.
        let row = |token: Option<String>| {
            token.map(|token| token.rsplit('.').next().unwrap().parse::<Uuid>().unwrap())
        };
        assert_eq!(
            row(favicon("www.example.com")),
            Some(Uuid::from_u128(3)),
            "the newest icon"
        );
        assert_eq!(
            favicon("api.example.com"),
            None,
            "a failure, an SVG, a logo and a page"
        );
        assert_eq!(row(favicon("cdn.example.com")), Some(Uuid::from_u128(11)));
        assert!(
            map.origins.iter().all(|origin| origin
                .endpoints
                .iter()
                .all(
                    |endpoint| !endpoint.path.ends_with(".ico") && !endpoint.path.ends_with(".png")
                )),
            "the icon rows themselves stay filtered out"
        );
    }

    let runtime = tokio::runtime::Runtime::new().unwrap();
    let origin = |host: &str| {
        all.origins
            .iter()
            .find(|origin| origin.origin == format!("https://{host}"))
            .unwrap()
    };
    let token = origin("www.example.com").favicon.clone().unwrap();
    assert_eq!(
        runtime.block_on(store.service_map_favicon(session, &token)),
        Some(("image/png", png.to_vec()))
    );
    assert_eq!(
        runtime.block_on(store.service_map_favicon(Uuid::from_u128(1), &token)),
        None,
        "another session"
    );
    let cdn = origin("cdn.example.com").favicon.clone().unwrap();
    assert_eq!(
        runtime.block_on(store.service_map_favicon(session, &cdn)),
        None,
        "bytes that are not an image are not served, whatever the header says"
    );
    let page = origin("www.example.com").endpoints[0].evidence[0].clone();
    assert_eq!(
        runtime.block_on(store.service_map_favicon(session, &page)),
        None,
        "a page row"
    );
    assert_eq!(
        favicon_type(b"\x00\x00\x01\x00\x01\x00"),
        Some("image/x-icon")
    );
    assert_eq!(
        favicon_type(b"RIFF\x00\x00\x00\x00WEBPVP8 "),
        Some("image/webp")
    );
    assert_eq!(
        favicon_type(b"<svg xmlns=\"http://www.w3.org/2000/svg\"/>"),
        None
    );
    assert_eq!(favicon_type(&vec![0x89; MAX_FAVICON_BYTES + 1]), None);
}

// An origin lists how its requests authenticate, busiest first, and each
// endpoint the kinds its own rows showed. No credential value leaves.
#[test]
fn origins_and_endpoints_name_how_their_requests_authenticate() {
    use crate::store::ListFilters;
    let session = Uuid::from_u128(106);
    // Split so secret scanning does not take a test sample for a leaked token.
    let bearer = concat!(
        "Bearer eyJhbGciOiJIUzI1NiJ9.",
        "eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    );
    let request = |path: &str, headers: &[(&str, &str)], sequence| {
        let mut record = filter_fixture(
            "api.example.com",
            path,
            200,
            "application/json",
            None,
            sequence,
        );
        let mut map = http::HeaderMap::new();
        for (name, value) in headers {
            map.append(
                http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                value.parse().unwrap(),
            );
        }
        record.request = MessageRecord::from_headers_and_body(&map, b"", 0);
        record
    };
    let store = TransactionStore::from_records(vec![
        request(
            "/v1/items",
            &[
                ("Authorization", bearer),
                ("Cookie", "JSESSIONID=SYNTHETIC_VALUE"),
            ],
            3,
        ),
        request("/v1/items", &[("Authorization", bearer)], 2),
        request("/v1/public", &[], 1),
    ]);
    let (all, _) = store
        .service_map_all_rows_blocking(
            session,
            technology::CatalogVersion::V2,
            &ListFilters::default(),
            false,
            None,
            &[],
            &[],
        )
        .unwrap();
    let origin = &all.origins[0];
    let methods: Vec<_> = origin
        .auth
        .iter()
        .map(|method| {
            (
                method.kind.as_str(),
                method.name.as_deref(),
                method.row_count,
            )
        })
        .collect();
    assert_eq!(
        methods,
        [
            ("bearer_jwt", None, 2),
            ("session_cookie", Some("JSESSIONID"), 1)
        ]
    );
    let endpoint = |path: &str| {
        origin
            .endpoints
            .iter()
            .find(|endpoint| endpoint.path == path)
            .unwrap()
            .auth
            .clone()
    };
    assert_eq!(endpoint("/v1/items"), ["bearer_jwt", "session_cookie"]);
    assert!(endpoint("/v1/public").is_empty());
    let text = serde_json::to_string(&all).unwrap();
    assert!(
        !text.contains("SYNTHETIC_VALUE") && !text.contains("eyJzdWIi"),
        "no credential value leaves"
    );
}

// A one-origin map spends its body reads on that origin: three hundred newer
// pages of other origins no longer use the budget up before its own page.
#[test]
fn a_one_origin_map_reads_its_own_pages() {
    use crate::store::ListFilters;
    let session = Uuid::from_u128(107);
    let page = |host: &str, sequence| {
        let mut record = filter_fixture(host, "/", 200, "text/html", None, sequence);
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::CONTENT_TYPE, "text/html".parse().unwrap());
        record.response = Some(MessageRecord::from_headers_and_body(
            &headers,
            br#"<meta name="generator" content="WordPress 6.5.2">"#,
            1024,
        ));
        record
    };
    // Newest first: the page asked about is the oldest.
    let mut records: Vec<_> = (0..300)
        .map(|i| page(&format!("p{i}.example.com"), 1_000 - i))
        .collect();
    records.push(page("www.example.com", 1));
    let store = TransactionStore::from_records(records);
    let (map, _) = store
        .service_map_all_rows_blocking(
            session,
            technology::CatalogVersion::V2,
            &ListFilters::default(),
            false,
            Some("https://www.example.com".into()),
            &[],
            &[],
        )
        .unwrap();
    assert_eq!(map.origins.len(), 1);
    assert!(
        map.origins[0]
            .front_technologies
            .iter()
            .any(|item| item.product_id == "wordpress"),
        "{:?}",
        map.origins[0].front_technologies
    );
}

// A one-origin or in-scope map over the whole history leaves a CDN out but
// keeps the jQuery the asked origin's page took from it, and a one-origin map
// spends no reads on the scripts other pages loaded.
#[test]
fn a_narrow_map_keeps_what_its_pages_loaded_from_elsewhere() {
    use crate::store::ListFilters;
    let session = Uuid::from_u128(108);
    let script = |path: &str, referer: &str, sequence| {
        let mut record = filter_fixture(
            "cdn.example.com",
            path,
            200,
            "application/javascript",
            Some(referer),
            sequence,
        );
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            "application/javascript".parse().unwrap(),
        );
        record.response = Some(MessageRecord::from_headers_and_body(
            &headers,
            b"/*! jQuery v3.7.1 | (c) OpenJS Foundation */",
            1024,
        ));
        record
    };
    let store = |others: u64| {
        // Newest first: other pages' scripts come before www's.
        let mut records: Vec<_> = (0..others)
            .map(|i| {
                script(
                    &format!("/js/{i}/jquery.min.js"),
                    &format!("https://p{i}.example.com/"),
                    1_000 - i,
                )
            })
            .collect();
        records.push(script("/js/jquery.min.js", "https://www.example.com/", 2));
        records.push(filter_fixture(
            "www.example.com",
            "/",
            200,
            "text/html",
            None,
            1,
        ));
        TransactionStore::from_records(records)
    };
    for (others, in_scope_only, only, include) in [
        (
            300,
            false,
            Some("https://www.example.com".to_string()),
            vec![],
        ),
        (300, true, None, vec!["www.example.com".to_string()]),
    ] {
        let (map, _) = store(others)
            .service_map_all_rows_blocking(
                session,
                technology::CatalogVersion::V2,
                &ListFilters::default(),
                in_scope_only,
                only,
                &include,
                &[],
            )
            .unwrap();
        assert_eq!(map.origins.len(), 1);
        assert_eq!(
            map.origins[0]
                .front_technologies
                .iter()
                .map(|item| (
                    item.product_id.as_str(),
                    item.version.as_deref(),
                    item.source_origin.as_str()
                ))
                .collect::<Vec<_>>(),
            [("jquery", Some("3.7.1"), "https://cdn.example.com")],
            "{include:?}"
        );
    }
}

// What no rule names is kept for a reader to judge: a banner, a header name, a
// cookie name. A named header, a standard one, and a Via value are not.
#[test]
fn an_origin_lists_what_no_rule_names() {
    use crate::store::ListFilters;
    let session = Uuid::from_u128(112);
    let row = |pairs: &[(&str, &str)], sequence| {
        let mut record = filter_fixture("www.example.com", "/", 200, "text/html", None, sequence);
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::CONTENT_TYPE, "text/html".parse().unwrap());
        for (name, value) in pairs {
            headers.append(
                http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                value.parse().unwrap(),
            );
        }
        record.response = Some(MessageRecord::from_headers_and_body(&headers, b"", 0));
        record
    };
    let store = TransactionStore::from_records(vec![
        row(
            &[
                ("Server", "HeRay"),
                ("heray-cache-status", "HIT"),
                ("x-request-id", "1"),
                // Any cache or tracer sends these; they name no server.
                ("X-Cache", "HIT"),
                (
                    "traceparent",
                    "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
                ),
                ("CF-RAY", "8d2c1e9a7b3f1a2b-ICN"),
                ("Via", "1.1 cache-1.internal.example.com"),
                ("Set-Cookie", "WMONID=abc; Path=/"),
                ("Set-Cookie", "JSESSIONID=ABC123; Path=/"),
            ],
            1,
        ),
        row(
            &[("Server", "nginx/1.25.3"), ("heray-cache-status", "MISS")],
            2,
        ),
    ]);
    let (map, _) = store
        .service_map_all_rows_blocking(
            session,
            technology::CatalogVersion::V2,
            &ListFilters::default(),
            false,
            None,
            &[],
            &[],
        )
        .unwrap();
    let unnamed = &map.origins[0].unnamed;
    let values = |signals: &[UnnamedSignal]| {
        signals
            .iter()
            .map(|signal| (signal.value.clone(), signal.row_count))
            .collect::<Vec<_>>()
    };
    assert_eq!(values(&unnamed.banners), [("server: HeRay".to_string(), 1)]);
    assert_eq!(
        values(&unnamed.headers),
        [("heray-cache-status".to_string(), 2)]
    );
    assert_eq!(values(&unnamed.cookies), [("WMONID".to_string(), 1)]);
    assert!(unnamed.banners[0].evidence.len() == 1);
}

// An API's successful answer is not read, but the same answer to a request a
// tester sent from Replay is, as is what a diagnostic path answers.
#[test]
fn a_replayed_answer_and_a_diagnostic_path_are_read() {
    use crate::store::ListFilters;
    let session = Uuid::from_u128(111);
    let answer = |host: &str, path: &str, kind: &str, body: &[u8], replayed: bool, sequence| {
        let mut record = filter_fixture(host, path, 200, kind, None, sequence);
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::CONTENT_TYPE, kind.parse().unwrap());
        record.response = Some(MessageRecord::from_headers_and_body(&headers, body, 4096));
        if replayed {
            record.notes.push(crate::model::REPLAY_NOTE.to_string());
        }
        record
    };
    let trace =
        br#"{"error":"java.lang.NullPointerException\n\tat org.springframework.web.servlet.DispatcherServlet.doDispatch(DispatcherServlet.java:1089)"}"#;
    let store = TransactionStore::from_records(vec![
        answer(
            "a.example.com",
            "/api/cart",
            "application/json",
            trace,
            false,
            1,
        ),
        answer(
            "b.example.com",
            "/api/cart",
            "application/json",
            trace,
            true,
            2,
        ),
        answer(
            "c.example.com",
            "/.git/config",
            "text/plain",
            b"[core]\n\trepositoryformatversion = 0\n",
            false,
            3,
        ),
    ]);
    let found = |origin: &str| {
        let (map, _) = store
            .service_map_all_rows_blocking(
                session,
                technology::CatalogVersion::V2,
                &ListFilters::default(),
                false,
                Some(origin.into()),
                &[],
                &[],
            )
            .unwrap();
        map.origins[0]
            .server_technologies
            .iter()
            .map(|item| item.product_id.clone())
            .collect::<Vec<_>>()
    };
    assert!(
        !found("https://a.example.com").contains(&"java_stack_trace".to_string()),
        "an API's success is not read"
    );
    assert!(found("https://b.example.com").contains(&"java_stack_trace".to_string()));
    assert!(found("https://c.example.com").contains(&"git_config".to_string()));
}

// A page that is not UTF-8, as many Korean sites still serve in EUC-KR, is
// stored as base64; the map reads it all the same, for ASCII signatures.
#[test]
fn a_page_stored_as_base64_is_read_too() {
    use crate::store::ListFilters;
    let session = Uuid::from_u128(109);
    let mut record = filter_fixture("www.example.com", "/", 200, "text/html", None, 1);
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::CONTENT_TYPE,
        "text/html; charset=euc-kr".parse().unwrap(),
    );
    // "한글" in EUC-KR, which is not UTF-8.
    let body = b"<meta name=\"generator\" content=\"WordPress 6.5.2\"><p>\xc7\xd1\xb1\xdb</p>";
    record.response = Some(MessageRecord::from_headers_and_body(&headers, body, 1024));
    assert_eq!(
        record.response.as_ref().unwrap().body_encoding,
        crate::model::BodyEncoding::Base64
    );
    let store = TransactionStore::from_records(vec![record]);
    let (map, _) = store
        .service_map_all_rows_blocking(
            session,
            technology::CatalogVersion::V2,
            &ListFilters::default(),
            false,
            Some("https://www.example.com".into()),
            &[],
            &[],
        )
        .unwrap();
    assert!(
        map.origins[0]
            .front_technologies
            .iter()
            .any(|item| item.product_id == "wordpress" && item.version.as_deref() == Some("6.5.2")),
        "{:?}",
        map.origins[0].front_technologies
    );
}

#[test]
fn service_map_cache_same_length_bundle_keeps_exact_version() {
    let session = Uuid::from_u128(9876);
    let asset = |version: &str, sequence| {
        let mut record = filter_fixture(
            "www.example.com",
            "/js/vendor.js",
            200,
            "application/javascript",
            None,
            sequence,
        );
        let mut headers = http::HeaderMap::new();
        headers.insert("content-type", "application/javascript".parse().unwrap());
        let body = format!("/*! jQuery v{version} | (c) OpenJS Foundation */");
        record.response = Some(MessageRecord::from_headers_and_body(
            &headers,
            body.as_bytes(),
            1024,
        ));
        record
    };
    let old = asset("3.6.0", 1);
    let new = asset("3.7.1", 2);
    assert_eq!(
        old.response.as_ref().unwrap().body_size,
        new.response.as_ref().unwrap().body_size
    );
    let rt = tokio::runtime::Runtime::new().unwrap();
    let store = TransactionStore::from_records(vec![old]);
    let map = |store: &TransactionStore| {
        store
            .service_map_all_rows_blocking(
                session,
                technology::CatalogVersion::V2,
                &crate::store::ListFilters::default(),
                false,
                None,
                &[],
                &[],
            )
            .unwrap()
            .0
    };
    let first = map(&store);
    assert_eq!(
        first.origins[0].front_technologies[0].version.as_deref(),
        Some("3.6.0")
    );
    let new_id = new.id;
    rt.block_on(store.insert(new));
    let second = map(&store);
    let fresh = TransactionStore::from_records(rt.block_on(store.snapshot(None)));
    let third = map(&fresh);
    assert_eq!(
        second.origins[0].front_technologies.len(),
        third.origins[0].front_technologies.len()
    );
    let entry = second.origins[0]
        .front_technologies
        .iter()
        .find(|technology| {
            technology
                .evidence
                .iter()
                .any(|id| id.ends_with(&new_id.to_string()))
        })
        .unwrap();
    assert_eq!(
        entry.version.as_deref(),
        Some("3.7.1"),
        "evidence for the new bundle must name its actual version"
    );
}

fn cache_body_record(path: &str, mime: &str, body: &str, sequence: u64) -> TransactionRecord {
    let mut record = filter_fixture("www.example.com", path, 200, mime, None, sequence);
    let mut headers = http::HeaderMap::new();
    headers.insert("content-type", mime.parse().unwrap());
    record.response = Some(MessageRecord::from_headers_and_body(
        &headers,
        body.as_bytes(),
        body.len(),
    ));
    record
}

#[test]
fn service_map_cache_separates_body_kind_and_url_suppression() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let session = Uuid::new_v4();
    let store = TransactionStore::from_records(vec![]);
    let scan = |row: TransactionRecord| {
        let id = row.id;
        runtime.block_on(store.insert(row));
        let (snapshot, _) = store.service_map_snapshot_blocking_for_catalog(
            session,
            100,
            technology::CatalogVersion::V2,
            &crate::store::ListFilters::default(),
        );
        snapshot
            .rows
            .into_iter()
            .find(|row| row.record_id == id)
            .unwrap()
            .libraries
    };
    let body = r#"<meta name="generator" content="WordPress 6.5.2">"#;
    assert!(scan(cache_body_record(
        "/content",
        "application/javascript",
        body,
        1
    ))
    .is_empty());
    let page = scan(cache_body_record("/content", "text/html", body, 2));
    assert!(page.iter().any(|item| item.product_id == "wordpress"));

    let body = "/*! jQuery v3.7.1 | (c) OpenJS Foundation */\n//# sourceMappingURL=vendor.js.map";
    let library = scan(cache_body_record(
        "/jquery.min.js",
        "application/javascript",
        body,
        3,
    ));
    assert!(!library.iter().any(|item| item.product_id == "source_map"));
    let bundle = scan(cache_body_record(
        "/vendor.js",
        "application/javascript",
        body,
        4,
    ));
    assert!(bundle.iter().any(|item| item.product_id == "source_map"));
    let library = scan(cache_body_record(
        "/jquery.js",
        "application/javascript",
        body,
        5,
    ));
    assert!(!library.iter().any(|item| item.product_id == "source_map"));
}

#[test]
fn service_map_cache_retained_bundles_keep_each_rows_version() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let session = Uuid::new_v4();
    let dir = std::env::temp_dir().join(format!("sniper-map-cache-retained-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let asset = |version: &str, sequence| {
        cache_body_record(
            "/vendor.js",
            "application/javascript",
            &format!("/*! jQuery v{version} | (c) OpenJS Foundation */"),
            sequence,
        )
    };
    let mut records = vec![asset("3.7.1", 2), asset("3.6.0", 1)];
    records[1].user_note = Some("synthetic note".into());
    let locators =
        crate::session::write_transactions_file_for_test_returning_locators(&dir, &records)
            .unwrap();
    let store = TransactionStore::from_records_with_journal(
        records.clone(),
        dir.join("transactions.journal"),
        None,
    );
    runtime.block_on(store.adopt_written_locators(locators));
    // Warm only the oldest response, then read both persisted bodies.
    let filter = crate::store::ListFilters {
        only_notes: true,
        ..Default::default()
    };
    let (old, _) = store.service_map_snapshot_blocking_for_catalog(
        session,
        100,
        technology::CatalogVersion::V2,
        &filter,
    );
    assert_eq!(old.rows.len(), 1);
    assert_eq!(old.rows[0].libraries[0].version.as_deref(), Some("3.6.0"));
    let (all, _) = store.service_map_snapshot_blocking_for_catalog(
        session,
        100,
        technology::CatalogVersion::V2,
        &crate::store::ListFilters::default(),
    );
    for (id, version) in [(records[0].id, "3.7.1"), (records[1].id, "3.6.0")] {
        let row = all.rows.iter().find(|row| row.record_id == id).unwrap();
        assert_eq!(row.libraries[0].version.as_deref(), Some(version));
    }
    drop(store);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn service_map_cache_duplicate_bodies_converge_within_read_budget() {
    let count = crate::service_map_libraries::MAX_READS + 1;
    let records = (1..=count)
        .map(|i| {
            cache_body_record(
                "/vendor.js",
                "application/javascript",
                "/*! jQuery v3.7.1 | (c) OpenJS Foundation */",
                i as u64,
            )
        })
        .collect();
    let store = TransactionStore::from_records(records);
    let read = || {
        store
            .service_map_all_rows_blocking(
                Uuid::nil(),
                technology::CatalogVersion::V2,
                &crate::store::ListFilters::default(),
                false,
                None,
                &[],
                &[],
            )
            .unwrap()
    };
    let (first, complete) = read();
    assert!(
        !complete,
        "each distinct response must be verified within the read cap"
    );
    assert_eq!(first.origins[0].front_technologies[0].row_count, count - 1);
    let (second, complete) = read();
    assert!(
        complete,
        "row caches let the next map finish the remaining response"
    );
    assert_eq!(second.origins[0].front_technologies[0].row_count, count);
    assert!(read().1, "a fully cached map needs no body reads");
}

#[test]
fn scoped_map_body_budget_skips_excluded_pages() {
    let session = Uuid::from_u128(9877);
    let page = |host: &str, sequence| {
        let mut record = cache_body_record(
            "/",
            "text/html",
            r#"<meta name="generator" content="WordPress 6.5.2">"#,
            sequence,
        );
        record.host = host.into();
        record
    };
    for (include, exclude) in [
        (vec!["www.example.com".to_string()], vec![]),
        (vec![], vec!["p*.example.com".to_string()]),
    ] {
        let mut records: Vec<_> = (0..300)
            .map(|i| page(&format!("p{i}.example.com"), 1000 - i))
            .collect();
        let target = page("www.example.com", 1);
        let id = target.id.to_string();
        records.push(target);
        let store = TransactionStore::from_records(records);
        for _ in 0..3 {
            let (map, complete) = store
                .service_map_all_rows_blocking(
                    session,
                    technology::CatalogVersion::V2,
                    &crate::store::ListFilters::default(),
                    true,
                    None,
                    &include,
                    &exclude,
                )
                .unwrap();
            assert_eq!(map.origins.len(), 1);
            let found = &map.origins[0].front_technologies;
            assert_eq!(found.len(), 1, "excluded pages cannot consume body reads");
            assert_eq!(found[0].product_id, "wordpress");
            assert_eq!(found[0].version.as_deref(), Some("6.5.2"));
            assert_eq!(found[0].row_count, 1);
            assert!(found[0].evidence[0].ends_with(&id));
            assert!(complete);
            assert!(
                map.snapshot.complete,
                "body budget does not change metadata completeness"
            );
            assert_eq!(map.snapshot.considered_rows, 301);
            assert_eq!(map.snapshot.included_rows, 1);
            assert_eq!(map.snapshot.excluded_rows, 300);
            assert_eq!(map.snapshot.omitted_rows, 0);
        }
    }
}

#[test]
fn scoped_map_cdn_bodies_use_captured_page_scope_spelling() {
    for (host, referer) in [
        ("bücher.example.com", "https://xn--bcher-kva.example.com/"),
        ("[2001:0db8::1]:443", "https://[2001:db8::1]/"),
        ("WWW.Example.COM.:443", "https://www.example.com./"),
    ] {
        let page = filter_fixture(host, "/", 200, "text/html", None, 1);
        let mut script = filter_fixture(
            "cdn.example.com",
            "/vendor.js",
            200,
            "application/javascript",
            Some(referer),
            2,
        );
        script.response.as_mut().unwrap().body_preview =
            "/*! jQuery v3.7.1 | (c) OpenJS Foundation */".into();
        let id = script.id.to_string();
        let store = TransactionStore::from_records(vec![script, page]);
        let (map, complete) = store
            .service_map_all_rows_blocking(
                Uuid::nil(),
                technology::CatalogVersion::V2,
                &crate::store::ListFilters::default(),
                true,
                None,
                &[host.into()],
                &[],
            )
            .unwrap();
        assert!(complete);
        assert_eq!(map.origins.len(), 1, "{host}");
        let found = &map.origins[0].front_technologies;
        assert_eq!(found.len(), 1, "{host}");
        assert_eq!(found[0].product_id, "jquery");
        assert_eq!(found[0].version.as_deref(), Some("3.7.1"));
        assert_eq!(found[0].source_origin, "https://cdn.example.com");
        assert!(found[0].evidence[0].ends_with(&id));
    }
}

#[test]
fn scoped_map_cdn_read_budget_converges_without_double_counting() {
    let count = crate::service_map_libraries::MAX_READS + 1;
    let mut records: Vec<_> = (1..=count)
        .map(|i| {
            let mut row = filter_fixture(
                "cdn.example.com",
                "/vendor.js",
                200,
                "application/javascript",
                Some("https://www.example.com/"),
                i as u64 + 1,
            );
            row.response.as_mut().unwrap().body_preview =
                "/*! jQuery v3.7.1 | (c) OpenJS Foundation */".into();
            row
        })
        .collect();
    records.push(filter_fixture(
        "www.example.com",
        "/",
        200,
        "text/html",
        None,
        1,
    ));
    let store = TransactionStore::from_records(records);
    let read = || {
        store
            .service_map_all_rows_blocking(
                Uuid::nil(),
                technology::CatalogVersion::V2,
                &crate::store::ListFilters::default(),
                true,
                None,
                &["www.example.com".into()],
                &[],
            )
            .unwrap()
    };
    let (first, complete) = read();
    assert!(!complete);
    assert!(first.snapshot.complete);
    assert_eq!(first.origins[0].front_technologies[0].row_count, count - 1);
    let (second, complete) = read();
    assert!(complete);
    assert_eq!(second.origins[0].front_technologies[0].row_count, count);
    assert!(read().1);
}

#[test]
fn scoped_map_keeps_the_body_byte_budget() {
    use crate::service_map_libraries::{MAX_BYTES_PER_MAP, MAX_ROW_BYTES};
    let mut body = r#"<meta name="generator" content="WordPress 6.5.2">"#.to_string();
    body.extend(std::iter::repeat_n(' ', MAX_ROW_BYTES - body.len()));
    let count = MAX_BYTES_PER_MAP / MAX_ROW_BYTES + 1;
    let records = (1..=count)
        .map(|i| cache_body_record("/", "text/html", &body, i as u64))
        .collect();
    let store = TransactionStore::from_records(records);
    let read = || {
        store
            .service_map_all_rows_blocking(
                Uuid::nil(),
                technology::CatalogVersion::V2,
                &crate::store::ListFilters::default(),
                true,
                None,
                &["www.example.com".into()],
                &[],
            )
            .unwrap()
    };
    let (first, complete) = read();
    assert!(!complete);
    assert_eq!(first.origins[0].front_technologies[0].row_count, count - 1);
    let (second, complete) = read();
    assert!(complete);
    assert_eq!(second.origins[0].front_technologies[0].row_count, count);
}

#[test]
fn scoped_map_prepass_keeps_scope_work_bounded() {
    let (include, exclude) = expensive_scope();
    let store = TransactionStore::from_records(
        (1..=40)
            .map(|i| fixture_record(&long_host(i), i as u64))
            .collect(),
    );
    assert!(matches!(
        store.service_map_all_rows_blocking(
            Uuid::nil(),
            technology::CatalogVersion::V2,
            &crate::store::ListFilters::default(),
            true,
            None,
            &include,
            &exclude,
        ),
        Err(crate::store::ServiceMapStreamError::ScopeWorkLimit)
    ));
}

#[test]
fn scoped_map_assets_of_filtered_pages_do_not_use_body_reads() {
    let mut records: Vec<_> = (0..300)
        .map(|i| {
            let mut script = filter_fixture(
                "cdn.example.com",
                "/vendor.js",
                200,
                "application/javascript",
                Some("https://ghost.example.com/"),
                1000 - i,
            );
            script.user_note = Some("synthetic note".into());
            script.response.as_mut().unwrap().body_preview =
                "/*! jQuery v3.7.1 | (c) OpenJS Foundation */".into();
            script
        })
        .collect();
    records.push(filter_fixture(
        "ghost.example.com",
        "/",
        200,
        "text/html",
        None,
        2,
    ));
    let mut target = cache_body_record(
        "/",
        "text/html",
        r#"<meta name="generator" content="WordPress 6.5.2">"#,
        1,
    );
    target.user_note = Some("synthetic note".into());
    records.push(target);
    let store = TransactionStore::from_records(records);
    let (map, complete) = store
        .service_map_all_rows_blocking(
            Uuid::nil(),
            technology::CatalogVersion::V2,
            &crate::store::ListFilters {
                only_notes: true,
                ..Default::default()
            },
            true,
            None,
            &["*.example.com".into()],
            &["cdn.example.com".into()],
        )
        .unwrap();
    assert!(complete);
    assert_eq!(map.origins.len(), 1);
    assert_eq!(map.origins[0].front_technologies[0].product_id, "wordpress");
    assert_eq!(map.snapshot.filtered_rows, 1);
    assert_eq!(map.snapshot.excluded_rows, 300);
    assert_eq!(map.snapshot.included_rows, 1);
}

#[test]
fn scoped_map_assets_of_capped_origins_do_not_use_body_reads() {
    let mut records: Vec<_> = (0..300)
        .map(|i| {
            let mut script = filter_fixture(
                "cdn.example.com",
                "/vendor.js",
                200,
                "application/javascript",
                Some("https://omitted.example.com/"),
                10_000 - i,
            );
            script.response.as_mut().unwrap().body_preview =
                "/*! jQuery v3.7.1 | (c) OpenJS Foundation */".into();
            script
        })
        .collect();
    records.extend((0..MAX_ORIGINS - 1).map(|i| {
        filter_fixture(
            &format!("p{i}.example.com"),
            "/",
            200,
            "application/octet-stream",
            None,
            3000 - i as u64,
        )
    }));
    records.push(cache_body_record(
        "/",
        "text/html",
        r#"<meta name="generator" content="WordPress 6.5.2">"#,
        2,
    ));
    records.push(filter_fixture(
        "omitted.example.com",
        "/",
        200,
        "text/html",
        None,
        1,
    ));
    let store = TransactionStore::from_records(records);
    let (map, complete) = store
        .service_map_all_rows_blocking(
            Uuid::nil(),
            technology::CatalogVersion::V2,
            &crate::store::ListFilters::default(),
            true,
            None,
            &["*.example.com".into()],
            &["cdn.example.com".into()],
        )
        .unwrap();
    assert!(complete, "unrepresented pages need no body reads");
    assert_eq!(map.origins.len(), MAX_ORIGINS);
    assert!(map
        .origins
        .iter()
        .all(|origin| origin.origin != "https://omitted.example.com"));
    let target = map
        .origins
        .iter()
        .find(|origin| origin.origin == "https://www.example.com")
        .unwrap();
    assert_eq!(target.front_technologies[0].product_id, "wordpress");
    assert!(
        !map.snapshot.complete,
        "metadata still reports its origin cap"
    );
    assert!(map
        .snapshot
        .stopped_by
        .contains(&"origins_limit".to_string()));
    assert_eq!(map.snapshot.omitted_rows, 1);
}

// The Flow view lists the selected origin's rows and those of the origins it
// links to directly, in order, one phase per page load, repeats folded.
#[test]
fn flow_orders_an_origins_requests_by_page_load_and_folds_repeats() {
    let session = Uuid::from_u128(101);
    let page = "https://www.example.com/";
    let navigate = |host: &str, path: &str, status: u16, sequence: u64| {
        with_request_headers(
            filter_fixture(host, path, status, "text/html", Some(page), sequence),
            &[("Sec-Fetch-Dest", "document")],
        )
    };
    let call = |sequence| {
        with_request_headers(
            filter_fixture(
                "api.example.com",
                "/v1/config",
                200,
                "application/json",
                Some(page),
                sequence,
            ),
            &[
                ("Origin", "https://www.example.com"),
                ("Sec-Fetch-Dest", "empty"),
            ],
        )
    };
    let mut login = navigate("sso.example.com", "/login", 302, 5);
    login.response.as_mut().unwrap().headers.push(HeaderRecord {
        name: "Location".into(),
        value: "https://www.example.com/callback".into(),
    });
    let mut records = vec![
        with_request_headers(
            filter_fixture("www.example.com", "/", 200, "text/html", None, 1),
            &[("Sec-Fetch-Dest", "document")],
        ),
        call(2),
        call(3),
        call(4),
        login,
        navigate("www.example.com", "/callback", 200, 6),
        with_request_headers(
            filter_fixture("other.example.com", "/", 200, "text/html", None, 7),
            &[("Sec-Fetch-Dest", "document")],
        ),
    ];
    // The store takes the newest record first.
    records.reverse();
    let store = TransactionStore::from_records(records);
    let (snapshot, _) = store.service_map_snapshot_blocking_for_catalog(
        session,
        DEFAULT_MAX_RECORDS,
        technology::CatalogVersion::V2,
        &crate::store::ListFilters::default(),
    );
    let flow = crate::service_map_flow::build(
        session,
        snapshot,
        "https://www.example.com",
        false,
        &[],
        &[],
    )
    .unwrap();

    assert_eq!(
        flow.lanes,
        [
            "https://www.example.com",
            "https://api.example.com",
            "https://sso.example.com"
        ]
    );
    assert_eq!((flow.flow_rows, flow.complete), (6, true));
    let pages: Vec<_> = flow
        .phases
        .iter()
        .map(|phase| {
            phase
                .page
                .as_ref()
                .map(|page| format!("{}{}", page.origin, page.path))
        })
        .collect();
    assert_eq!(
        pages,
        [
            Some("https://www.example.com/".to_string()),
            Some("https://sso.example.com/login".to_string()),
            Some("https://www.example.com/callback".to_string()),
        ]
    );
    let first = &flow.phases[0].steps;
    assert_eq!(first.len(), 2, "the three config calls fold into one step");
    assert_eq!(
        (
            first[1].origin.as_str(),
            first[1].path.as_str(),
            first[1].count,
            first[1].request_kind
        ),
        ("https://api.example.com", "/v1/config", 3, "api")
    );
    assert_eq!(first[1].evidence.len(), 2, "the first and the newest row");
    let redirect = flow.phases[1].steps[0].redirect.as_ref().unwrap();
    assert_eq!(
        (redirect.origin.as_str(), redirect.path.as_str()),
        ("https://www.example.com", "/callback")
    );
}
