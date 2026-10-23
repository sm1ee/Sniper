use super::*;
use crate::service_map::{MetadataSnapshot, DEFAULT_MAX_RECORDS};
use crate::service_map_technology::CatalogVersion;

fn row(sequence: u64) -> TransactionRecord {
    let message =
        MessageRecord::from_headers_and_body(&http::HeaderMap::new(), b"synthetic body", 1024);
    let mut row = TransactionRecord::http(
        chrono::DateTime::from_timestamp(1_760_000_000, 0).unwrap(),
        "GET".into(),
        "https".into(),
        "example.com".into(),
        format!("/items/{sequence}"),
        Some(200),
        1,
        message.clone(),
        Some(message),
        vec![],
        None,
        None,
    );
    row.id = Uuid::from_u128(sequence as u128 + 1);
    row.sequence = sequence;
    row
}

async fn capture(store: &Arc<TransactionStore>) -> (MetadataSnapshot, ServiceMapMetadataEpoch) {
    let store = Arc::clone(store);
    tokio::task::spawn_blocking(move || {
        store.service_map_snapshot_blocking_for_catalog(
            Uuid::from_u128(99),
            DEFAULT_MAX_RECORDS,
            CatalogVersion::V1,
            &crate::store::ListFilters::default(),
        )
    })
    .await
    .unwrap()
}

fn durable_store(records: Vec<TransactionRecord>) -> (Arc<TransactionStore>, PathBuf) {
    let dir = std::env::temp_dir().join(format!("sniper-map-epoch-{}", Uuid::new_v4()));
    fs::create_dir_all(&dir).unwrap();
    let store = Arc::new(TransactionStore::from_records_with_journal(
        records,
        dir.join("transactions.journal"),
        None,
    ));
    (store, dir)
}

#[tokio::test]
async fn service_map_epoch_blocking_projection_matches_async_and_never_reads_bodies() {
    let record = row(1);
    let (store, dir) = durable_store(vec![record.clone()]);
    let locators =
        crate::session::write_transactions_file_for_test_returning_locators(&dir, &[record])
            .unwrap();
    store.adopt_written_locators(locators).await;
    fs::remove_file(dir.join("transactions.ndjson")).unwrap();
    for catalog in [CatalogVersion::V1, CatalogVersion::V2] {
        let asynchronous = store
            .service_map_snapshot_for_catalog(Uuid::from_u128(99), DEFAULT_MAX_RECORDS, catalog)
            .await;
        let worker_store = Arc::clone(&store);
        let (mut blocking, epoch) = tokio::task::spawn_blocking(move || {
            worker_store.service_map_snapshot_blocking_for_catalog(
                Uuid::from_u128(99),
                DEFAULT_MAX_RECORDS,
                catalog,
                &crate::store::ListFilters::default(),
            )
        })
        .await
        .unwrap();
        assert!(store.service_map_metadata_epoch_matches(epoch).await);
        blocking.captured_at = asynchronous.captured_at;
        let mut a = crate::service_map::build_bounded(
            Uuid::from_u128(99),
            asynchronous,
            DEFAULT_MAX_RECORDS,
            false,
            None,
            &[],
            &[],
        )
        .unwrap();
        let mut b = crate::service_map::build_bounded(
            Uuid::from_u128(99),
            blocking,
            DEFAULT_MAX_RECORDS,
            false,
            None,
            &[],
            &[],
        )
        .unwrap();
        a.snapshot.id = Uuid::nil();
        b.snapshot.id = Uuid::nil();
        assert_eq!(
            serde_json::to_vec(&a).unwrap(),
            serde_json::to_vec(&b).unwrap()
        );
    }
    assert!(store.inner.read().await.entries[0]
        .request
        .body_preview
        .is_empty());
    drop(store);
    fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn service_map_epoch_changes_on_delete_retention_update_replace_and_duplicates() {
    for operation in [
        "delete",
        "retention",
        "update",
        "replace",
        "duplicate",
        "duplicate_hydration",
    ] {
        let initial = row(1);
        let (store, dir) = durable_store(vec![row(2), initial.clone()]);
        if operation == "duplicate_hydration" {
            let mut disk = initial.clone();
            disk.path = "/different-retained-metadata".into();
            let locators = crate::session::write_transactions_file_for_test_returning_locators(
                &dir,
                &[disk, row(2)],
            )
            .unwrap();
            store.adopt_written_locators(locators).await;
        }
        let (_, epoch) = capture(&store).await;
        match operation {
            "delete" => {
                assert_eq!(store.delete_ids(&[initial.id]).await.unwrap(), 1);
            }
            "retention" => {
                assert_eq!(
                    store
                        .trim_retention(1, &HashSet::new(), 1)
                        .await
                        .unwrap()
                        .deleted_ids,
                    [initial.id]
                );
            }
            "update" => {
                assert!(store
                    .update_record(initial.id, |r| r.path = "/changed".into())
                    .await
                    .is_some());
            }
            "replace" => {
                store.replace_all(vec![row(2), initial]).await;
            }
            _ => {
                store.insert(initial).await;
            }
        }
        assert!(
            !store.service_map_metadata_epoch_matches(epoch).await,
            "{operation}"
        );
        if operation == "duplicate_hydration" {
            assert!(capture(&store)
                .await
                .0
                .rows
                .iter()
                .any(|row| row.path == "/different-retained-metadata"));
        }
        drop(store);
        fs::remove_dir_all(dir).unwrap();
    }
}

#[tokio::test]
async fn service_map_epoch_legacy_cap_rotates_only_for_actual_trim_including_zero() {
    for cap in [0, 1] {
        let store = Arc::new(TransactionStore::from_records_with_max_entries(
            vec![row(1)],
            Some(cap),
        ));
        let (_, epoch) = capture(&store).await;
        store.insert(row(2)).await;
        assert!(!store.service_map_metadata_epoch_matches(epoch).await);
        assert_eq!(store.len().await, cap);
    }
    let store = Arc::new(TransactionStore::from_records_with_max_entries(
        vec![],
        Some(1),
    ));
    let (_, epoch) = capture(&store).await;
    store.insert(row(1)).await;
    assert!(store.service_map_metadata_epoch_matches(epoch).await);
    let mut inner = store.inner.write().await;
    assert!(!inner.trim_to_max_entries(1));
    assert_eq!(inner.service_map_metadata_epoch, epoch.0);
    assert!(inner.trim_to_max_entries(0));
    let empty_epoch = inner.service_map_metadata_epoch;
    assert!(!inner.trim_to_max_entries(0));
    assert_eq!(inner.service_map_metadata_epoch, empty_epoch);
}

#[tokio::test]
async fn service_map_epoch_preserves_append_annotations_rollback_and_body_publication() {
    let initial = row(1);
    let (store, dir) = durable_store(vec![initial.clone()]);
    let (_, epoch) = capture(&store).await;
    store.insert(row(2)).await;
    assert!(store.service_map_metadata_epoch_matches(epoch).await);
    store
        .update_annotations(
            initial.id,
            Some(Some("red".into())),
            Some(Some("note".into())),
        )
        .await
        .unwrap();
    assert!(store.service_map_metadata_epoch_matches(epoch).await);
    assert!(store
        .restore_annotations_if_current(
            initial.id,
            Some("red".into()),
            Some("note".into()),
            None,
            None
        )
        .await
        .unwrap());
    assert!(store.service_map_metadata_epoch_matches(epoch).await);
    let snapshot = store.snapshot_for_persistence(None).await.unwrap();
    let staged = dir.join("replacement");
    fs::create_dir_all(&staged).unwrap();
    let records: Vec<_> = snapshot.iter().map(|(record, _)| record.clone()).collect();
    let locators =
        crate::session::write_transactions_file_for_test_returning_locators(&staged, &records)
            .unwrap();
    let source = staged.join("transactions.ndjson");
    let destination = dir.join("transactions.ndjson");
    let publisher = Arc::clone(&store);
    tokio::task::spawn_blocking(move || {
        publisher.publish_persistence_snapshot(&snapshot, locators, || {
            crate::platform::rename(&source, &destination)
        })
    })
    .await
    .unwrap()
    .unwrap();
    assert!(store.service_map_metadata_epoch_matches(epoch).await);
    assert!(store
        .inner
        .read()
        .await
        .entries
        .iter()
        .all(|r| r.request.body_preview.is_empty()));
    drop(store);
    fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn service_map_epoch_failed_delete_and_failed_update_preserve_snapshot() {
    let initial = row(1);
    let store = Arc::new(TransactionStore::from_records(vec![initial.clone()]));
    let (_, epoch) = capture(&store).await;
    assert!(store.delete_ids(&[initial.id]).await.is_err());
    assert!(store
        .update_record(Uuid::new_v4(), |r| r.path = "/unused".into())
        .await
        .is_none());
    assert!(store.service_map_metadata_epoch_matches(epoch).await);
    let (store, dir) = durable_store(vec![initial.clone()]);
    let locators = crate::session::write_transactions_file_for_test_returning_locators(
        &dir,
        &[initial.clone()],
    )
    .unwrap();
    store.adopt_written_locators(locators).await;
    fs::remove_file(dir.join("transactions.ndjson")).unwrap();
    let (_, epoch) = capture(&store).await;
    assert!(store
        .update_record(initial.id, |r| r.path = "/unused".into())
        .await
        .is_none());
    assert!(store.service_map_metadata_epoch_matches(epoch).await);
    // Even failed duplicate hydration is conservatively destructive: it installs
    // a new row and may alter the older row's metadata in other cases.
    store.insert(initial).await;
    assert!(!store.service_map_metadata_epoch_matches(epoch).await);
    drop(store);
    fs::remove_dir_all(dir).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn service_map_epoch_invalidates_after_unlock_before_event_sequence_advances() {
    let initial = row(1);
    let store = Arc::new(TransactionStore::from_records(vec![initial.clone()]));
    let (_, epoch) = capture(&store).await;
    let event_sequence = store.latest_event_sequence();
    let (ready, started) = oneshot::channel();
    let (release, resume) = mpsc::channel();
    *store.before_transaction_event_hook.lock().unwrap() = Some(Box::new(move || {
        ready.send(()).unwrap();
        resume
            .recv_timeout(std::time::Duration::from_secs(10))
            .unwrap();
    }));
    let writer = Arc::clone(&store);
    let updating = tokio::spawn(async move {
        writer
            .update_record(initial.id, |r| r.path = "/changed".into())
            .await
    });
    started.await.unwrap();
    assert_eq!(store.latest_event_sequence(), event_sequence);
    assert!(!store.service_map_metadata_epoch_matches(epoch).await);
    assert_eq!(capture(&store).await.0.rows[0].path, "/changed");
    release.send(()).unwrap();
    assert!(updating.await.unwrap().is_some());
    assert!(store.latest_event_sequence() > event_sequence);
}

// Retention removes rows between a whole-history read's chunks. The read
// continues below the oldest row it read that is still retained, so each
// remaining unread row is read once; a replaced history keeps none of them.
#[test]
fn whole_history_read_resumes_below_the_oldest_retained_row_it_read() {
    let mut inner = StoreInner::from_newest_first((0..10).rev().map(row).collect());
    // The last chunk read the newest six rows, oldest first.
    let read: Vec<_> = (4..10)
        .map(|index| (inner.entries[index].id, inner.body_generations[index]))
        .collect();
    assert_eq!(resume_below(&inner, &[]), Some(10), "nothing read yet");
    inner.trim_to_max_entries(8);
    assert_eq!(resume_below(&inner, &read), Some(2));
    assert_eq!(inner.entries[1].path, "/items/3", "the unread rows left");
    inner.trim_to_max_entries(5);
    assert_eq!(resume_below(&inner, &read), Some(0), "and none left");
    let replaced = StoreInner::from_newest_first((0..10).rev().map(row).collect());
    assert_eq!(resume_below(&replaced, &read), None);
}

// Auto-refresh asks for freshness after an event, without throwing away the
// whole-history cache when that event did not change this store's data.
#[test]
fn whole_history_cache_fresh_reuses_complete_unchanged_bytes() {
    let store = TransactionStore::from_records(vec![row(1)]);
    let bytes = bytes::Bytes::from_static(b"synthetic complete map");
    store.store_service_map(
        "filter-one".into(),
        store.service_map_history_token(),
        std::time::Duration::from_secs(10),
        true,
        bytes.clone(),
    );
    assert_eq!(store.cached_service_map("filter-one", true), Some(bytes));
    assert!(store.cached_service_map("filter-two", true).is_none());
}

#[tokio::test]
async fn whole_history_cache_fresh_bypasses_changed_history_cooldown() {
    let store = Arc::new(TransactionStore::from_records(vec![row(1)]));
    let worker = Arc::clone(&store);
    tokio::task::spawn_blocking(move || {
        worker.store_service_map(
            "filter".into(),
            worker.service_map_history_token(),
            std::time::Duration::from_secs(10),
            true,
            bytes::Bytes::from_static(b"before capture"),
        );
    })
    .await
    .unwrap();
    store.insert(row(2)).await;
    tokio::task::spawn_blocking(move || {
        // A normal poll still sees the previous map during the 40-second
        // cooldown, but an event-informed fresh read can rebuild immediately.
        assert_eq!(
            store.cached_service_map("filter", false),
            Some(bytes::Bytes::from_static(b"before capture"))
        );
        assert!(store.cached_service_map("filter", true).is_none());
        let bytes = bytes::Bytes::from_static(b"after capture");
        store.store_service_map(
            "filter".into(),
            store.service_map_history_token(),
            std::time::Duration::from_secs(10),
            true,
            bytes.clone(),
        );
        assert_eq!(store.cached_service_map("filter", true), Some(bytes));
    })
    .await
    .unwrap();
}

#[test]
fn whole_history_cache_clean_polls_continue_private_enrichment() {
    let store = TransactionStore::from_records(vec![row(1)]);
    // Public projection completeness is not the private enrichment flag.
    let bytes = bytes::Bytes::from_static(br#"{"snapshot":{"complete":true}}"#);
    store.store_service_map(
        "filter".into(),
        store.service_map_history_token(),
        std::time::Duration::from_secs(10),
        false,
        bytes.clone(),
    );
    assert_eq!(store.cached_service_map("filter", false), Some(bytes));
    store
        .service_map_result
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .built = std::time::Instant::now() - std::time::Duration::from_secs(60);
    assert!(store.cached_service_map("filter", false).is_none());
    assert!(store.cached_service_map("filter", true).is_none());
}
