//! Opt-in HTTP history retention. Configuration commits and deletion are separate
//! transactions: a failed settings save must never remove captured traffic.
use crate::session::{SessionContext, SessionRegistry};
use rsa::sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    num::NonZeroU32,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, Weak,
    },
    time::Duration,
};
use tokio::sync::{Mutex as AsyncMutex, RwLock};
use uuid::Uuid;

const DELETE_CHUNK_SIZE: usize = 256;
const COMPACTION_DEBOUNCE: Duration = Duration::from_millis(250);
#[cfg(not(test))]
const MIN_COMPACTION_INTERVAL: Duration = Duration::from_secs(30);
// Short enough for a test to outwait it.
#[cfg(test)]
const MIN_COMPACTION_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum HistoryRetentionPolicy {
    #[default]
    Off,
    KeepNewest {
        max_entries: NonZeroU32,
    },
}

impl<'de> Deserialize<'de> for HistoryRetentionPolicy {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Serde's internally tagged unit variant accepts unrelated fields. An
        // empty struct variant makes Off just as strict as KeepNewest.
        #[derive(Deserialize)]
        #[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
        enum Input {
            Off {},
            KeepNewest { max_entries: NonZeroU32 },
        }
        Ok(match Input::deserialize(deserializer)? {
            Input::Off {} => Self::Off,
            Input::KeepNewest { max_entries } => Self::KeepNewest { max_entries },
        })
    }
}

impl HistoryRetentionPolicy {
    pub fn target(&self) -> Option<usize> {
        match self {
            Self::Off => None,
            Self::KeepNewest { max_entries } => Some(max_entries.get() as usize),
        }
    }
}

pub fn history_retention_config_token(
    session_id: Uuid,
    policy: &HistoryRetentionPolicy,
    revision: u64,
) -> String {
    let bytes = serde_json::to_vec(&(session_id, policy, revision))
        .expect("retention policy is serializable");
    let mut hash = Sha256::new();
    hash.update(b"sniper-http-history-retention-v1\0");
    hash.update(bytes);
    format!("{:x}", hash.finalize())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HistoryRetentionStatus {
    pub total_count: usize,
    pub protected_count: usize,
    pub pending: bool,
    pub disk_cleanup_pending: bool,
    pub blocked_reason: Option<HistoryRetentionBlockedReason>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryRetentionBlockedReason {
    ProtectedRecords,
    WorkspaceDurabilityUncertain,
    PersistenceError,
    RecordIdentityConflict,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HistoryRetentionSnapshot {
    pub session_id: Uuid,
    pub config_token: String,
    pub config_revision: String,
    pub policy: HistoryRetentionPolicy,
    pub status: HistoryRetentionStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub changed: Option<bool>,
}

#[derive(Debug)]
pub(crate) enum PolicyWriteError {
    NotCommitted,
    CommittedButUncertain,
    OutcomeUnknown,
}

#[derive(Default)]
pub(crate) struct SessionRetentionState {
    pub persistence_error: AtomicBool,
    #[cfg(test)]
    pub compactions_started: std::sync::atomic::AtomicUsize,
    worker: Mutex<Option<tokio::task::AbortHandle>>,
    #[cfg(test)]
    chunk_gate: Mutex<
        Option<(
            tokio::sync::oneshot::Sender<()>,
            tokio::sync::oneshot::Receiver<()>,
        )>,
    >,
}
#[cfg(test)]
impl SessionRetentionState {
    pub(crate) fn pause_after_next_chunk(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        let (entered, wait) = tokio::sync::oneshot::channel();
        let (resume, release) = tokio::sync::oneshot::channel();
        *self.chunk_gate.lock().unwrap() = Some((entered, release));
        (wait, resume)
    }
}
impl Drop for SessionRetentionState {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.get_mut().unwrap().take() {
            worker.abort();
        }
    }
}

pub(crate) type WorkspaceDurabilityGate = Mutex<HashSet<Uuid>>;
type Contexts = AsyncMutex<HashMap<Uuid, Arc<SessionContext>>>;
type OperationLocks = AsyncMutex<HashMap<Uuid, Arc<AsyncMutex<()>>>>;

/// Only weak references survive while idle. The context owns the abort handle,
/// so dropping a session or the application cannot strand a worker or a journal.
pub(crate) struct RetentionEnvironment {
    pub sessions: Weak<SessionRegistry>,
    pub active: Weak<RwLock<Arc<SessionContext>>>,
    pub contexts: Weak<Contexts>,
    pub operations: Weak<OperationLocks>,
    pub workspace_uncertain: Weak<WorkspaceDurabilityGate>,
    pub persistence_uncertain: Weak<WorkspaceDurabilityGate>,
}
impl RetentionEnvironment {
    async fn operation_lock_for_current(
        &self,
        session: &Arc<SessionContext>,
    ) -> Option<Arc<AsyncMutex<()>>> {
        let (Some(registry), Some(active), Some(contexts), Some(operations)) = (
            self.sessions.upgrade(),
            self.active.upgrade(),
            self.contexts.upgrade(),
            self.operations.upgrade(),
        ) else {
            return None;
        };
        // Match activation's active -> contexts order, and release these guards
        // before waiting for the per-session operation lock. A replaced context
        // must not register a lock for work it no longer owns.
        let active = active.read().await;
        let contexts = contexts.lock().await;
        let mut operations = operations.lock().await;
        let current = if active.id() == session.id() {
            Arc::ptr_eq(&active, session)
        } else {
            contexts
                .get(&session.id())
                .is_some_and(|current| Arc::ptr_eq(current, session))
        };
        // Deletion publishes registry removal before pruning this same map.
        // Checking membership under the map guard prevents a late wake from
        // recreating the entry after teardown has already pruned it.
        if !current || !registry.contains_session(session.id()) {
            return None;
        }
        Some(
            operations
                .entry(session.id())
                .or_insert_with(|| Arc::new(AsyncMutex::new(())))
                .clone(),
        )
    }

    async fn is_current(&self, session: &Arc<SessionContext>) -> bool {
        let (Some(registry), Some(active), Some(contexts)) = (
            self.sessions.upgrade(),
            self.active.upgrade(),
            self.contexts.upgrade(),
        ) else {
            return false;
        };
        if !registry.contains_session(session.id()) {
            return false;
        }
        let active = active.read().await;
        if active.id() == session.id() {
            return Arc::ptr_eq(&active, session);
        }
        drop(active);
        let current = contexts.lock().await;
        current
            .get(&session.id())
            .is_some_and(|value| Arc::ptr_eq(value, session))
    }
    fn persistence_is_uncertain(&self, session: &SessionContext) -> bool {
        session
            .history_retention
            .persistence_error
            .load(Ordering::Acquire)
            || self
                .persistence_uncertain
                .upgrade()
                .is_none_or(|gate| gate.lock().unwrap().contains(&session.id()))
    }
    fn mark_persistence_error(&self, session: &SessionContext) {
        session
            .history_retention
            .persistence_error
            .store(true, Ordering::Release);
        if let Some(gate) = self.persistence_uncertain.upgrade() {
            gate.lock().unwrap().insert(session.id());
        }
    }
    fn workspace_is_uncertain(&self, id: Uuid) -> bool {
        self.workspace_uncertain
            .upgrade()
            .is_none_or(|gate| gate.lock().unwrap().contains(&id))
    }
}

pub(crate) fn start_worker(session: &Arc<SessionContext>, environment: RetentionEnvironment) {
    if !session.retention_writable() {
        return;
    }
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        return;
    };
    let mut slot = session.history_retention.worker.lock().unwrap();
    if slot.as_ref().is_some_and(|handle| !handle.is_finished()) {
        return;
    }
    let notify = session.store.retention_notify();
    let weak = Arc::downgrade(session);
    let task = runtime.spawn(async move {
        let mut compact_after: Option<tokio::time::Instant> = None;
        let mut last_compaction: Option<tokio::time::Instant> = None;
        // The policy revision the last cleanup ran under, and the snapshotted
        // bytes trimmed since then.
        let mut compacted_revision: Option<u64> = None;
        let mut trimmed_bytes: u64 = 0;
        loop {
            if let Some(deadline) = compact_after {
                tokio::select! { _ = notify.notified() => (), _ = tokio::time::sleep_until(deadline) => () }
            } else { notify.notified().await; }
            let Some(session) = weak.upgrade() else { return; };
            if !environment.is_current(&session).await { return; }
            // Off is the default and must not change session-operation state.
            // Previously trimmed records still need disk cleanup after disable.
            if session.runtime.history_retention_policy().await.target().is_none()
                && !session.store.retention_compaction_pending()
            {
                compact_after = None;
                continue;
            }
            let Some(operation_lock) = environment.operation_lock_for_current(&session).await else { return; };
            loop {
                let operation_guard = operation_lock.lock().await;
                if !environment.is_current(&session).await { return; }
                let mutation_guard = session.mutation_guard().await;
                if environment.workspace_is_uncertain(session.id()) || environment.persistence_is_uncertain(&session) { break; }
                let policy = session.runtime.history_retention_policy().await;
                let Some(target) = policy.target() else { break; };
                // Read only IDs, and release the workspace lock before entering
                // the store's insertion/lease critical section.
                let protected = session.workspace.http_replay_source_ids().await;
                match session.store.trim_retention(target, &protected, DELETE_CHUNK_SIZE).await {
                    Ok(result) if !result.deleted_ids.is_empty() => {
                        trimmed_bytes = trimmed_bytes.saturating_add(result.reclaimable_bytes);
                    }
                    Ok(_) => break,
                    Err(error) => {
                        tracing::warn!(session_id = %session.id(), ?error, "HTTP history retention persistence failed");
                        environment.mark_persistence_error(&session);
                        break;
                    }
                }
                drop(mutation_guard);
                drop(operation_guard);
                #[cfg(test)]
                {
                    let gate = session.history_retention.chunk_gate.lock().unwrap().take();
                    if let Some((entered, resume)) = gate {
                        let _ = entered.send(());
                        let _ = resume.await;
                    }
                }
                // Let a queued disable, limit increase, or Replay save win
                // before selecting another bounded deletion batch.
                tokio::task::yield_now().await;
            }
            if !session.store.retention_compaction_pending() {
                // A snapshot written for another reason already reclaimed it.
                compact_after = None;
                trimmed_bytes = 0;
                continue;
            }
            if environment.workspace_is_uncertain(session.id()) || environment.persistence_is_uncertain(&session) {
                compact_after = None;
                continue;
            }
            // At the cap every capture trims a row. Its tombstone is already
            // durable in the journal, and the snapshot that journal growth forces
            // reclaims the space with everything else, so rewriting the whole
            // session for each trickle of trims was pure cost: a full rewrite every
            // MIN_COMPACTION_INTERVAL for as long as capture ran. A changed policy
            // still cleans up promptly, and so do trimmed bodies worth a rewrite.
            let revision = session.runtime.history_retention_config().await.1;
            if compacted_revision == Some(revision)
                && trimmed_bytes < crate::proxy::TRANSACTION_JOURNAL_COMPACT_BYTES
            {
                compact_after = None;
                continue;
            }
            let now = tokio::time::Instant::now();
            let deadline = *compact_after.get_or_insert_with(|| compaction_deadline(now, last_compaction));
            if now < deadline { continue; }
            let _operation_guard = operation_lock.lock().await;
            if !environment.is_current(&session).await { return; }
            let _mutation_guard = session.mutation_guard().await;
            compact_after = None;
            if environment.workspace_is_uncertain(session.id()) || environment.persistence_is_uncertain(&session) { continue; }
            #[cfg(test)]
            session.history_retention.compactions_started.fetch_add(1, Ordering::Relaxed);
            match session.persist_mutation_locked().await {
                Ok(metadata) => {
                    last_compaction = Some(tokio::time::Instant::now());
                    compacted_revision = Some(revision);
                    trimmed_bytes = 0;
                    if let Some(registry) = environment.sessions.upgrade() {
                        if let Err(error) = registry.update_metadata(metadata) { tracing::warn!(?error, "retention session metadata update failed"); }
                    }
                    if session.store.retention_compaction_pending() {
                        // A failed checkpoint purge is still disk cleanup work,
                        // but it must not spin or silently claim success.
                        environment.mark_persistence_error(&session);
                    }
                }
                Err(error) => {
                    tracing::warn!(session_id = %session.id(), ?error, "HTTP history retention disk cleanup failed");
                    environment.mark_persistence_error(&session);
                }
            }

        }
    });
    *slot = Some(task.abort_handle());
    session.store.notify_retention_work();
}

pub(crate) async fn snapshot(
    session: &Arc<SessionContext>,
    workspace_uncertain: bool,
    persistence_uncertain: bool,
    changed: Option<bool>,
) -> HistoryRetentionSnapshot {
    let (policy, revision) = session.runtime.history_retention_config().await;
    let protected = session.workspace.http_replay_source_ids().await;
    let details = session
        .store
        .retention_status_details(&protected, policy.target())
        .await;
    let total_count = details.total_count;
    let protected_count = details.protected_count;
    let excess = policy.target().is_some_and(|target| total_count > target);
    let disk_cleanup_pending = session.store.retention_compaction_pending();
    let blocked_reason = if persistence_uncertain
        || session
            .history_retention
            .persistence_error
            .load(Ordering::Acquire)
    {
        Some(HistoryRetentionBlockedReason::PersistenceError)
    } else if !excess && !disk_cleanup_pending {
        None
    } else if workspace_uncertain {
        Some(HistoryRetentionBlockedReason::WorkspaceDurabilityUncertain)
    } else if excess && details.all_records_protected {
        Some(HistoryRetentionBlockedReason::ProtectedRecords)
    } else if excess && details.identity_conflict {
        Some(HistoryRetentionBlockedReason::RecordIdentityConflict)
    } else {
        None
    };
    HistoryRetentionSnapshot {
        session_id: session.id(),
        config_token: history_retention_config_token(session.id(), &policy, revision),
        config_revision: revision.to_string(),
        policy,
        status: HistoryRetentionStatus {
            total_count,
            protected_count,
            pending: excess || disk_cleanup_pending,
            disk_cleanup_pending,
            blocked_reason,
        },
        changed,
    }
}

fn compaction_deadline(
    now: tokio::time::Instant,
    last: Option<tokio::time::Instant>,
) -> tokio::time::Instant {
    last.map_or(now + COMPACTION_DEBOUNCE, |last| {
        (now + COMPACTION_DEBOUNCE).max(last + MIN_COMPACTION_INTERVAL)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestEnvironment {
        data_dir: std::path::PathBuf,
        sessions: Arc<SessionRegistry>,
        active: Arc<RwLock<Arc<SessionContext>>>,
        contexts: Arc<Contexts>,
        operations: Arc<OperationLocks>,
        workspace_uncertain: Arc<WorkspaceDurabilityGate>,
        persistence_uncertain: Arc<WorkspaceDurabilityGate>,
    }

    impl TestEnvironment {
        fn new() -> Self {
            let data_dir = std::env::temp_dir()
                .join(format!("sniper-retention-worker-locks-{}", Uuid::new_v4()));
            let (sessions, active) = SessionRegistry::load_or_create(&data_dir, 100, 100).unwrap();
            Self {
                data_dir,
                sessions: Arc::new(sessions),
                active: Arc::new(RwLock::new(active)),
                contexts: Arc::new(AsyncMutex::new(HashMap::new())),
                operations: Arc::new(AsyncMutex::new(HashMap::new())),
                workspace_uncertain: Arc::new(Mutex::new(HashSet::new())),
                persistence_uncertain: Arc::new(Mutex::new(HashSet::new())),
            }
        }

        fn environment(&self) -> RetentionEnvironment {
            RetentionEnvironment {
                sessions: Arc::downgrade(&self.sessions),
                active: Arc::downgrade(&self.active),
                contexts: Arc::downgrade(&self.contexts),
                operations: Arc::downgrade(&self.operations),
                workspace_uncertain: Arc::downgrade(&self.workspace_uncertain),
                persistence_uncertain: Arc::downgrade(&self.persistence_uncertain),
            }
        }

        async fn inactive(&self) -> Arc<SessionContext> {
            let metadata = self
                .sessions
                .create_session(Some("Synthetic retention context".into()))
                .unwrap();
            let session = self.sessions.load_context(metadata.id).unwrap();
            self.contexts
                .lock()
                .await
                .insert(metadata.id, session.clone());
            session
        }

        async fn cleanup(self) {
            let data_dir = self.data_dir.clone();
            let mut contexts = vec![Arc::downgrade(&*self.active.read().await)];
            contexts.extend(self.contexts.lock().await.values().map(Arc::downgrade));
            drop(self);
            tokio::time::timeout(Duration::from_secs(2), async {
                while contexts.iter().any(|context| context.upgrade().is_some()) {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            std::fs::remove_dir_all(data_dir).unwrap();
        }
    }

    #[tokio::test]
    async fn history_retention_off_wakes_leave_operation_map_untouched_until_enabled() {
        let fixture = TestEnvironment::new();
        let session = fixture.active.read().await.clone();
        start_worker(&session, fixture.environment());
        for _ in 0..8 {
            session.store.notify_retention_work();
            tokio::task::yield_now().await;
        }
        assert!(fixture.operations.lock().await.is_empty());
        assert_eq!(
            session
                .history_retention
                .compactions_started
                .load(Ordering::Relaxed),
            0
        );

        session
            .runtime
            .set_history_retention_policy(
                HistoryRetentionPolicy::KeepNewest {
                    max_entries: NonZeroU32::new(1).unwrap(),
                },
                1,
            )
            .await;
        session.store.notify_retention_work();
        tokio::time::timeout(Duration::from_secs(2), async {
            while !fixture.operations.lock().await.contains_key(&session.id()) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        drop(session);
        fixture.cleanup().await;
    }

    #[tokio::test]
    async fn history_retention_registration_rechecks_deletion_after_waiting_for_map() {
        let fixture = TestEnvironment::new();
        let session = fixture.inactive().await;
        let environment = fixture.environment();
        {
            let operations = fixture.operations.lock().await;
            let registration = environment.operation_lock_for_current(&session);
            tokio::pin!(registration);
            assert!(
                tokio::time::timeout(Duration::from_millis(20), &mut registration)
                    .await
                    .is_err()
            );
            // Keep the cached Arc in place: membership must be checked again
            // after the map wait, not only by an earlier ownership precheck.
            fixture.sessions.delete_session(session.id()).unwrap();
            drop(operations);
            assert!(registration.await.is_none());
        }
        assert!(fixture.operations.lock().await.is_empty());
        drop(session);
        fixture.cleanup().await;
    }

    #[tokio::test]
    async fn history_retention_stale_context_cannot_register_or_prune_replacement_lock() {
        for existing_lock in [false, true] {
            let fixture = TestEnvironment::new();
            let original = fixture.inactive().await;
            let environment = fixture.environment();
            let previous = if existing_lock {
                environment.operation_lock_for_current(&original).await
            } else {
                None
            };
            let replacement = fixture.sessions.load_context(original.id()).unwrap();
            fixture
                .contexts
                .lock()
                .await
                .insert(original.id(), replacement.clone());
            assert!(environment
                .operation_lock_for_current(&original)
                .await
                .is_none());
            assert_eq!(
                fixture.operations.lock().await.len(),
                usize::from(existing_lock)
            );
            let current = environment
                .operation_lock_for_current(&replacement)
                .await
                .unwrap();
            if let Some(previous) = previous {
                assert!(Arc::ptr_eq(&previous, &current));
            }
            assert!(environment
                .operation_lock_for_current(&original)
                .await
                .is_none());
            assert!(Arc::ptr_eq(
                &current,
                fixture.operations.lock().await.get(&original.id()).unwrap()
            ));
            fixture.contexts.lock().await.remove(&original.id());
            assert!(environment
                .operation_lock_for_current(&replacement)
                .await
                .is_none());
            assert!(Arc::ptr_eq(
                &current,
                fixture.operations.lock().await.get(&original.id()).unwrap()
            ));
            drop(original);
            drop(replacement);
            fixture.cleanup().await;
        }
    }

    #[tokio::test]
    async fn history_retention_deleted_enabled_context_wake_does_not_recreate_lock() {
        let fixture = TestEnvironment::new();
        let session = fixture.inactive().await;
        session
            .runtime
            .set_history_retention_policy(
                HistoryRetentionPolicy::KeepNewest {
                    max_entries: NonZeroU32::new(1).unwrap(),
                },
                1,
            )
            .await;
        fixture.sessions.delete_session(session.id()).unwrap();
        fixture.contexts.lock().await.remove(&session.id());
        start_worker(&session, fixture.environment());
        tokio::time::timeout(Duration::from_secs(2), async {
            while !session
                .history_retention
                .worker
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .is_finished()
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(fixture.operations.lock().await.is_empty());
        drop(session);
        fixture.cleanup().await;
    }

    #[test]
    fn history_retention_compaction_coalesces_sustained_inserts() {
        let start = tokio::time::Instant::now();
        assert_eq!(
            compaction_deadline(start, None),
            start + COMPACTION_DEBOUNCE
        );
        let quiet = (MIN_COMPACTION_INTERVAL - COMPACTION_DEBOUNCE).as_millis() as u64;
        for milliseconds in 0..quiet {
            let next =
                compaction_deadline(start + Duration::from_millis(milliseconds), Some(start));
            assert_eq!(next, start + MIN_COMPACTION_INTERVAL);
        }
    }
}
