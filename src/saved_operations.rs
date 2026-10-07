//! Durable, idempotent receipts for local saved-data mutations only.
//!
//! A durable unknown intent precedes every mutation. An intent is never removed
//! or overwritten, including when the caller disconnects or the mutation panics.
//! A repeated operation ID therefore never reruns a possibly completed mutation.
//! If intent publication succeeds but its directory sync fails, only the same
//! invocation may attempt a terminal not-applied receipt before mutation starts.
//! Recovery is attempted once; persistent storage faults leave the intent pending.

use std::{
    collections::HashMap,
    fmt, fs,
    future::Future,
    io::{self, Write},
    panic::AssertUnwindSafe,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use chrono::{DateTime, Utc};
use futures_util::FutureExt;
use rsa::sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex as AsyncMutex;
use uuid::Uuid;

use crate::session::SessionSummary;

const CONTRACT_VERSION: &str = "saved.v1";
const LEDGER_DIRECTORY: &str = "saved-operations-v1";
// Sharing this across ledger instances also protects tests and callers that
// reopen the same data directory within one process. The runtime already owns
// the cross-process data-directory lock.
static OPERATION_LOCK: AsyncMutex<()> = AsyncMutex::const_new(());

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SavedOperationKind {
    #[serde(rename = "saved.v1.http.delete")]
    HttpDelete,
    #[serde(rename = "saved.v1.http.clear")]
    HttpClear,
    #[serde(rename = "saved.v1.session.rename")]
    SessionRename,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SavedOperationOutcome {
    Applied,
    NotApplied,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SavedOperationCode {
    Applied,
    Pending,
    InvalidInput,
    SessionNotFound,
    SessionConflict,
    SelectionMismatch,
    PersistenceFailed,
    MutationFailed,
    ReceiptPersistenceFailed,
    WorkerFailed,
}

impl SavedOperationCode {
    pub fn message(self) -> &'static str {
        match self {
            Self::Applied => "Saved-data mutation applied.",
            Self::Pending => "A durable intent exists; the mutation outcome is unknown. Do not retry with a new operation ID.",
            Self::InvalidInput => "The saved-data input is invalid.",
            Self::SessionNotFound => "The explicitly selected session was not found.",
            Self::SessionConflict => "The selected session cannot be modified in its current state.",
            Self::SelectionMismatch => "The saved HTTP selection no longer matches.",
            Self::PersistenceFailed => "Saved-data persistence failed; inspect the outcome before taking further action.",
            Self::MutationFailed => "The saved-data mutation did not complete successfully.",
            Self::ReceiptPersistenceFailed => "The final receipt could not be durably saved; the mutation outcome is unknown. Do not retry with a new operation ID.",
            Self::WorkerFailed => "The mutation worker ended without a confirmed outcome. Do not retry with a new operation ID.",
        }
    }
}

/// Results contain counts or session metadata, never saved HTTP traffic.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SavedOperationResult {
    HttpDeleted { deleted_count: usize },
    HttpCleared { deleted_count: usize },
    SessionRenamed { session: SessionSummary },
}

impl SavedOperationResult {
    fn matches(&self, operation: SavedOperationKind) -> bool {
        matches!(
            (self, operation),
            (Self::HttpDeleted { .. }, SavedOperationKind::HttpDelete)
                | (Self::HttpCleared { .. }, SavedOperationKind::HttpClear)
                | (
                    Self::SessionRenamed { .. },
                    SavedOperationKind::SessionRename
                )
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedOperationReceipt {
    pub contract_version: String,
    pub operation_id: Uuid,
    pub session_id: Uuid,
    pub operation: SavedOperationKind,
    pub outcome: SavedOperationOutcome,
    pub code: SavedOperationCode,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<SavedOperationResult>,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SavedOperationExecution {
    pub receipt: SavedOperationReceipt,
    pub replayed: bool,
}

/// Explicit classification is required after mutation starts. An error is not
/// evidence of no application: persistence acknowledgements can fail after a
/// durable write. Only use `not_applied` with definitive evidence of no change.
#[derive(Clone, Debug)]
pub struct SavedOperationCompletion {
    outcome: SavedOperationOutcome,
    code: SavedOperationCode,
    result: Option<SavedOperationResult>,
}

impl SavedOperationCompletion {
    pub fn applied(result: SavedOperationResult) -> Self {
        Self {
            outcome: SavedOperationOutcome::Applied,
            code: SavedOperationCode::Applied,
            result: Some(result),
        }
    }

    pub fn not_applied(code: SavedOperationCode) -> Self {
        Self {
            outcome: SavedOperationOutcome::NotApplied,
            code: failure_code(code),
            result: None,
        }
    }

    pub fn unknown(code: SavedOperationCode) -> Self {
        Self {
            outcome: SavedOperationOutcome::Unknown,
            code: failure_code(code),
            result: None,
        }
    }
}

fn failure_code(code: SavedOperationCode) -> SavedOperationCode {
    match code {
        SavedOperationCode::Applied | SavedOperationCode::Pending => {
            SavedOperationCode::MutationFailed
        }
        other => other,
    }
}

#[derive(Clone, Debug)]
pub enum SavedOperationError {
    Conflict { receipt: SavedOperationReceipt },
    InvalidInput,
    IntentPersistenceFailed,
    ReadFailed,
    CorruptReceipt,
    WorkerFailed,
}

impl fmt::Display for SavedOperationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Conflict { .. } => "operation_id is already bound to different saved-data input",
            Self::InvalidInput => "could not fingerprint the typed saved-data input",
            Self::IntentPersistenceFailed => "could not save a durable operation intent; mutation was not started",
            Self::ReadFailed => "could not read the saved operation ledger; no new mutation was started",
            Self::CorruptReceipt => "the saved operation ledger is inconsistent; no new mutation was started",
            Self::WorkerFailed => "operation worker failed; inspect the operation receipt before taking further action",
        })
    }
}

impl std::error::Error for SavedOperationError {}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredReceipt {
    fingerprint: String,
    receipt: SavedOperationReceipt,
}

#[derive(Debug)]
enum PersistenceFailure {
    BeforePublication,
    AfterPublication,
    WorkerFailed,
}

#[derive(Debug)]
pub struct SavedOperationLedger {
    root: PathBuf,
    // Pending entries stay visible while their mutation/final fsync runs.
    // If publishing or syncing a terminal receipt fails after mutation begins,
    // report unknown for the remainder of this process even if the final file
    // is already visible. On restart, a surviving complete file is evidence of
    // its recorded result; the durable intent still prevents any rerun.
    visible: Mutex<HashMap<Uuid, StoredReceipt>>,
    #[cfg(test)]
    failpoint: std::sync::atomic::AtomicU8,
    #[cfg(test)]
    directory_sync_failures: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    directory_sync_attempts: std::sync::atomic::AtomicUsize,
}

impl SavedOperationLedger {
    /// Construction does no IO; all receipt reads/writes run on blocking workers.
    pub fn new(data_dir: impl AsRef<Path>) -> Self {
        Self {
            root: data_dir.as_ref().join(LEDGER_DIRECTORY),
            visible: Mutex::new(HashMap::new()),
            #[cfg(test)]
            failpoint: std::sync::atomic::AtomicU8::new(0),
            #[cfg(test)]
            directory_sync_failures: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            directory_sync_attempts: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Only a hash of `input` is retained. Callers must validate a typed input
    /// from the closed saved-data registry before invoking this method.
    ///
    /// Once polled, execution belongs to a detached task, so cancelling the
    /// request cannot release the operation lock while a mutation is running.
    pub async fn execute<I, F, Fut>(
        self: &Arc<Self>,
        operation_id: Uuid,
        session_id: Uuid,
        operation: SavedOperationKind,
        input: &I,
        mutation: F,
    ) -> Result<SavedOperationExecution, SavedOperationError>
    where
        I: Serialize + ?Sized,
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = SavedOperationCompletion> + Send + 'static,
    {
        let fingerprint = fingerprint(operation, session_id, input)?;
        let ledger = self.clone();
        tokio::spawn(async move {
            let _guard = OPERATION_LOCK.lock().await;
            if let Some(existing) = ledger.read(operation_id).await? {
                if existing.fingerprint != fingerprint {
                    return Err(SavedOperationError::Conflict {
                        receipt: existing.receipt,
                    });
                }
                return Ok(SavedOperationExecution {
                    receipt: existing.receipt,
                    replayed: true,
                });
            }
            let mut stored = StoredReceipt {
                fingerprint,
                receipt: SavedOperationReceipt {
                    contract_version: CONTRACT_VERSION.to_owned(),
                    operation_id,
                    session_id,
                    operation,
                    outcome: SavedOperationOutcome::Unknown,
                    code: SavedOperationCode::Pending,
                    message: SavedOperationCode::Pending.message().to_owned(),
                    result: None,
                    created_at: Utc::now(),
                    completed_at: None,
                },
            };
            let recover_unstarted_intent = match ledger.persist(stored.clone(), false).await {
                Ok(()) => false,
                Err(PersistenceFailure::AfterPublication) => true,
                Err(_) => return Err(SavedOperationError::IntentPersistenceFailed),
            };

            ledger
                .visible
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .insert(operation_id, stored.clone());

            let completion = if recover_unstarted_intent {
                // Only this invocation proves the closure has never run. Never
                // recover an arbitrary pending intent discovered by read().
                ledger
                    .sync_unstarted_intent(stored.clone())
                    .await
                    .map_err(|_| SavedOperationError::IntentPersistenceFailed)?;
                SavedOperationCompletion::not_applied(SavedOperationCode::PersistenceFailed)
            } else {
                AssertUnwindSafe(async move { mutation().await })
                    .catch_unwind()
                    .await
                    .unwrap_or_else(|_| {
                        SavedOperationCompletion::unknown(SavedOperationCode::WorkerFailed)
                    })
            };
            let completion = if completion
                .result
                .as_ref()
                .is_some_and(|result| !result.matches(operation))
            {
                SavedOperationCompletion::unknown(SavedOperationCode::WorkerFailed)
            } else {
                completion
            };
            stored.receipt.outcome = completion.outcome;
            stored.receipt.code = completion.code;
            stored.receipt.message = completion.code.message().to_owned();
            stored.receipt.result = completion.result;
            stored.receipt.completed_at = Some(Utc::now());
            if ledger.persist(stored.clone(), true).await.is_err() {
                stored.receipt.outcome = SavedOperationOutcome::Unknown;
                stored.receipt.code = SavedOperationCode::ReceiptPersistenceFailed;
                stored.receipt.message = SavedOperationCode::ReceiptPersistenceFailed
                    .message()
                    .to_owned();
                stored.receipt.result = None;
                stored.receipt.completed_at = None;
                ledger
                    .visible
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .insert(operation_id, stored.clone());
            } else {
                ledger
                    .visible
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .remove(&operation_id);
            }
            Ok(SavedOperationExecution {
                receipt: stored.receipt,
                replayed: false,
            })
        })
        .await
        .map_err(|_| SavedOperationError::WorkerFailed)?
    }

    /// No receipt means unknown, never proof that an operation was not applied.
    /// This does not wait for running mutations: their durable pending receipt
    /// can be observed while execution is still in progress.
    pub async fn lookup(
        self: &Arc<Self>,
        operation_id: Uuid,
    ) -> Result<Option<SavedOperationReceipt>, SavedOperationError> {
        Ok(self.read(operation_id).await?.map(|stored| stored.receipt))
    }

    async fn read(
        self: &Arc<Self>,
        operation_id: Uuid,
    ) -> Result<Option<StoredReceipt>, SavedOperationError> {
        if let Some(stored) = self
            .visible
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .get(&operation_id)
            .cloned()
        {
            return Ok(Some(stored));
        }
        let ledger = self.clone();
        let disk = tokio::task::spawn_blocking(move || ledger.read_sync(operation_id))
            .await
            .map_err(|_| SavedOperationError::ReadFailed)?;
        // The operation may have started after the first cache check. Its
        // pending/uncertain entry takes precedence over a not-yet-synced file.
        if let Some(stored) = self
            .visible
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .get(&operation_id)
            .cloned()
        {
            return Ok(Some(stored));
        }
        disk
    }

    fn read_sync(&self, operation_id: Uuid) -> Result<Option<StoredReceipt>, SavedOperationError> {
        let mut intent = read_record(&self.path(operation_id, false))?;
        let completed = read_record(&self.path(operation_id, true))?;
        if intent.is_none() && completed.is_some() {
            // A writer may have published both files between these two reads.
            intent = read_record(&self.path(operation_id, false))?;
        }
        let Some(intent) = intent else {
            // A terminal file without its intent is inconsistent, not a fresh ID.
            return if completed.is_some() {
                Err(SavedOperationError::CorruptReceipt)
            } else {
                Ok(None)
            };
        };
        validate_record(&intent, operation_id, false)?;
        if let Some(completed) = completed {
            validate_record(&completed, operation_id, true)?;
            if intent.fingerprint != completed.fingerprint
                || intent.receipt.session_id != completed.receipt.session_id
                || intent.receipt.operation != completed.receipt.operation
                || intent.receipt.created_at != completed.receipt.created_at
            {
                return Err(SavedOperationError::CorruptReceipt);
            }
            Ok(Some(completed))
        } else {
            Ok(Some(intent))
        }
    }

    async fn persist(
        self: &Arc<Self>,
        stored: StoredReceipt,
        complete: bool,
    ) -> Result<(), PersistenceFailure> {
        let ledger = self.clone();
        tokio::task::spawn_blocking(move || {
            #[cfg(test)]
            if ledger.failpoint.load(std::sync::atomic::Ordering::SeqCst)
                == if complete { 2 } else { 1 }
            {
                return Err(PersistenceFailure::BeforePublication);
            }
            ensure_ledger_directory(&ledger.root)
                .map_err(|_| PersistenceFailure::BeforePublication)?;
            publish_record(&ledger.path(stored.receipt.operation_id, complete), &stored)
                .map_err(|_| PersistenceFailure::BeforePublication)?;
            #[cfg(test)]
            {
                let failpoint = ledger.failpoint.load(std::sync::atomic::Ordering::SeqCst);
                if complete && failpoint == 4 {
                    return Err(PersistenceFailure::AfterPublication);
                }
                if !complete && failpoint == 5 {
                    panic!("injected worker failure after intent publication");
                }
            }
            ledger
                .sync_receipt_directory()
                .map_err(|_| PersistenceFailure::AfterPublication)?;
            #[cfg(test)]
            if complete && ledger.failpoint.load(std::sync::atomic::Ordering::SeqCst) == 3 {
                return Err(PersistenceFailure::AfterPublication);
            }
            Ok(())
        })
        .await
        .map_err(|_| PersistenceFailure::WorkerFailed)?
    }

    async fn sync_unstarted_intent(self: &Arc<Self>, stored: StoredReceipt) -> io::Result<()> {
        let ledger = self.clone();
        tokio::task::spawn_blocking(move || {
            let existing = ledger
                .read_sync(stored.receipt.operation_id)
                .map_err(io::Error::other)?;
            // Do not finalize a missing, altered, corrupt, or already completed
            // record. The immutable intent must still be this invocation's.
            if serde_json::to_value(existing).map_err(io::Error::other)?
                != serde_json::to_value(&stored).map_err(io::Error::other)?
            {
                return Err(io::Error::other("operation intent changed before recovery"));
            }
            fs::OpenOptions::new()
                .write(true)
                .open(ledger.path(stored.receipt.operation_id, false))?
                .sync_all()?;
            if let Some(parent) = ledger.root.parent() {
                crate::platform::sync_directory(parent)?;
            }
            ledger.sync_receipt_directory()
        })
        .await
        .map_err(|_| io::Error::other("intent recovery worker failed"))?
    }

    fn sync_receipt_directory(&self) -> io::Result<()> {
        #[cfg(test)]
        {
            use std::sync::atomic::Ordering;
            self.directory_sync_attempts.fetch_add(1, Ordering::SeqCst);
            let mut remaining = self.directory_sync_failures.load(Ordering::SeqCst);
            while remaining > 0 {
                match self.directory_sync_failures.compare_exchange_weak(
                    remaining,
                    remaining - 1,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                ) {
                    Ok(_) => {
                        return Err(io::Error::other("injected receipt directory sync failure"))
                    }
                    Err(current) => remaining = current,
                }
            }
        }
        crate::platform::sync_directory(&self.root)
    }

    fn path(&self, operation_id: Uuid, complete: bool) -> PathBuf {
        self.root.join(format!(
            "{operation_id}.{}.json",
            if complete { "result" } else { "intent" }
        ))
    }
}

fn fingerprint<I: Serialize + ?Sized>(
    operation: SavedOperationKind,
    session_id: Uuid,
    input: &I,
) -> Result<String, SavedOperationError> {
    // Value's object map is key-sorted, unlike arbitrary Serialize map iteration.
    // The array order remains part of typed input identity.
    let value = serde_json::to_value(input).map_err(|_| SavedOperationError::InvalidInput)?;
    let bytes = serde_json::to_vec(&(operation, session_id, value))
        .map_err(|_| SavedOperationError::InvalidInput)?;
    let mut hash = Sha256::new();
    hash.update(b"sniper-saved-operation-fingerprint-v1\0");
    hash.update(bytes);
    Ok(format!("{:x}", hash.finalize()))
}

fn validate_record(
    stored: &StoredReceipt,
    operation_id: Uuid,
    complete: bool,
) -> Result<(), SavedOperationError> {
    let receipt = &stored.receipt;
    let invalid = receipt.contract_version != CONTRACT_VERSION
        || receipt.operation_id != operation_id
        || stored.fingerprint.len() != 64
        || !stored
            .fingerprint
            .bytes()
            .all(|ch| ch.is_ascii_digit() || (b'a'..=b'f').contains(&ch))
        || receipt.message != receipt.code.message()
        || if complete {
            receipt.completed_at.is_none()
                || receipt.code == SavedOperationCode::Pending
                || match receipt.outcome {
                    SavedOperationOutcome::Applied => {
                        receipt.code != SavedOperationCode::Applied
                            || !receipt
                                .result
                                .as_ref()
                                .is_some_and(|result| result.matches(receipt.operation))
                    }
                    _ => receipt.result.is_some() || receipt.code == SavedOperationCode::Applied,
                }
        } else {
            receipt.completed_at.is_some()
                || receipt.outcome != SavedOperationOutcome::Unknown
                || receipt.code != SavedOperationCode::Pending
                || receipt.result.is_some()
        };
    if invalid {
        Err(SavedOperationError::CorruptReceipt)
    } else {
        Ok(())
    }
}

fn read_record(path: &Path) -> Result<Option<StoredReceipt>, SavedOperationError> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|_| SavedOperationError::CorruptReceipt),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(SavedOperationError::ReadFailed),
    }
}

fn ensure_ledger_directory(path: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)?;
    // The ledger entry in the data directory must survive a crash too.
    if let Some(parent) = path.parent() {
        crate::platform::sync_directory(parent)?;
    }
    Ok(())
}

// Publishes synced file contents; the caller must then sync the directory and
// distinguish failure there from failure before publication.
fn publish_record(path: &Path, stored: &StoredReceipt) -> io::Result<()> {
    // Intent and result are separate immutable files. Never delete or replace
    // an existing receipt as a fallback for a failed rename.
    match fs::symlink_metadata(path) {
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "receipt already exists",
            ))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let temporary = TemporaryFile(path.with_extension(format!("tmp-{}", Uuid::new_v4())));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary.0)?;
    serde_json::to_writer(&mut file, stored).map_err(io::Error::other)?;
    file.write_all(b"\n")?;
    file.flush()?;
    file.sync_all()?;
    drop(file);
    crate::platform::rename(&temporary.0, path)
}

struct TemporaryFile(PathBuf);

impl Drop for TemporaryFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Notify;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("sniper-saved-operation-{}", Uuid::new_v4()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn ledger(&self) -> Arc<SavedOperationLedger> {
            Arc::new(SavedOperationLedger::new(&self.0))
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn applied() -> SavedOperationCompletion {
        SavedOperationCompletion::applied(SavedOperationResult::HttpDeleted { deleted_count: 3 })
    }

    #[tokio::test]
    async fn duplicate_returns_exact_receipt_and_conflicts_never_execute() {
        let directory = TestDirectory::new();
        let ledger = directory.ledger();
        let id = Uuid::new_v4();
        let session = Uuid::new_v4();
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = calls.clone();
        let first = ledger
            .execute(
                id,
                session,
                SavedOperationKind::HttpDelete,
                &vec![1, 2],
                move || async move {
                    counted.fetch_add(1, Ordering::SeqCst);
                    applied()
                },
            )
            .await
            .unwrap();
        let repeated = ledger
            .execute(
                id,
                session,
                SavedOperationKind::HttpDelete,
                &vec![1, 2],
                || async { panic!("must not execute twice") },
            )
            .await
            .unwrap();
        assert!(!first.replayed);
        assert!(repeated.replayed);
        assert_eq!(
            serde_json::to_value(first.receipt).unwrap(),
            serde_json::to_value(repeated.receipt).unwrap()
        );
        for (session, kind, input) in [
            (session, SavedOperationKind::HttpDelete, vec![2, 3]),
            (Uuid::new_v4(), SavedOperationKind::HttpDelete, vec![1, 2]),
            (session, SavedOperationKind::HttpClear, vec![1, 2]),
        ] {
            assert!(matches!(
                ledger
                    .execute(id, session, kind, &input, || async {
                        panic!("conflict must not execute")
                    })
                    .await,
                Err(SavedOperationError::Conflict { .. })
            ));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn receipt_survives_restart_and_absent_id_is_unknown() {
        let directory = TestDirectory::new();
        let ledger = directory.ledger();
        let id = Uuid::new_v4();
        let session = Uuid::new_v4();
        let first = ledger
            .execute(id, session, SavedOperationKind::HttpDelete, &(), || async {
                applied()
            })
            .await
            .unwrap();
        drop(ledger);
        let restarted = directory.ledger();
        assert!(restarted.lookup(Uuid::new_v4()).await.unwrap().is_none());
        let repeated = restarted
            .execute(id, session, SavedOperationKind::HttpDelete, &(), || async {
                panic!("restart must not rerun")
            })
            .await
            .unwrap();
        assert!(repeated.replayed);
        assert_eq!(
            serde_json::to_value(first.receipt).unwrap(),
            serde_json::to_value(repeated.receipt).unwrap()
        );
    }

    #[tokio::test]
    async fn pending_intent_survives_crash_style_restart_and_blocks_retry() {
        let directory = TestDirectory::new();
        let ledger = directory.ledger();
        let id = Uuid::new_v4();
        let session = Uuid::new_v4();
        let stored = StoredReceipt {
            fingerprint: fingerprint(SavedOperationKind::HttpDelete, session, &()).unwrap(),
            receipt: SavedOperationReceipt {
                contract_version: CONTRACT_VERSION.into(),
                operation_id: id,
                session_id: session,
                operation: SavedOperationKind::HttpDelete,
                outcome: SavedOperationOutcome::Unknown,
                code: SavedOperationCode::Pending,
                message: SavedOperationCode::Pending.message().into(),
                result: None,
                created_at: Utc::now(),
                completed_at: None,
            },
        };
        ledger.persist(stored, false).await.unwrap();
        drop(ledger);
        let restarted = directory.ledger();
        let receipt = restarted
            .execute(id, session, SavedOperationKind::HttpDelete, &(), || async {
                panic!("pending cannot be retried")
            })
            .await
            .unwrap();
        assert!(receipt.replayed);
        assert_eq!(receipt.receipt.outcome, SavedOperationOutcome::Unknown);
        assert_eq!(receipt.receipt.code, SavedOperationCode::Pending);
    }

    #[tokio::test]
    async fn intent_write_failure_never_invokes_mutation() {
        let directory = TestDirectory::new();
        let ledger = directory.ledger();
        ledger.failpoint.store(1, Ordering::SeqCst);
        let id = Uuid::new_v4();
        let result = ledger
            .execute(
                id,
                Uuid::new_v4(),
                SavedOperationKind::HttpDelete,
                &(),
                || async { panic!("failed intent must not run") },
            )
            .await;
        assert!(matches!(
            result,
            Err(SavedOperationError::IntentPersistenceFailed)
        ));
        assert!(ledger.lookup(id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn intent_directory_sync_failure_recovers_not_applied_without_mutation() {
        let directory = TestDirectory::new();
        let ledger = directory.ledger();
        ledger.directory_sync_failures.store(1, Ordering::SeqCst);
        let id = Uuid::new_v4();
        let session = Uuid::new_v4();
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = calls.clone();
        let first = ledger
            .execute(
                id,
                session,
                SavedOperationKind::HttpDelete,
                &(),
                move || {
                    counted.fetch_add(1, Ordering::SeqCst);
                    async { applied() }
                },
            )
            .await
            .unwrap();
        assert!(!first.replayed);
        assert_eq!(first.receipt.outcome, SavedOperationOutcome::NotApplied);
        assert_eq!(first.receipt.code, SavedOperationCode::PersistenceFailed);
        assert!(first.receipt.result.is_none());
        assert!(first.receipt.completed_at.is_some());
        assert_eq!(ledger.directory_sync_attempts.load(Ordering::SeqCst), 3);
        let expected = serde_json::to_value(&first.receipt).unwrap();
        let intent_bytes = fs::read(ledger.path(id, false)).unwrap();
        let result_bytes = fs::read(ledger.path(id, true)).unwrap();
        assert_eq!(fs::read_dir(&ledger.root).unwrap().count(), 2);
        for current in [ledger.clone(), directory.ledger()] {
            let counted = calls.clone();
            let repeated = current
                .execute(
                    id,
                    session,
                    SavedOperationKind::HttpDelete,
                    &(),
                    move || {
                        counted.fetch_add(1, Ordering::SeqCst);
                        async { applied() }
                    },
                )
                .await
                .unwrap();
            assert!(repeated.replayed);
            assert_eq!(serde_json::to_value(repeated.receipt).unwrap(), expected);
            assert_eq!(
                serde_json::to_value(current.lookup(id).await.unwrap().unwrap()).unwrap(),
                expected
            );
            for (session, kind, input) in [
                (
                    session,
                    SavedOperationKind::HttpDelete,
                    serde_json::json!(1),
                ),
                (
                    Uuid::new_v4(),
                    SavedOperationKind::HttpDelete,
                    serde_json::Value::Null,
                ),
                (
                    session,
                    SavedOperationKind::HttpClear,
                    serde_json::Value::Null,
                ),
            ] {
                let counted = calls.clone();
                assert!(matches!(
                    current
                        .execute(id, session, kind, &input, move || {
                            counted.fetch_add(1, Ordering::SeqCst);
                            async { applied() }
                        })
                        .await,
                    Err(SavedOperationError::Conflict { .. })
                ));
            }
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(fs::read(ledger.path(id, false)).unwrap(), intent_bytes);
        assert_eq!(fs::read(ledger.path(id, true)).unwrap(), result_bytes);
        assert_eq!(ledger.directory_sync_attempts.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn persistent_intent_directory_sync_failure_stays_reserved_without_retry() {
        let directory = TestDirectory::new();
        let ledger = directory.ledger();
        ledger
            .directory_sync_failures
            .store(usize::MAX, Ordering::SeqCst);
        let id = Uuid::new_v4();
        let session = Uuid::new_v4();
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = calls.clone();
        let first = ledger
            .execute(
                id,
                session,
                SavedOperationKind::HttpDelete,
                &(),
                move || {
                    counted.fetch_add(1, Ordering::SeqCst);
                    async { applied() }
                },
            )
            .await;
        assert!(matches!(
            first,
            Err(SavedOperationError::IntentPersistenceFailed)
        ));
        // Initial sync and one bounded recovery attempt. There is no retry loop.
        assert_eq!(ledger.directory_sync_attempts.load(Ordering::SeqCst), 2);
        let intent_bytes = fs::read(ledger.path(id, false)).unwrap();
        assert!(!ledger.path(id, true).exists());
        // Even once storage works again, neither a new request nor a new ledger
        // has the original invocation's proof that no mutation was attempted.
        ledger.directory_sync_failures.store(0, Ordering::SeqCst);
        for current in [ledger.clone(), directory.ledger()] {
            let counted = calls.clone();
            let repeated = current
                .execute(
                    id,
                    session,
                    SavedOperationKind::HttpDelete,
                    &(),
                    move || {
                        counted.fetch_add(1, Ordering::SeqCst);
                        async { applied() }
                    },
                )
                .await
                .unwrap();
            assert!(repeated.replayed);
            assert_eq!(repeated.receipt.outcome, SavedOperationOutcome::Unknown);
            assert_eq!(repeated.receipt.code, SavedOperationCode::Pending);
            assert!(repeated.receipt.completed_at.is_none());
            assert_eq!(
                current.lookup(id).await.unwrap().unwrap().code,
                SavedOperationCode::Pending
            );
            assert!(!current.path(id, true).exists());
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(ledger.directory_sync_attempts.load(Ordering::SeqCst), 2);
        assert_eq!(fs::read(ledger.path(id, false)).unwrap(), intent_bytes);
    }

    #[tokio::test]
    async fn recovery_terminal_write_failures_remain_unknown_without_mutation() {
        // Before terminal publication, after its directory sync, and after its
        // rename but before directory sync must all preserve the reservation.
        for failpoint in [2, 3, 4] {
            let directory = TestDirectory::new();
            let ledger = directory.ledger();
            ledger.directory_sync_failures.store(1, Ordering::SeqCst);
            ledger.failpoint.store(failpoint, Ordering::SeqCst);
            let id = Uuid::new_v4();
            let session = Uuid::new_v4();
            let calls = Arc::new(AtomicUsize::new(0));
            let counted = calls.clone();
            let first = ledger
                .execute(
                    id,
                    session,
                    SavedOperationKind::HttpDelete,
                    &(),
                    move || {
                        counted.fetch_add(1, Ordering::SeqCst);
                        async { applied() }
                    },
                )
                .await
                .unwrap();
            assert_eq!(first.receipt.outcome, SavedOperationOutcome::Unknown);
            assert_eq!(
                first.receipt.code,
                SavedOperationCode::ReceiptPersistenceFailed
            );
            assert!(first.receipt.completed_at.is_none());
            for current in [ledger.clone(), directory.ledger()] {
                let counted = calls.clone();
                let repeated = current
                    .execute(
                        id,
                        session,
                        SavedOperationKind::HttpDelete,
                        &(),
                        move || {
                            counted.fetch_add(1, Ordering::SeqCst);
                            async { applied() }
                        },
                    )
                    .await
                    .unwrap();
                assert!(repeated.replayed);
                let expected = if Arc::ptr_eq(&current, &ledger) {
                    (
                        SavedOperationOutcome::Unknown,
                        SavedOperationCode::ReceiptPersistenceFailed,
                    )
                } else if failpoint == 2 {
                    (SavedOperationOutcome::Unknown, SavedOperationCode::Pending)
                } else {
                    // Only a surviving, valid terminal file establishes the
                    // not-applied result after a restart.
                    (
                        SavedOperationOutcome::NotApplied,
                        SavedOperationCode::PersistenceFailed,
                    )
                };
                assert_eq!((repeated.receipt.outcome, repeated.receipt.code), expected);
            }
            assert_eq!(calls.load(Ordering::SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn intent_worker_failure_does_not_recover_or_invoke_mutation() {
        let directory = TestDirectory::new();
        let ledger = directory.ledger();
        ledger.failpoint.store(5, Ordering::SeqCst);
        let id = Uuid::new_v4();
        let session = Uuid::new_v4();
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = calls.clone();
        assert!(matches!(
            ledger
                .execute(
                    id,
                    session,
                    SavedOperationKind::HttpDelete,
                    &(),
                    move || {
                        counted.fetch_add(1, Ordering::SeqCst);
                        async { applied() }
                    }
                )
                .await,
            Err(SavedOperationError::IntentPersistenceFailed)
        ));
        assert!(ledger.path(id, false).exists());
        assert!(!ledger.path(id, true).exists());
        assert_eq!(ledger.directory_sync_attempts.load(Ordering::SeqCst), 0);
        for current in [ledger, directory.ledger()] {
            let counted = calls.clone();
            let repeated = current
                .execute(
                    id,
                    session,
                    SavedOperationKind::HttpDelete,
                    &(),
                    move || {
                        counted.fetch_add(1, Ordering::SeqCst);
                        async { applied() }
                    },
                )
                .await
                .unwrap();
            assert!(repeated.replayed);
            assert_eq!(repeated.receipt.code, SavedOperationCode::Pending);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn unstarted_intent_recovery_rejects_inconsistent_records_without_writes() {
        for changed in [
            "missing",
            "corrupt",
            "fingerprint",
            "session",
            "operation",
            "created",
            "completed",
        ] {
            let directory = TestDirectory::new();
            let ledger = directory.ledger();
            let id = Uuid::new_v4();
            let session = Uuid::new_v4();
            let stored = StoredReceipt {
                fingerprint: fingerprint(SavedOperationKind::HttpDelete, session, &()).unwrap(),
                receipt: SavedOperationReceipt {
                    contract_version: CONTRACT_VERSION.into(),
                    operation_id: id,
                    session_id: session,
                    operation: SavedOperationKind::HttpDelete,
                    outcome: SavedOperationOutcome::Unknown,
                    code: SavedOperationCode::Pending,
                    message: SavedOperationCode::Pending.message().into(),
                    result: None,
                    created_at: Utc::now(),
                    completed_at: None,
                },
            };
            ledger.directory_sync_failures.store(1, Ordering::SeqCst);
            assert!(matches!(
                ledger.persist(stored.clone(), false).await,
                Err(PersistenceFailure::AfterPublication)
            ));
            let mut altered = stored.clone();
            match changed {
                "missing" => fs::remove_file(ledger.path(id, false)).unwrap(),
                "corrupt" => fs::write(ledger.path(id, false), b"{}").unwrap(),
                "completed" => {
                    altered.receipt.outcome = SavedOperationOutcome::NotApplied;
                    altered.receipt.code = SavedOperationCode::InvalidInput;
                    altered.receipt.message = SavedOperationCode::InvalidInput.message().into();
                    altered.receipt.completed_at = Some(Utc::now());
                    ledger.persist(altered, true).await.unwrap();
                }
                field => {
                    match field {
                        "fingerprint" => altered.fingerprint = "0".repeat(64),
                        "session" => altered.receipt.session_id = Uuid::new_v4(),
                        "operation" => altered.receipt.operation = SavedOperationKind::HttpClear,
                        "created" => altered.receipt.created_at += chrono::Duration::seconds(1),
                        _ => unreachable!(),
                    }
                    fs::write(
                        ledger.path(id, false),
                        serde_json::to_vec(&altered).unwrap(),
                    )
                    .unwrap();
                }
            }
            let before_intent = fs::read(ledger.path(id, false)).ok();
            let before_result = fs::read(ledger.path(id, true)).ok();
            let syncs = ledger.directory_sync_attempts.load(Ordering::SeqCst);
            assert!(
                ledger.sync_unstarted_intent(stored).await.is_err(),
                "{changed}"
            );
            assert_eq!(
                fs::read(ledger.path(id, false)).ok(),
                before_intent,
                "{changed}"
            );
            assert_eq!(
                fs::read(ledger.path(id, true)).ok(),
                before_result,
                "{changed}"
            );
            assert_eq!(
                ledger.directory_sync_attempts.load(Ordering::SeqCst),
                syncs,
                "{changed}"
            );
        }
    }

    #[tokio::test]
    async fn applied_mutation_abrupt_process_exit_leaves_pending_and_blocks_restart() {
        const CHILD_DIRECTORY: &str = "SNIPER_TEST_SAVED_OPERATION_CRASH_DIR";
        const CHILD_ID: &str = "SNIPER_TEST_SAVED_OPERATION_CRASH_ID";
        const CHILD_SESSION: &str = "SNIPER_TEST_SAVED_OPERATION_CRASH_SESSION";
        if let Some(path) = std::env::var_os(CHILD_DIRECTORY) {
            let ledger = Arc::new(SavedOperationLedger::new(&path));
            let id = Uuid::parse_str(&std::env::var(CHILD_ID).unwrap()).unwrap();
            let session = Uuid::parse_str(&std::env::var(CHILD_SESSION).unwrap()).unwrap();
            ledger
                .execute(
                    id,
                    session,
                    SavedOperationKind::HttpDelete,
                    &(),
                    move || async move {
                        // A temp-only stand-in mutation survives the process exit, while
                        // no terminal receipt can be written and destructors cannot run.
                        let marker = PathBuf::from(path).join("mutation-count");
                        let mut file = fs::File::create(marker).unwrap();
                        file.write_all(b"1").unwrap();
                        file.sync_all().unwrap();
                        std::process::exit(0);
                    },
                )
                .await
                .unwrap();
            panic!("the child must exit during its mutation");
        }
        let directory = TestDirectory::new();
        let id = Uuid::new_v4();
        let session = Uuid::new_v4();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "saved_operations::tests::applied_mutation_abrupt_process_exit_leaves_pending_and_blocks_restart"])
            .env(CHILD_DIRECTORY, &directory.0)
            .env(CHILD_ID, id.to_string())
            .env(CHILD_SESSION, session.to_string())
            .status()
            .unwrap();
        assert!(status.success());
        let marker = directory.0.join("mutation-count");
        assert_eq!(fs::read(&marker).unwrap(), b"1");
        let restarted = directory.ledger();
        let retried_marker = marker.clone();
        let repeated = restarted
            .execute(
                id,
                session,
                SavedOperationKind::HttpDelete,
                &(),
                move || async move {
                    fs::write(retried_marker, b"2").unwrap();
                    applied()
                },
            )
            .await
            .unwrap();
        assert!(repeated.replayed);
        assert_eq!(repeated.receipt.outcome, SavedOperationOutcome::Unknown);
        assert_eq!(repeated.receipt.code, SavedOperationCode::Pending);
        assert!(repeated.receipt.completed_at.is_none());
        assert_eq!(fs::read(marker).unwrap(), b"1");
        assert!(!restarted.path(id, true).exists());
        assert_eq!(restarted.directory_sync_attempts.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn result_write_failure_is_unknown_and_intent_blocks_restart_retry() {
        let directory = TestDirectory::new();
        let ledger = directory.ledger();
        ledger.failpoint.store(2, Ordering::SeqCst);
        let id = Uuid::new_v4();
        let session = Uuid::new_v4();
        let first = ledger
            .execute(id, session, SavedOperationKind::HttpDelete, &(), || async {
                applied()
            })
            .await
            .unwrap();
        assert_eq!(first.receipt.outcome, SavedOperationOutcome::Unknown);
        assert_eq!(
            first.receipt.code,
            SavedOperationCode::ReceiptPersistenceFailed
        );
        assert!(first.receipt.result.is_none());
        assert_eq!(
            ledger.lookup(id).await.unwrap().unwrap().code,
            SavedOperationCode::ReceiptPersistenceFailed
        );
        let repeated = ledger
            .execute(id, session, SavedOperationKind::HttpDelete, &(), || async {
                panic!("unknown must not rerun")
            })
            .await
            .unwrap();
        assert!(repeated.replayed);
        assert_eq!(
            repeated.receipt.code,
            SavedOperationCode::ReceiptPersistenceFailed
        );
        drop(ledger);
        let restarted = directory.ledger();
        let receipt = restarted
            .execute(id, session, SavedOperationKind::HttpDelete, &(), || async {
                panic!("restart of unknown must not rerun")
            })
            .await
            .unwrap();
        assert_eq!(receipt.receipt.outcome, SavedOperationOutcome::Unknown);
        assert_eq!(receipt.receipt.code, SavedOperationCode::Pending);
    }

    #[tokio::test]
    async fn failure_after_result_publication_remains_unknown_in_running_process() {
        let directory = TestDirectory::new();
        let ledger = directory.ledger();
        ledger.failpoint.store(3, Ordering::SeqCst);
        let id = Uuid::new_v4();
        let session = Uuid::new_v4();
        let result = ledger
            .execute(id, session, SavedOperationKind::HttpDelete, &(), || async {
                applied()
            })
            .await
            .unwrap();
        assert_eq!(result.receipt.outcome, SavedOperationOutcome::Unknown);
        assert_eq!(
            ledger.lookup(id).await.unwrap().unwrap().outcome,
            SavedOperationOutcome::Unknown
        );
        let repeated = ledger
            .execute(id, session, SavedOperationKind::HttpDelete, &(), || async {
                panic!("must not rerun")
            })
            .await
            .unwrap();
        assert_eq!(repeated.receipt.outcome, SavedOperationOutcome::Unknown);
        drop(ledger);
        // A complete, surviving result gives a restarted process evidence of
        // application; this reconciles the uncertainty without re-execution.
        let restarted = directory.ledger();
        let recovered = restarted
            .execute(id, session, SavedOperationKind::HttpDelete, &(), || async {
                panic!("must not rerun")
            })
            .await
            .unwrap();
        assert!(recovered.replayed);
        assert_eq!(recovered.receipt.outcome, SavedOperationOutcome::Applied);
    }

    #[tokio::test]
    async fn request_cancellation_keeps_mutation_and_receipt_work_running() {
        let directory = TestDirectory::new();
        let ledger = directory.ledger();
        let id = Uuid::new_v4();
        let session = Uuid::new_v4();
        let started = Arc::new(Notify::new());
        let finish = Arc::new(Notify::new());
        let request = {
            let ledger = ledger.clone();
            let started = started.clone();
            let finish = finish.clone();
            tokio::spawn(async move {
                ledger
                    .execute(
                        id,
                        session,
                        SavedOperationKind::HttpDelete,
                        &(),
                        move || async move {
                            started.notify_one();
                            finish.notified().await;
                            applied()
                        },
                    )
                    .await
            })
        };
        tokio::time::timeout(std::time::Duration::from_secs(10), started.notified())
            .await
            .unwrap();
        assert_eq!(
            ledger.lookup(id).await.unwrap().unwrap().code,
            SavedOperationCode::Pending
        );
        request.abort();
        let _ = request.await;
        finish.notify_one();
        // This queues behind the detached original while it finishes saving.
        let repeated = ledger
            .execute(id, session, SavedOperationKind::HttpDelete, &(), || async {
                panic!("cancelled caller cannot cause rerun")
            })
            .await
            .unwrap();
        assert!(repeated.replayed);
        assert_eq!(repeated.receipt.outcome, SavedOperationOutcome::Applied);
    }

    #[tokio::test]
    async fn mutation_panic_records_unknown_and_definitive_rejection_is_not_applied() {
        let directory = TestDirectory::new();
        let ledger = directory.ledger();
        let id = Uuid::new_v4();
        let session = Uuid::new_v4();
        let panic = ledger
            .execute(id, session, SavedOperationKind::HttpDelete, &(), || async {
                panic!("synthetic failure")
            })
            .await
            .unwrap();
        assert_eq!(panic.receipt.outcome, SavedOperationOutcome::Unknown);
        assert_eq!(panic.receipt.code, SavedOperationCode::WorkerFailed);
        let rejected = ledger
            .execute(
                Uuid::new_v4(),
                session,
                SavedOperationKind::HttpDelete,
                &(),
                || async {
                    SavedOperationCompletion::not_applied(SavedOperationCode::SessionNotFound)
                },
            )
            .await
            .unwrap();
        assert_eq!(rejected.receipt.outcome, SavedOperationOutcome::NotApplied);
    }

    #[tokio::test]
    async fn inputs_are_only_hashed_and_corrupt_receipts_fail_closed() {
        let directory = TestDirectory::new();
        let ledger = directory.ledger();
        let id = Uuid::new_v4();
        ledger
            .execute(
                id,
                Uuid::new_v4(),
                SavedOperationKind::HttpDelete,
                &"private-filter-value",
                || async { applied() },
            )
            .await
            .unwrap();
        for path in fs::read_dir(&ledger.root).unwrap() {
            let content = fs::read_to_string(path.unwrap().path()).unwrap();
            assert!(!content.contains("private-filter-value"));
        }
        fs::write(ledger.path(id, false), "{}").unwrap();
        assert!(matches!(
            ledger.lookup(id).await,
            Err(SavedOperationError::CorruptReceipt)
        ));
        assert!(matches!(
            ledger
                .execute(
                    id,
                    Uuid::new_v4(),
                    SavedOperationKind::HttpDelete,
                    &(),
                    || async { panic!("corrupt record must fail closed") }
                )
                .await,
            Err(SavedOperationError::CorruptReceipt)
        ));
    }

    #[test]
    fn fingerprints_canonicalize_object_key_order_and_bind_operation_and_session() {
        let session = Uuid::new_v4();
        let first = serde_json::json!({"a": 1, "b": {"c": 2, "d": 3}});
        let second: serde_json::Value =
            serde_json::from_str(r#"{"b":{"d":3,"c":2},"a":1}"#).unwrap();
        let expected = fingerprint(SavedOperationKind::HttpDelete, session, &first).unwrap();
        assert_eq!(
            expected,
            fingerprint(SavedOperationKind::HttpDelete, session, &second).unwrap()
        );
        assert_ne!(
            expected,
            fingerprint(SavedOperationKind::HttpClear, session, &first).unwrap()
        );
        assert_ne!(
            expected,
            fingerprint(SavedOperationKind::HttpDelete, Uuid::new_v4(), &first).unwrap()
        );
    }
}
