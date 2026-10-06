//! Opt-in contracts for local saved-data management. No operation sends traffic.
use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    history_selection::{selection_token, HistorySelection},
    saved_contract::{self, CONTRACT_VERSION},
    saved_operations::{
        SavedOperationCode, SavedOperationCompletion, SavedOperationError, SavedOperationKind,
        SavedOperationOutcome, SavedOperationResult,
    },
    state::AppState,
    store::ListFilters,
};

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SavedErrorCode {
    InvalidInput,
    UnknownOperation,
    SessionNotFound,
    SessionUnavailable,
    SelectionMismatch,
    StaleContinuation,
    OperationConflict,
    StorageUnavailable,
    OutcomeUnknown,
}

impl SavedErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidInput => "INVALID_INPUT",
            Self::UnknownOperation => "UNKNOWN_OPERATION",
            Self::SessionNotFound => "SESSION_NOT_FOUND",
            Self::SessionUnavailable => "SESSION_UNAVAILABLE",
            Self::SelectionMismatch => "SELECTION_MISMATCH",
            Self::StaleContinuation => "STALE_CONTINUATION",
            Self::OperationConflict => "OPERATION_CONFLICT",
            Self::StorageUnavailable => "STORAGE_UNAVAILABLE",
            Self::OutcomeUnknown => "OUTCOME_UNKNOWN",
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedApiError {
    pub code: SavedErrorCode,
    pub message: String,
    pub outcome: SavedOperationOutcome,
    pub operation_id: Option<Uuid>,
    pub session_id: Option<Uuid>,
    pub retryable: bool,
}

fn error_response(
    status: StatusCode,
    code: SavedErrorCode,
    message: &str,
    outcome: SavedOperationOutcome,
    input: &Value,
) -> Response {
    let error = SavedApiError {
        code,
        message: message.to_owned(),
        outcome,
        operation_id: input
            .get("operation_id")
            .and_then(Value::as_str)
            .and_then(|s| Uuid::parse_str(s).ok()),
        session_id: saved_contract::input_session_id(input),
        retryable: false,
    };
    (
        status,
        Json(json!({"ok":false,"contract_version":CONTRACT_VERSION,"error":error})),
    )
        .into_response()
}

fn success(data: Value) -> Response {
    Json(json!({"ok":true,"contract_version":CONTRACT_VERSION,"data":data})).into_response()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CallPayload {
    operation: String,
    input: Value,
}

pub fn is_write(operation: &str) -> bool {
    saved_contract::is_write(operation)
}

/// Parsing lives inside the handler so invalid JSON also has a typed error.
pub(crate) async fn call(
    State(state): State<Arc<AppState>>,
    body: Result<Bytes, axum::extract::rejection::BytesRejection>,
) -> Response {
    let body = match body {
        Ok(body) => body,
        Err(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                SavedErrorCode::InvalidInput,
                "Saved-data request body is unreadable or exceeds the server limit",
                SavedOperationOutcome::NotApplied,
                &Value::Null,
            )
        }
    };
    let payload: CallPayload = match serde_json::from_slice(&body) {
        Ok(payload) => payload,
        Err(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                SavedErrorCode::InvalidInput,
                "Expected a saved-data operation and input object",
                SavedOperationOutcome::NotApplied,
                &Value::Null,
            )
        }
    };
    if saved_contract::input_schema(&payload.operation).is_none() {
        return error_response(
            StatusCode::BAD_REQUEST,
            SavedErrorCode::UnknownOperation,
            "Unknown saved-data operation",
            SavedOperationOutcome::NotApplied,
            &payload.input,
        );
    }
    if saved_contract::validate_input(&payload.operation, &payload.input).is_err() {
        // Validation may inspect private filters. Never copy them into errors.
        return error_response(
            StatusCode::BAD_REQUEST,
            SavedErrorCode::InvalidInput,
            "Input does not satisfy this saved-data operation's schema",
            SavedOperationOutcome::NotApplied,
            &payload.input,
        );
    }
    let input = payload.input;
    match payload.operation.as_str() {
        "saved.v1.http.list" => list_http(&state, input).await,
        "saved.v1.session.list" => list_sessions(&state, input).await,
        "saved.v1.http.select" => select_http(&state, input).await,
        "saved.v1.operation.get" => get_operation(&state, input).await,
        operation => mutate(&state, operation, input).await,
    }
}

async fn list_http(state: &Arc<AppState>, input: Value) -> Response {
    let cursor = input.get("continuation");
    let source = cursor.unwrap_or(&input);
    let requested_session = source
        .get("session_id")
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok());
    let session =
        match crate::api::resolve_read_session_for_optional_id(state, requested_session).await {
            Ok(session) => session,
            Err(response) => return read_session_error(response.status(), &input),
        };
    let store_generation = session.store.saved_cursor_generation();
    if cursor.is_some_and(|cursor| {
        cursor
            .get("store_generation")
            .and_then(Value::as_str)
            .and_then(|s| Uuid::parse_str(s).ok())
            != Some(store_generation)
    }) {
        return error_response(
            StatusCode::CONFLICT,
            SavedErrorCode::StaleContinuation,
            "Saved-data continuation expired after the session store reloaded; start a new listing",
            SavedOperationOutcome::NotApplied,
            &input,
        );
    }
    let limit = source
        .get("limit")
        .and_then(Value::as_u64)
        .unwrap_or(saved_contract::DEFAULT_LIMIT as u64) as usize;
    let before_sequence = cursor
        .and_then(|c| c.get("before_sequence"))
        .and_then(Value::as_u64);
    let page = session
        .store
        .list_page(&ListFilters {
            limit: Some(limit),
            before_sequence,
            sort_key: Some("index".into()),
            sort_direction: Some("desc".into()),
            ..Default::default()
        })
        .await;
    let continuation = if page.has_more {
        page.items.last().map(|item| json!({"session_id":session.id(),"before_sequence":item.sequence,"limit":limit,"store_generation":store_generation}))
    } else {
        None
    };
    success(json!({
        "contract_version":CONTRACT_VERSION,"session_id":session.id(),
        "items":page.items,"limit":limit,"has_more":continuation.is_some(),"continuation":continuation,
    }))
}

async fn list_sessions(state: &Arc<AppState>, input: Value) -> Response {
    let limit = input
        .get("limit")
        .and_then(Value::as_u64)
        .unwrap_or(saved_contract::DEFAULT_LIMIT as u64) as usize;
    let after_id = input
        .get("after_id")
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok());
    let mut items = state.list_sessions().await;
    items.sort_unstable_by_key(|item| item.id);
    items.retain(|item| after_id.is_none_or(|after| item.id > after));
    let has_more = items.len() > limit;
    items.truncate(limit);
    let continuation = if has_more {
        items
            .last()
            .map(|item| json!({"after_id":item.id,"limit":limit}))
    } else {
        None
    };
    success(
        json!({"contract_version":CONTRACT_VERSION,"items":items,"limit":limit,
        "has_more":has_more,"continuation":continuation}),
    )
}

fn read_session_error(status: StatusCode, input: &Value) -> Response {
    if status == StatusCode::NOT_FOUND {
        error_response(
            status,
            SavedErrorCode::SessionNotFound,
            "Saved session not found",
            SavedOperationOutcome::NotApplied,
            input,
        )
    } else {
        error_response(
            status,
            SavedErrorCode::SessionUnavailable,
            "Saved session is unavailable",
            SavedOperationOutcome::NotApplied,
            input,
        )
    }
}

async fn select_http(state: &Arc<AppState>, input: Value) -> Response {
    let selection: HistorySelection =
        serde_json::from_value(input.clone()).expect("validated selection");
    let session =
        match crate::api::resolve_read_session_for_optional_id(state, Some(selection.session_id))
            .await
        {
            Ok(session) => session,
            Err(response) => return read_session_error(response.status(), &input),
        };
    match selection.resolve(&session.store).await {
        Ok(rows) => success(
            json!({"contract_version":CONTRACT_VERSION,"session_id":selection.session_id,
            "count":rows.len(),"ids":rows.iter().map(|row| row.id).collect::<Vec<_>>(),
            "selection_token":selection_token(selection.session_id, &rows)}),
        ),
        Err(_) => error_response(
            StatusCode::CONFLICT,
            SavedErrorCode::SelectionMismatch,
            "Selection contains IDs missing from the saved session",
            SavedOperationOutcome::NotApplied,
            &input,
        ),
    }
}

async fn get_operation(state: &Arc<AppState>, input: Value) -> Response {
    let operation_id = Uuid::parse_str(input["operation_id"].as_str().unwrap()).unwrap();
    match state.saved_operations.lookup(operation_id).await {
        Ok(receipt) => {
            let outcome = receipt
                .as_ref()
                .map(|receipt| receipt.outcome)
                .unwrap_or(SavedOperationOutcome::Unknown);
            success(
                json!({"contract_version":CONTRACT_VERSION,"operation_id":operation_id,
                "found":receipt.is_some(),"outcome":outcome,"receipt":receipt}),
            )
        }
        Err(error) => ledger_error(error, &input),
    }
}

fn ledger_error(error: SavedOperationError, input: &Value) -> Response {
    match error {
        SavedOperationError::Conflict { .. } => error_response(StatusCode::CONFLICT, SavedErrorCode::OperationConflict,
            "Operation ID is already bound to different input; no new mutation was started", SavedOperationOutcome::NotApplied, input),
        SavedOperationError::InvalidInput => error_response(StatusCode::BAD_REQUEST, SavedErrorCode::InvalidInput,
            "Invalid saved mutation input", SavedOperationOutcome::NotApplied, input),
        SavedOperationError::IntentPersistenceFailed => error_response(StatusCode::INTERNAL_SERVER_ERROR, SavedErrorCode::StorageUnavailable,
            "Could not reserve operation durably; no mutation was started", SavedOperationOutcome::NotApplied, input),
        _ => error_response(StatusCode::INTERNAL_SERVER_ERROR, SavedErrorCode::OutcomeUnknown,
            "Could not establish the saved operation outcome; inspect the receipt before any further action", SavedOperationOutcome::Unknown, input),
    }
}

async fn mutate(state: &Arc<AppState>, operation: &str, input: Value) -> Response {
    let operation_id = Uuid::parse_str(input["operation_id"].as_str().unwrap()).unwrap();
    let session_id = Uuid::parse_str(input["session_id"].as_str().unwrap()).unwrap();
    let kind = match operation {
        "saved.v1.http.delete" => SavedOperationKind::HttpDelete,
        "saved.v1.http.clear" => SavedOperationKind::HttpClear,
        "saved.v1.session.rename" => SavedOperationKind::SessionRename,
        _ => {
            return error_response(
                StatusCode::BAD_REQUEST,
                SavedErrorCode::UnknownOperation,
                "Unknown saved mutation",
                SavedOperationOutcome::NotApplied,
                &input,
            )
        }
    };
    let state_for_mutation = state.clone();
    let mutation_input = input.clone();
    let result = state
        .saved_operations
        .execute(operation_id, session_id, kind, &input, move || async move {
            if !state_for_mutation.sessions.contains_session(session_id) {
                return SavedOperationCompletion::not_applied(SavedOperationCode::SessionNotFound);
            }
            if matches!(kind, SavedOperationKind::SessionRename) {
                let name = mutation_input["name"].as_str().unwrap().to_owned();
                return match state_for_mutation.rename_session(session_id, name).await {
                    Ok(session) => {
                        SavedOperationCompletion::applied(SavedOperationResult::SessionRenamed {
                            session,
                        })
                    }
                    // Rename spans registry persistence and cached metadata. A generic error
                    // cannot prove rollback across a failed disk acknowledgement.
                    Err(_) => SavedOperationCompletion::unknown(SavedOperationCode::MutationFailed),
                };
            }
            let session = match crate::api::resolve_session_for_optional_id(
                &state_for_mutation,
                Some(session_id),
            )
            .await
            {
                Ok(session) => session,
                Err(response) => {
                    return SavedOperationCompletion::not_applied(
                        if response.status() == StatusCode::NOT_FOUND {
                            SavedOperationCode::SessionNotFound
                        } else {
                            SavedOperationCode::SessionConflict
                        },
                    )
                }
            };
            let _operation_guard = match crate::api::guard_session_write_operation(
                &state_for_mutation,
                &session,
                false,
            )
            .await
            {
                Ok(guard) => guard,
                Err(response) => {
                    return SavedOperationCompletion::not_applied(
                        if response.status() == StatusCode::NOT_FOUND {
                            SavedOperationCode::SessionNotFound
                        } else {
                            SavedOperationCode::SessionConflict
                        },
                    )
                }
            };
            let _mutation_guard = session.mutation_guard().await;
            let deleted = if matches!(kind, SavedOperationKind::HttpClear) {
                session.store.delete_all().await
            } else {
                let mut selection_input = mutation_input;
                selection_input
                    .as_object_mut()
                    .unwrap()
                    .remove("operation_id");
                let selection: HistorySelection =
                    serde_json::from_value(selection_input).expect("validated deletion");
                session
                    .store
                    .delete_selection(&selection)
                    .await
                    .map(|(count, _)| count)
            };
            match deleted {
                Ok(deleted_count) => SavedOperationCompletion::applied(
                    if matches!(kind, SavedOperationKind::HttpClear) {
                        SavedOperationResult::HttpCleared { deleted_count }
                    } else {
                        SavedOperationResult::HttpDeleted { deleted_count }
                    },
                ),
                Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => {
                    SavedOperationCompletion::not_applied(SavedOperationCode::SelectionMismatch)
                }
                Err(_) => SavedOperationCompletion::unknown(SavedOperationCode::PersistenceFailed),
            }
        })
        .await;
    match result {
        Ok(execution) => success(
            json!({"contract_version":CONTRACT_VERSION,"receipt":execution.receipt,"replayed":execution.replayed}),
        ),
        Err(error) => ledger_error(error, &input),
    }
}
