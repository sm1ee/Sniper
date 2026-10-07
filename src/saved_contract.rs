//! Opt-in contracts for managing saved data. These names never dispatch traffic.
//!
//! Schemas use JSON Schema 2020-12. `x-sniper-*` keywords document the few
//! additional checks JSON Schema cannot express (UTF-8 bytes, date arithmetic,
//! ordered status ranges, and Rust's integer representation). `validate_input`
//! applies those checks as well as the structural schema. Call it before serde
//! deserialization: an absent optional member is accepted, explicit null is not.

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::{collections::HashSet, sync::LazyLock};
use uuid::Uuid;

use crate::history_selection::HistorySelection;

pub const CONTRACT_VERSION: &str = "saved.v1";
pub const DEFAULT_LIMIT: usize = 50;
pub const MAX_LIMIT: usize = 200;
pub const OPERATIONS: &[&str] = &[
    "saved.v1.http.list",
    "saved.v1.http.select",
    "saved.v1.http.delete",
    "saved.v1.http.clear",
    "saved.v1.session.list",
    "saved.v1.session.rename",
    "saved.v1.operation.get",
];

const FILTER_FIELDS: &[&str] = &[
    "query",
    "method",
    "host",
    "status",
    "status_range",
    "since",
    "mime",
];
const UUID_PATTERN: &str =
    "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$";
const TOKEN_PATTERN: &str = "^[0-9a-f]{64}$";
// Enumerating Unicode White_Space avoids differing JavaScript/Rust meanings of
// \s, especially for U+0085 and U+FEFF.
const NONBLANK_PATTERN: &str =
    "[^\\u0009-\\u000D\\u0020\\u0085\\u00A0\\u1680\\u2000-\\u200A\\u2028\\u2029\\u202F\\u205F\\u3000]";
const NAME_PATTERN: &str = "^[^\\u0000-\\u001F\\u007F-\\u009F]*$";

static PATTERNS: LazyLock<Vec<(&str, regex::Regex)>> = LazyLock::new(|| {
    [UUID_PATTERN, TOKEN_PATTERN, NONBLANK_PATTERN, NAME_PATTERN]
        .into_iter()
        .map(|pattern| {
            (
                pattern,
                regex::Regex::new(pattern).expect("valid contract pattern"),
            )
        })
        .collect()
});

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpListInput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub continuation: Option<HttpContinuation>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpContinuation {
    pub session_id: Uuid,
    pub store_generation: Uuid,
    pub before_sequence: u64,
    pub limit: usize,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionListInput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after_id: Option<Uuid>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionContinuation {
    pub limit: usize,
    pub after_id: Uuid,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClearInput {
    pub session_id: Uuid,
    pub operation_id: Uuid,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RenameInput {
    pub session_id: Uuid,
    pub operation_id: Uuid,
    pub name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationGetInput {
    pub operation_id: Uuid,
}

pub fn is_write(name: &str) -> bool {
    matches!(
        name,
        "saved.v1.http.delete" | "saved.v1.http.clear" | "saved.v1.session.rename"
    )
}

/// Resolve the session identity for saved-data diagnostics and response binding.
/// A present top-level member keeps precedence even when invalid, so malformed
/// mixed inputs cannot substitute a continuation's session in their errors.
pub fn input_session_id(input: &Value) -> Option<Uuid> {
    input
        .get("session_id")
        .or_else(|| input.get("continuation")?.get("session_id"))
        .and_then(Value::as_str)
        .and_then(|text| Uuid::parse_str(text).ok())
}

/// Validate first, so serde's acceptance of null `Option`s cannot widen a contract.
pub fn parse_input<T: DeserializeOwned>(name: &str, value: &Value) -> Result<T, String> {
    validate_input(name, value)?;
    serde_json::from_value(value.clone()).map_err(|error| error.to_string())
}

/// The operation ID belongs to the receipt, not to the legacy selection type.
pub fn parse_selection(name: &str, value: &Value) -> Result<HistorySelection, String> {
    if !matches!(name, "saved.v1.http.select" | "saved.v1.http.delete") {
        return Err("operation does not accept a history selection".into());
    }
    validate_input(name, value)?;
    deserialize_selection(value)
}

fn deserialize_selection(value: &Value) -> Result<HistorySelection, String> {
    let mut selection = value.clone();
    if let Some(object) = selection.as_object_mut() {
        object.remove("operation_id");
    }
    serde_json::from_value(selection).map_err(|error| error.to_string())
}

pub fn input_schema(name: &str) -> Option<Value> {
    let schema = match name {
        "saved.v1.http.list" => {
            let mut schema = object(
                json!({
                    "session_id": uuid_schema(),
                    "limit": limit_schema(),
                    "continuation": http_continuation_schema()
                }),
                &[],
            );
            schema["not"] = json!({
                "required": ["continuation"],
                "anyOf": [{"required":["session_id"]},{"required":["limit"]}]
            });
            schema["description"] = json!("Lists saved HTTP summaries in descending sequence order. Omitted session_id resolves the active session once; continuation pins that session, store generation, and limit. A continuation cannot be combined with session_id or limit. A changed store generation expires a continuation with STALE_CONTINUATION.");
            schema
        }
        "saved.v1.http.select" => selection_schema(false),
        "saved.v1.http.delete" => selection_schema(true),
        "saved.v1.http.clear" => object(
            json!({"session_id":uuid_schema(),"operation_id":uuid_schema()}),
            &["session_id", "operation_id"],
        ),
        "saved.v1.session.list" => object(
            json!({"limit":limit_schema(),"after_id":uuid_schema()}),
            &[],
        ),
        "saved.v1.session.rename" => object(
            json!({
                "session_id":uuid_schema(),
                "operation_id":uuid_schema(),
                "name": {
                    "type":"string", "minLength":1, "maxLength":256,
                    "pattern": NAME_PATTERN,
                    "x-sniper-semantic":"session-name",
                    "description":"Must already be trimmed, contain a non-whitespace character and no Unicode control characters, and occupy at most 256 UTF-8 bytes.",
                    "x-sniper-maxUtf8Bytes":256
                }
            }),
            &["session_id", "operation_id", "name"],
        ),
        "saved.v1.operation.get" => {
            object(json!({"operation_id":uuid_schema()}), &["operation_id"])
        }
        _ => return None,
    };
    Some(document_schema(name, "input", schema))
}

pub fn output_schema(name: &str) -> Option<Value> {
    let schema = match name {
        "saved.v1.http.list" => {
            let mut schema = object(
                json!({
                    "contract_version":version_schema(), "session_id":uuid_schema(),
                    "items":{"type":"array","maxItems":MAX_LIMIT,"items":transaction_summary_schema()},
                    "limit":limit_schema(), "has_more":{"type":"boolean"},
                    "continuation":nullable(http_continuation_schema())
                }),
                &[
                    "contract_version",
                    "session_id",
                    "items",
                    "limit",
                    "has_more",
                    "continuation",
                ],
            );
            schema["allOf"] = json!([page_continuation_constraint()]);
            schema["x-sniper-semantic"] = json!("http-page");
            schema["description"] = json!("items contains at most limit rows. A non-null continuation repeats session_id and limit, and before_sequence equals the last item's sequence.");
            schema
        }
        "saved.v1.http.select" => {
            let mut schema = object(
                json!({
                    "contract_version":version_schema(),"session_id":uuid_schema(),
                    "count":unsigned_schema(0, u64::MAX),
                    "ids":{"type":"array","items":uuid_schema(),"uniqueItems":true},
                    "selection_token":{"type":"string","pattern":TOKEN_PATTERN}
                }),
                &[
                    "contract_version",
                    "session_id",
                    "count",
                    "ids",
                    "selection_token",
                ],
            );
            schema["x-sniper-semantic"] = json!("selection-count");
            schema["description"] = json!("count equals the number of unique IDs in ids.");
            schema
        }
        "saved.v1.http.delete" | "saved.v1.http.clear" | "saved.v1.session.rename" => object(
            json!({
                "contract_version":version_schema(),
                "receipt":receipt_schema(Some(name)),
                "replayed":{"type":"boolean"}
            }),
            &["contract_version", "receipt", "replayed"],
        ),
        "saved.v1.session.list" => {
            let mut schema = object(
                json!({
                    "contract_version":version_schema(),
                    "items":{"type":"array","maxItems":MAX_LIMIT,"items":session_summary_schema()},
                    "limit":limit_schema(),"has_more":{"type":"boolean"},
                    "continuation":nullable(session_continuation_schema())
                }),
                &[
                    "contract_version",
                    "items",
                    "limit",
                    "has_more",
                    "continuation",
                ],
            );
            schema["allOf"] = json!([page_continuation_constraint()]);
            schema["x-sniper-semantic"] = json!("session-page");
            schema["description"] = json!("items contains at most limit rows. A non-null continuation repeats limit and after_id equals the last item's id.");
            schema
        }
        "saved.v1.operation.get" => {
            let mut schema = object(
                json!({
                    "contract_version":version_schema(), "operation_id":uuid_schema(),
                    "found":{"type":"boolean"},"outcome":outcome_schema(),
                    "receipt":nullable(receipt_schema(None))
                }),
                &[
                    "contract_version",
                    "operation_id",
                    "found",
                    "outcome",
                    "receipt",
                ],
            );
            schema["oneOf"] = json!([
                {"properties":{"found":{"const":false},"outcome":{"const":"unknown"},"receipt":{"type":"null"}}},
                {"properties":{"found":{"const":true},"receipt":{"type":"object"}}}
            ]);
            schema["description"] = json!("An absent receipt is unknown, not proof that a mutation did not happen. When found, operation_id and outcome match the receipt.");
            schema
        }
        _ => return None,
    };
    Some(document_schema(name, "output", schema))
}

pub fn validate_input(name: &str, value: &Value) -> Result<(), String> {
    let schema =
        input_schema(name).ok_or_else(|| format!("unsupported saved operation: {name}"))?;
    validate_schema(&schema, value, "input")?;
    if matches!(name, "saved.v1.http.select" | "saved.v1.http.delete") {
        deserialize_selection(value)?
            .validate(name == "saved.v1.http.delete")
            .map_err(|message| message.replace("capture.http.select", "saved.v1.http.select"))?;
    }
    Ok(())
}

/// Validate successful operation data before a caller interprets an outcome.
/// A malformed mutation response is not evidence that the mutation failed.
pub fn validate_output(name: &str, value: &Value) -> Result<(), String> {
    let schema =
        output_schema(name).ok_or_else(|| format!("unsupported saved operation: {name}"))?;
    validate_schema(&schema, value, "output")?;
    match name {
        "saved.v1.http.list" | "saved.v1.session.list" => {
            let items = value["items"].as_array().expect("validated array");
            let limit = value["limit"].as_u64().expect("validated integer");
            if items.len() as u64 > limit {
                return Err("output.items exceeds output.limit".into());
            }
            if !value["continuation"].is_null() {
                let cursor = &value["continuation"];
                let last = items
                    .last()
                    .ok_or("output continuation requires a nonempty page")?;
                if cursor["limit"] != value["limit"] {
                    return Err("output continuation limit does not match the page".into());
                }
                if name == "saved.v1.http.list" {
                    if cursor["session_id"] != value["session_id"]
                        || cursor["before_sequence"] != last["sequence"]
                    {
                        return Err("output HTTP continuation does not match the page".into());
                    }
                } else if cursor["after_id"] != last["id"] {
                    return Err("output session continuation does not match the page".into());
                }
            }
        }
        "saved.v1.http.select" => {
            if value["count"].as_u64()
                != Some(value["ids"].as_array().expect("validated IDs").len() as u64)
            {
                return Err("output.count does not match output.ids".into());
            }
        }
        "saved.v1.operation.get" if value["found"] == json!(true) => {
            if value["operation_id"] != value["receipt"]["operation_id"]
                || value["outcome"] != value["receipt"]["outcome"]
            {
                return Err("output lookup does not match its receipt".into());
            }
        }
        _ => {}
    }
    Ok(())
}

/// Error envelopes are distinct from each operation's successful data schema.
pub fn error_schema() -> Value {
    document_schema(
        "saved.v1",
        "error",
        object(
            json!({
                "ok":{"type":"boolean","const":false},
                "contract_version":version_schema(),
                "error":object(
                    json!({
                        "code":{"type":"string","enum":[
                            "INVALID_INPUT","UNKNOWN_OPERATION","SESSION_NOT_FOUND",
                            "SESSION_UNAVAILABLE","SELECTION_MISMATCH","OPERATION_CONFLICT",
                            "STORAGE_UNAVAILABLE","OUTCOME_UNKNOWN","STALE_CONTINUATION"
                        ]},
                        "message":{"type":"string"},"outcome":outcome_schema(),
                        "operation_id":nullable(uuid_schema()),"session_id":nullable(uuid_schema()),
                        "retryable":{"type":"boolean","const":false}
                    }),
                    &["code", "message", "outcome", "operation_id", "session_id", "retryable"]
                )
            }),
            &["ok", "contract_version", "error"],
        ),
    )
}

fn selection_schema(deleting: bool) -> Value {
    let mut properties = Map::new();
    properties.insert("session_id".into(), uuid_schema());
    properties.insert(
        "ids".into(),
        json!({"type":"array","minItems":1,"items":uuid_schema()}),
    );
    for name in ["query", "method", "host", "mime"] {
        properties.insert(
            name.into(),
            json!({"type":"string","minLength":1,"pattern":NONBLANK_PATTERN}),
        );
    }
    properties.insert("status".into(), unsigned_schema(100, 599));
    properties.insert("status_range".into(), json!({
        "type":"string","minLength":1,"pattern":NONBLANK_PATTERN,
        "x-sniper-semantic":"ordered-status-range",
        "description":"After trimming Unicode whitespace: a lowercase class 1xx through 5xx, or two parseable u16 integers separated by '-', with 100 <= lower <= upper <= 599. Endpoint whitespace is trimmed. Cannot be combined with status."
    }));
    properties.insert("since".into(), json!({
        "type":"string","minLength":1,"pattern":NONBLANK_PATTERN,
        "x-sniper-semantic":"saved-history-since",
        "description":"After trimming Unicode whitespace: a valid calendar date parsed as %Y-%m-%d, an RFC3339 timestamp, or nonnegative ASCII integer followed by s, m, h, or d. Relative durations must fit checked signed 64-bit seconds and chrono date arithmetic."
    }));
    properties.insert(
        "selection_token".into(),
        json!({"type":"string","pattern":TOKEN_PATTERN}),
    );
    let mut required = vec!["session_id"];
    if deleting {
        properties.insert("operation_id".into(), uuid_schema());
        required.push("operation_id");
    }
    let presence: Vec<Value> = FILTER_FIELDS
        .iter()
        .map(|name| json!({"required":[name]}))
        .collect();
    let mut filtered = json!({"anyOf":presence,"not":{"required":["ids"]}});
    if deleting {
        filtered["required"] = json!(["selection_token"]);
    }
    let mut schema = object(Value::Object(properties), &required);
    schema["oneOf"] = json!([
        {"required":["ids"],"not":{"anyOf":presence}},
        filtered
    ]);
    schema["not"] = json!({"required":["status","status_range"]});
    schema["x-sniper-semantic"] = json!("history-selection");
    schema["description"] = json!("Pins one session and selects explicit nonempty IDs or nonempty validated filters, never both. Filtered deletion also requires the exact selection_token from saved.v1.http.select. Unknown members and explicit null are rejected.");
    schema
}

fn document_schema(name: &str, direction: &str, mut schema: Value) -> Value {
    schema["$schema"] = json!("https://json-schema.org/draft/2020-12/schema");
    schema["$id"] = json!(format!("urn:sniper:{name}:{direction}"));
    schema["title"] = json!(format!("{name} {direction}"));
    schema["x-sniper-contract-version"] = version_schema()["const"].clone();
    schema
}

fn object(properties: Value, required: &[&str]) -> Value {
    json!({"type":"object","properties":properties,"required":required,"additionalProperties":false})
}

fn version_schema() -> Value {
    json!({"type":"string","const":CONTRACT_VERSION})
}

fn uuid_schema() -> Value {
    json!({"type":"string","format":"uuid","pattern":UUID_PATTERN})
}

fn timestamp_schema() -> Value {
    json!({"type":"string","format":"date-time"})
}

fn unsigned_schema(minimum: u64, maximum: u64) -> Value {
    json!({
        "type":"integer","minimum":minimum,"maximum":maximum,
        "x-sniper-json-number-representation":"unsigned-integer",
        "description":"An unsigned JSON integer token, without a decimal point or exponent."
    })
}

fn limit_schema() -> Value {
    let mut schema = unsigned_schema(1, MAX_LIMIT as u64);
    schema["default"] = json!(DEFAULT_LIMIT);
    schema
}

fn nullable(schema: Value) -> Value {
    json!({"anyOf":[schema,{"type":"null"}]})
}

fn http_continuation_schema() -> Value {
    object(
        json!({"session_id":uuid_schema(),"store_generation":uuid_schema(),"before_sequence":unsigned_schema(1,u64::MAX),"limit":limit_schema()}),
        &["session_id", "store_generation", "before_sequence", "limit"],
    )
}

fn session_continuation_schema() -> Value {
    object(
        json!({"limit":limit_schema(),"after_id":uuid_schema()}),
        &["limit", "after_id"],
    )
}

fn page_continuation_constraint() -> Value {
    json!({"oneOf":[
        {"properties":{"has_more":{"const":false},"continuation":{"type":"null"}}},
        {"properties":{"has_more":{"const":true},"continuation":{"type":"object"}}}
    ]})
}

/// Mirrors serialized TransactionSummary, including omitted versus null fields.
pub fn transaction_summary_schema() -> Value {
    let number = unsigned_schema(0, u64::MAX);
    object(
        json!({
            "id":uuid_schema(),"started_at":timestamp_schema(),
            "kind":{"type":"string","enum":["http","tunnel"]},
            "sequence":number,"method":{"type":"string"},"scheme":{"type":"string"},
            "host":{"type":"string"},"path":{"type":"string"},
            "status":nullable(unsigned_schema(0,u16::MAX as u64)),
            "duration_ms":number,"request_bytes":number,"response_bytes":number,"note_count":number,
            "has_response":{"type":"boolean"},"content_type":nullable(json!({"type":"string"})),
            "is_websocket":{"type":"boolean"},"has_match_replace":{"type":"boolean"},
            "color_tag":{"type":"string"},"has_user_note":{"type":"boolean"},
            "note_preview":{"type":"string"},"annotation_revision":unsigned_schema(1,u64::MAX)
        }),
        &[
            "id",
            "started_at",
            "kind",
            "sequence",
            "method",
            "scheme",
            "host",
            "path",
            "status",
            "duration_ms",
            "request_bytes",
            "response_bytes",
            "note_count",
            "has_response",
            "content_type",
            "is_websocket",
            "has_match_replace",
            "has_user_note",
        ],
    )
}

pub fn session_summary_schema() -> Value {
    let number = unsigned_schema(0, u64::MAX);
    object(
        json!({
            "id":uuid_schema(),"name":{"type":"string"},
            "created_at":timestamp_schema(),"updated_at":timestamp_schema(),"last_opened_at":timestamp_schema(),
            "request_count":number,"websocket_count":number,"event_count":number,"fuzzer_count":number,"rule_count":number,
            "storage_path":{"type":"string"},"active":{"type":"boolean"}
        }),
        &[
            "id",
            "name",
            "created_at",
            "updated_at",
            "last_opened_at",
            "request_count",
            "websocket_count",
            "event_count",
            "fuzzer_count",
            "rule_count",
            "storage_path",
            "active",
        ],
    )
}

fn outcome_schema() -> Value {
    json!({"type":"string","enum":["applied","not_applied","unknown"]})
}

pub fn receipt_schema(operation: Option<&str>) -> Value {
    let operation_schema = match operation {
        Some(name) => json!({"type":"string","const":name}),
        None => {
            json!({"type":"string","enum":["saved.v1.http.delete","saved.v1.http.clear","saved.v1.session.rename"]})
        }
    };
    let mut schema = object(
        json!({
            "contract_version":version_schema(),"operation_id":uuid_schema(),"session_id":uuid_schema(),
            "operation":operation_schema,"outcome":outcome_schema(),
            "code":{"type":"string","enum":[
                "applied","pending","invalid_input","session_not_found","session_conflict",
                "selection_mismatch","persistence_failed","mutation_failed","receipt_persistence_failed","worker_failed"
            ]},
            "message":{"type":"string"},
            "result":{"oneOf":[
                object(json!({"kind":{"const":"http_deleted"},"deleted_count":unsigned_schema(0,u64::MAX)}), &["kind","deleted_count"]),
                object(json!({"kind":{"const":"http_cleared"},"deleted_count":unsigned_schema(0,u64::MAX)}), &["kind","deleted_count"]),
                object(json!({"kind":{"const":"session_renamed"},"session":session_summary_schema()}), &["kind","session"])
            ]},
            "created_at":timestamp_schema(),"completed_at":timestamp_schema()
        }),
        &[
            "contract_version",
            "operation_id",
            "session_id",
            "operation",
            "outcome",
            "code",
            "message",
            "created_at",
        ],
    );
    schema["allOf"] = json!([
        {"oneOf":[
            {"properties":{"outcome":{"const":"applied"},"code":{"const":"applied"}},"required":["result","completed_at"]},
            {"properties":{"outcome":{"const":"not_applied"},"code":{"not":{"enum":["applied","pending"]}}},"required":["completed_at"],"not":{"required":["result"]}},
            {"properties":{"outcome":{"const":"unknown"},"code":{"not":{"const":"applied"}}},"not":{"required":["result"]}}
        ]},
        {"oneOf":[
            {"properties":{"operation":{"const":"saved.v1.http.delete"},"result":{"properties":{"kind":{"const":"http_deleted"}}}}},
            {"properties":{"operation":{"const":"saved.v1.http.clear"},"result":{"properties":{"kind":{"const":"http_cleared"}}}}},
            {"properties":{"operation":{"const":"saved.v1.session.rename"},"result":{"properties":{"kind":{"const":"session_renamed"}}}}}
        ]}
    ]);
    schema
}

// Deliberately private and limited to the vocabulary emitted above. The same
// schema drives input checks and contract fixtures, avoiding two field lists.
fn validate_schema(schema: &Value, value: &Value, path: &str) -> Result<(), String> {
    if let Some(expected) = schema.get("const") {
        if value != expected {
            return Err(format!("{path} must equal {expected}"));
        }
    }
    if let Some(variants) = schema.get("enum").and_then(Value::as_array) {
        if !variants.contains(value) {
            return Err(format!("{path} is not an allowed value"));
        }
    }
    if let Some(kind) = schema.get("type").and_then(Value::as_str) {
        let matches = match kind {
            "object" => value.is_object(),
            "array" => value.is_array(),
            "string" => value.is_string(),
            "integer" => value.is_u64(),
            "boolean" => value.is_boolean(),
            "null" => value.is_null(),
            _ => return Err("unsupported internal schema type".into()),
        };
        if !matches {
            return Err(format!("{path} must be {kind}"));
        }
    }
    if let Some(object) = value.as_object() {
        if let Some(required) = schema.get("required").and_then(Value::as_array) {
            for field in required.iter().filter_map(Value::as_str) {
                if !object.contains_key(field) {
                    return Err(format!("{path}.{field} is required"));
                }
            }
        }
        let properties = schema.get("properties").and_then(Value::as_object);
        for (field, item) in object {
            if let Some(property) = properties.and_then(|properties| properties.get(field)) {
                validate_schema(property, item, &format!("{path}.{field}"))?;
            } else if schema.get("additionalProperties") == Some(&Value::Bool(false)) {
                return Err(format!("{path}.{field} is not supported"));
            }
        }
    }
    if let Some(items) = value.as_array() {
        if schema.get("uniqueItems") == Some(&Value::Bool(true)) {
            let mut seen = HashSet::with_capacity(items.len());
            for item in items {
                if !seen.insert(item.to_string()) {
                    return Err(format!("{path} contains duplicate items"));
                }
            }
        }
        for (keyword, too_many) in [("minItems", false), ("maxItems", true)] {
            if let Some(bound) = schema.get(keyword).and_then(Value::as_u64) {
                if (!too_many && items.len() < bound as usize)
                    || (too_many && items.len() > bound as usize)
                {
                    return Err(format!("{path} violates {keyword} {bound}"));
                }
            }
        }
        if let Some(item_schema) = schema.get("items") {
            for (index, item) in items.iter().enumerate() {
                validate_schema(item_schema, item, &format!("{path}[{index}]"))?;
            }
        }
    }
    if let Some(text) = value.as_str() {
        let length = text.chars().count() as u64;
        if schema
            .get("minLength")
            .and_then(Value::as_u64)
            .is_some_and(|min| length < min)
            || schema
                .get("maxLength")
                .and_then(Value::as_u64)
                .is_some_and(|max| length > max)
        {
            return Err(format!("{path} has an invalid length"));
        }
        if let Some(pattern) = schema.get("pattern").and_then(Value::as_str) {
            let regex = &PATTERNS
                .iter()
                .find(|(source, _)| *source == pattern)
                .expect("saved contract pattern is registered")
                .1;
            if !regex.is_match(text) {
                return Err(format!("{path} has an invalid format"));
            }
        }
        if schema.get("format").and_then(Value::as_str) == Some("date-time")
            && chrono::DateTime::parse_from_rfc3339(text).is_err()
        {
            return Err(format!("{path} must be an RFC3339 timestamp"));
        }
        if schema.get("format").and_then(Value::as_str) == Some("uuid")
            && Uuid::parse_str(text).is_err()
        {
            return Err(format!("{path} must be a UUID"));
        }
        if schema.get("x-sniper-semantic").and_then(Value::as_str) == Some("session-name")
            && (text.is_empty()
                || text.trim() != text
                || text.len() > 256
                || text.chars().any(char::is_control))
        {
            return Err(format!("{path} must be trimmed, nonblank, at most 256 UTF-8 bytes, and contain no control characters"));
        }
    }
    if let Some(number) = value.as_u64() {
        if schema
            .get("minimum")
            .and_then(Value::as_u64)
            .is_some_and(|min| number < min)
            || schema
                .get("maximum")
                .and_then(Value::as_u64)
                .is_some_and(|max| number > max)
        {
            return Err(format!("{path} is outside the allowed range"));
        }
    }
    if let Some(schemas) = schema.get("allOf").and_then(Value::as_array) {
        for schema in schemas {
            validate_schema(schema, value, path)?;
        }
    }
    for keyword in ["oneOf", "anyOf"] {
        if let Some(schemas) = schema.get(keyword).and_then(Value::as_array) {
            let matches = schemas
                .iter()
                .filter(|schema| validate_schema(schema, value, path).is_ok())
                .count();
            if matches == 0 || (keyword == "oneOf" && matches != 1) {
                return Err(format!(
                    "{path} does not match the permitted {keyword} shapes"
                ));
            }
        }
    }
    if let Some(excluded) = schema.get("not") {
        if validate_schema(excluded, value, path).is_ok() {
            return Err(format!("{path} combines incompatible fields"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        model::{TrafficKind, TransactionSummary},
        saved_data::{SavedApiError, SavedErrorCode},
        saved_operations::{
            SavedOperationCode, SavedOperationKind, SavedOperationOutcome, SavedOperationReceipt,
            SavedOperationResult,
        },
        session::SessionSummary,
    };
    use chrono::Utc;

    fn id() -> Uuid {
        Uuid::nil()
    }

    #[test]
    fn registry_only_contains_saved_data_contracts() {
        assert_eq!(OPERATIONS.len(), 7);
        for name in OPERATIONS {
            assert!(input_schema(name).is_some());
            assert!(output_schema(name).is_some());
        }
        assert!(input_schema("capture.replay.send").is_none());
        assert!(output_schema("saved.v2.http.list").is_none());
        assert!(validate_input("saved.v1.missing", &json!({})).is_err());
    }

    #[test]
    fn error_session_identity_uses_cursor_without_overriding_top_level_input() {
        let explicit = Uuid::nil();
        let pinned = Uuid::new_v4();
        assert_eq!(
            input_session_id(&json!({"session_id":explicit})),
            Some(explicit)
        );
        assert_eq!(
            input_session_id(&json!({"continuation":{"session_id":pinned}})),
            Some(pinned)
        );
        assert_eq!(
            input_session_id(&json!({"session_id":explicit,"continuation":{"session_id":pinned}})),
            Some(explicit)
        );
        for invalid in [json!(null), json!("invalid"), json!(12)] {
            assert_eq!(
                input_session_id(
                    &json!({"session_id":invalid,"continuation":{"session_id":pinned}})
                ),
                None
            );
        }
        for input in [
            json!(null),
            json!({}),
            json!({"continuation":null}),
            json!({"continuation":{"session_id":"invalid"}}),
        ] {
            assert_eq!(input_session_id(&input), None);
        }
    }

    #[test]
    fn lists_are_bounded_strict_and_continuations_are_reusable() {
        for value in [
            json!({}),
            json!({"session_id":id(),"limit":1}),
            json!({"limit":200}),
            json!({"continuation":{"session_id":id(),"store_generation":id(),"before_sequence":1,"limit":200}}),
        ] {
            assert!(
                validate_input("saved.v1.http.list", &value).is_ok(),
                "{value}"
            );
            let _: HttpListInput = parse_input("saved.v1.http.list", &value).unwrap();
        }
        for value in [
            json!(null),
            json!([]),
            json!({"limit":null}),
            json!({"session_id":null}),
            json!({"limit":0}),
            json!({"limit":201}),
            json!({"limit":1.5}),
            json!({"limit":1.0}),
            json!({"limit":-1}),
            json!({"limit":"2"}),
            json!({"query":"example"}),
            json!({"session_id":"not-a-uuid"}),
            json!({"session_id":id().simple().to_string()}),
            json!({"continuation":null}),
            json!({"continuation":{}}),
            json!({"continuation":{"session_id":id(),"before_sequence":1,"limit":1}}),
            json!({"continuation":{"session_id":id(),"store_generation":null,"before_sequence":1,"limit":1}}),
            json!({"continuation":{"session_id":id(),"store_generation":id(),"before_sequence":0,"limit":1}}),
            json!({"continuation":{"session_id":id(),"store_generation":id(),"before_sequence":1,"limit":1,"extra":true}}),
            json!({"session_id":id(),"continuation":{"session_id":id(),"store_generation":id(),"before_sequence":1,"limit":1}}),
            json!({"limit":1,"continuation":{"session_id":id(),"store_generation":id(),"before_sequence":1,"limit":1}}),
        ] {
            assert!(
                validate_input("saved.v1.http.list", &value).is_err(),
                "{value}"
            );
        }
        assert!(
            validate_input("saved.v1.session.list", &json!({"limit":2,"after_id":id()})).is_ok()
        );
        assert!(validate_input("saved.v1.session.list", &json!({"after_id":null})).is_err());
    }

    #[test]
    fn selections_share_strict_existing_filter_semantics() {
        for filter in [
            json!({"ids":[id()]}),
            json!({"host":"example.com"}),
            json!({"status":200}),
            json!({"status_range":"200-299"}),
            json!({"status_range":"4xx"}),
            json!({"since":"2024-01-01"}),
            json!({"since":"30m"}),
            json!({"since":"2024-01-01T00:00:00Z"}),
        ] {
            let mut value = json!({"session_id":id()});
            value
                .as_object_mut()
                .unwrap()
                .extend(filter.as_object().unwrap().clone());
            assert!(
                validate_input("saved.v1.http.select", &value).is_ok(),
                "{value}"
            );
            assert!(parse_selection("saved.v1.http.select", &value).is_ok());
        }
        for filter in [
            json!({}),
            json!({"ids":[]}),
            json!({"ids":["bad"]}),
            json!({"host":"\u{85}"}),
            json!({"host":null}),
            json!({"query":""}),
            json!({"status":600}),
            json!({"status":99}),
            json!({"status":200,"status_range":"2xx"}),
            json!({"status_range":"599-200"}),
            json!({"status_range":"6xx"}),
            json!({"since":"2024-02-30"}),
            json!({"since":"-1m"}),
            json!({"since":"999999999999999999999999d"}),
            json!({"ids":[id()],"host":"example.com"}),
            json!({"host":"example.com","selection_token":null}),
            json!({"host":"example.com","selection_token":"bad"}),
        ] {
            let mut value = json!({"session_id":id()});
            value
                .as_object_mut()
                .unwrap()
                .extend(filter.as_object().unwrap().clone());
            assert!(
                validate_input("saved.v1.http.select", &value).is_err(),
                "{value}"
            );
        }
        let mut value = json!({"session_id":id(),"operation_id":id(),"host":"example.com"});
        assert!(validate_input("saved.v1.http.delete", &value).is_err());
        value["selection_token"] = json!("a".repeat(64));
        assert!(parse_selection("saved.v1.http.delete", &value).is_ok());
        assert!(parse_selection(
            "saved.v1.http.delete",
            &json!({"session_id":id(),"operation_id":id(),"ids":[id()]})
        )
        .is_ok());
    }

    #[test]
    fn mutations_require_ids_and_names_have_byte_and_unicode_limits() {
        for name in ["a", &"é".repeat(128)] {
            assert!(validate_input(
                "saved.v1.session.rename",
                &json!({"session_id":id(),"operation_id":id(),"name":name})
            )
            .is_ok());
        }
        for name in [
            "",
            " ",
            " name",
            "name ",
            "bad\nname",
            "bad\u{85}name",
            &"é".repeat(129),
            &"a".repeat(257),
        ] {
            assert!(
                validate_input(
                    "saved.v1.session.rename",
                    &json!({"session_id":id(),"operation_id":id(),"name":name})
                )
                .is_err(),
                "{name:?}"
            );
        }
        for value in [
            json!({"session_id":id()}),
            json!({"operation_id":id()}),
            json!({"session_id":id(),"operation_id":null}),
            json!({"session_id":id(),"operation_id":id(),"extra":1}),
        ] {
            assert!(validate_input("saved.v1.http.clear", &value).is_err());
        }
        assert!(validate_input("saved.v1.operation.get", &json!({"operation_id":id()})).is_ok());
    }

    fn session() -> SessionSummary {
        SessionSummary {
            id: id(),
            name: "Saved examples".into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_opened_at: Utc::now(),
            request_count: 0,
            websocket_count: 0,
            event_count: 0,
            fuzzer_count: 0,
            rule_count: 0,
            storage_path: "/tmp/example-session".into(),
            active: false,
        }
    }

    #[test]
    fn real_serialized_summaries_match_complete_output_schemas() {
        let mut summary = TransactionSummary {
            id: id(),
            started_at: Utc::now(),
            kind: TrafficKind::Http,
            sequence: 1,
            method: "GET".into(),
            scheme: "https".into(),
            host: "example.com".into(),
            path: "/".into(),
            status: None,
            duration_ms: 0,
            request_bytes: 0,
            response_bytes: 0,
            note_count: 0,
            has_response: false,
            content_type: None,
            is_websocket: false,
            has_match_replace: false,
            color_tag: None,
            has_user_note: false,
            note_preview: None,
            annotation_revision: 0,
        };
        for annotated in [false, true] {
            if annotated {
                summary.color_tag = Some("blue".into());
                summary.note_preview = Some("Example".into());
                summary.annotation_revision = 1;
            }
            let value = json!({"contract_version":CONTRACT_VERSION,"session_id":id(),"items":[summary],"limit":1,"has_more":false,"continuation":null});
            validate_schema(
                &output_schema("saved.v1.http.list").unwrap(),
                &value,
                "output",
            )
            .unwrap();
        }
        let value = json!({"contract_version":CONTRACT_VERSION,"items":[session()],"limit":1,"has_more":true,"continuation":{"limit":1,"after_id":id()}});
        validate_schema(
            &output_schema("saved.v1.session.list").unwrap(),
            &value,
            "output",
        )
        .unwrap();
        validate_input("saved.v1.session.list", &value["continuation"]).unwrap();
        let value = json!({"contract_version":CONTRACT_VERSION,"session_id":id(),"count":0,"ids":[],"selection_token":"a".repeat(64)});
        validate_schema(
            &output_schema("saved.v1.http.select").unwrap(),
            &value,
            "output",
        )
        .unwrap();
    }

    #[test]
    fn receipts_and_unknown_lookups_have_precise_outputs() {
        for (operation, result) in [
            (
                "saved.v1.http.delete",
                json!({"kind":"http_deleted","deleted_count":2}),
            ),
            (
                "saved.v1.http.clear",
                json!({"kind":"http_cleared","deleted_count":0}),
            ),
            (
                "saved.v1.session.rename",
                json!({"kind":"session_renamed","session":session()}),
            ),
        ] {
            let receipt = json!({"contract_version":CONTRACT_VERSION,"operation_id":id(),"session_id":id(),
                "operation":operation,"outcome":"applied","code":"applied","message":"Saved data updated.",
                "result":result,"created_at":Utc::now(),"completed_at":Utc::now()});
            let envelope =
                json!({"contract_version":CONTRACT_VERSION,"receipt":receipt,"replayed":false});
            validate_output(operation, &envelope).unwrap();
            for field in [
                "operation_id",
                "session_id",
                "operation",
                "outcome",
                "code",
                "result",
                "completed_at",
            ] {
                let mut incomplete = envelope.clone();
                incomplete["receipt"].as_object_mut().unwrap().remove(field);
                assert!(
                    validate_output(operation, &incomplete).is_err(),
                    "missing {field}"
                );
            }
            let mut surplus = envelope.clone();
            surplus["receipt"]["unexpected"] = json!(true);
            assert!(validate_output(operation, &surplus).is_err());
            let found = json!({"contract_version":CONTRACT_VERSION,"operation_id":id(),"found":true,"outcome":"applied","receipt":receipt});
            validate_output("saved.v1.operation.get", &found).unwrap();
            let mut mismatched = found;
            mismatched["outcome"] = json!("unknown");
            assert!(validate_output("saved.v1.operation.get", &mismatched).is_err());
        }
        let mut absent = json!({"contract_version":CONTRACT_VERSION,"operation_id":id(),"found":false,"outcome":"unknown","receipt":null});
        let schema = output_schema("saved.v1.operation.get").unwrap();
        validate_schema(&schema, &absent, "output").unwrap();
        absent["outcome"] = json!("not_applied");
        assert!(validate_schema(&schema, &absent, "output").is_err());
    }

    #[test]
    fn real_receipts_and_errors_match_schemas_in_every_outcome() {
        let mut receipt = SavedOperationReceipt {
            contract_version: CONTRACT_VERSION.into(),
            operation_id: id(),
            session_id: id(),
            operation: SavedOperationKind::HttpDelete,
            outcome: SavedOperationOutcome::Applied,
            code: SavedOperationCode::Applied,
            message: SavedOperationCode::Applied.message().into(),
            result: Some(SavedOperationResult::HttpDeleted { deleted_count: 2 }),
            created_at: Utc::now(),
            completed_at: Some(Utc::now()),
        };
        let schema = receipt_schema(Some("saved.v1.http.delete"));
        validate_schema(&schema, &serde_json::to_value(&receipt).unwrap(), "receipt").unwrap();
        receipt.outcome = SavedOperationOutcome::NotApplied;
        receipt.code = SavedOperationCode::SelectionMismatch;
        receipt.message = receipt.code.message().into();
        receipt.result = None;
        validate_schema(&schema, &serde_json::to_value(&receipt).unwrap(), "receipt").unwrap();
        receipt.outcome = SavedOperationOutcome::Unknown;
        receipt.code = SavedOperationCode::Pending;
        receipt.message = receipt.code.message().into();
        receipt.completed_at = None;
        validate_schema(&schema, &serde_json::to_value(&receipt).unwrap(), "receipt").unwrap();
        receipt.result = Some(SavedOperationResult::HttpDeleted { deleted_count: 2 });
        assert!(
            validate_schema(&schema, &serde_json::to_value(&receipt).unwrap(), "receipt").is_err()
        );

        for operation_id in [None, Some(id())] {
            let error = SavedApiError {
                code: SavedErrorCode::InvalidInput,
                message: "Invalid saved-data input".into(),
                outcome: SavedOperationOutcome::NotApplied,
                operation_id,
                session_id: None,
                retryable: false,
            };
            let mut value = json!({"ok":false,"contract_version":CONTRACT_VERSION,"error":error});
            validate_schema(&error_schema(), &value, "error envelope").unwrap();
            value["error"]["retryable"] = json!(true);
            assert!(validate_schema(&error_schema(), &value, "error envelope").is_err());
        }
    }
}
