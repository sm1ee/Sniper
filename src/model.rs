use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, Utc};
use http::HeaderMap;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrafficKind {
    Http,
    Tunnel,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BodyEncoding {
    Utf8,
    Base64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HeaderRecord {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EditableRequest {
    pub scheme: String,
    pub host: String,
    pub method: String,
    pub path: String,
    pub headers: Vec<HeaderRecord>,
    pub body: String,
    pub body_encoding: BodyEncoding,
    pub preview_truncated: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RequestTargetOverride {
    pub scheme: String,
    pub host: String,
    pub port: String,
}

impl EditableRequest {
    pub fn from_headers_and_body(
        scheme: impl Into<String>,
        host: impl Into<String>,
        method: impl Into<String>,
        path: impl Into<String>,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Self {
        let content_type = headers
            .get(http::header::CONTENT_TYPE)
            .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned());
        let body_encoding = if is_textual_body(content_type.as_deref(), body) {
            BodyEncoding::Utf8
        } else {
            BodyEncoding::Base64
        };

        Self {
            scheme: scheme.into(),
            host: host.into(),
            method: method.into(),
            path: path.into(),
            headers: header_records(headers),
            body: match body_encoding {
                BodyEncoding::Utf8 => String::from_utf8_lossy(body).into_owned(),
                BodyEncoding::Base64 => STANDARD.encode(body),
            },
            body_encoding,
            preview_truncated: false,
        }
    }

    pub fn from_message_record(
        scheme: impl Into<String>,
        host: impl Into<String>,
        method: impl Into<String>,
        path: impl Into<String>,
        message: &MessageRecord,
    ) -> Self {
        Self {
            scheme: scheme.into(),
            host: host.into(),
            method: method.into(),
            path: path.into(),
            headers: message.headers.clone(),
            body: message.body_preview.clone(),
            body_encoding: message.body_encoding.clone(),
            preview_truncated: message.preview_truncated,
        }
    }

    pub fn body_bytes(&self) -> Vec<u8> {
        match self.body_encoding {
            BodyEncoding::Utf8 => self.body.as_bytes().to_vec(),
            BodyEncoding::Base64 => STANDARD.decode(self.body.as_bytes()).unwrap_or_default(),
        }
    }

    pub fn content_type(&self) -> Option<String> {
        self.headers
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case("content-type"))
            .map(|header| header.value.clone())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageRecord {
    pub headers: Vec<HeaderRecord>,
    pub body_preview: String,
    pub body_encoding: BodyEncoding,
    pub body_size: usize,
    pub preview_truncated: bool,
    pub content_type: Option<String>,
}

impl MessageRecord {
    pub fn from_headers_and_body(headers: &HeaderMap, body: &[u8], max_preview: usize) -> Self {
        let content_type = headers
            .get(http::header::CONTENT_TYPE)
            .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned());
        let preview_len = max_preview.min(body.len());
        let preview_bytes = &body[..preview_len];
        let textual = is_textual_body(content_type.as_deref(), preview_bytes);
        let body_preview = if textual {
            String::from_utf8_lossy(preview_bytes).into_owned()
        } else {
            STANDARD.encode(preview_bytes)
        };

        Self {
            headers: header_records(headers),
            body_preview,
            body_encoding: if textual {
                BodyEncoding::Utf8
            } else {
                BodyEncoding::Base64
            },
            body_size: body.len(),
            preview_truncated: body.len() > max_preview,
            content_type,
        }
    }

    pub fn body_bytes(&self) -> Vec<u8> {
        match self.body_encoding {
            BodyEncoding::Utf8 => self.body_preview.as_bytes().to_vec(),
            BodyEncoding::Base64 => STANDARD
                .decode(self.body_preview.as_bytes())
                .unwrap_or_default(),
        }
    }

    pub fn header_value(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case(name))
            .map(|header| header.value.as_str())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionRecord {
    pub id: Uuid,
    pub started_at: DateTime<Utc>,
    pub kind: TrafficKind,
    pub method: String,
    pub scheme: String,
    pub host: String,
    pub path: String,
    pub status: Option<u16>,
    pub duration_ms: u64,
    pub request: MessageRecord,
    pub response: Option<MessageRecord>,
    pub notes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub color_tag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_note: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_request: Option<MessageRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_response: Option<MessageRecord>,
}

impl TransactionRecord {
    pub fn http(
        started_at: DateTime<Utc>,
        method: String,
        scheme: String,
        host: String,
        path: String,
        status: Option<u16>,
        duration_ms: u64,
        request: MessageRecord,
        response: Option<MessageRecord>,
        notes: Vec<String>,
        original_request: Option<MessageRecord>,
        original_response: Option<MessageRecord>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            started_at,
            kind: TrafficKind::Http,
            method,
            scheme,
            host,
            path,
            status,
            duration_ms,
            request,
            response,
            notes,
            color_tag: None,
            user_note: None,
            original_request,
            original_response,
        }
    }

    pub fn tunnel(
        started_at: DateTime<Utc>,
        host: String,
        status: Option<u16>,
        duration_ms: u64,
        request: MessageRecord,
        notes: Vec<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            started_at,
            kind: TrafficKind::Tunnel,
            method: "CONNECT".to_string(),
            scheme: "tcp".to_string(),
            host,
            path: String::new(),
            status,
            duration_ms,
            request,
            response: None,
            notes,
            color_tag: None,
            user_note: None,
            original_request: None,
            original_response: None,
        }
    }

    pub fn summary(&self) -> TransactionSummary {
        TransactionSummary {
            id: self.id,
            started_at: self.started_at,
            kind: self.kind.clone(),
            method: self.method.clone(),
            scheme: self.scheme.clone(),
            host: self.host.clone(),
            path: self.path.clone(),
            status: self.status,
            duration_ms: self.duration_ms,
            request_bytes: self.request.body_size,
            response_bytes: self
                .response
                .as_ref()
                .map_or(0, |response| response.body_size),
            note_count: self.notes.len(),
            has_response: self.response.is_some(),
            content_type: self
                .response
                .as_ref()
                .and_then(|message| message.content_type.clone())
                .or_else(|| self.request.content_type.clone()),
            is_websocket: self.is_websocket(),
            has_match_replace: self.original_request.is_some() || self.original_response.is_some(),
            color_tag: self.color_tag.clone(),
            has_user_note: self.user_note.is_some(),
        }
    }

    pub fn editable_request(&self) -> EditableRequest {
        EditableRequest::from_message_record(
            self.scheme.clone(),
            self.host.clone(),
            self.method.clone(),
            self.path.clone(),
            &self.request,
        )
    }

    pub fn is_websocket(&self) -> bool {
        self.status == Some(101)
            || self
                .request
                .header_value("upgrade")
                .map(|value| value.eq_ignore_ascii_case("websocket"))
                .unwrap_or(false)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionSummary {
    pub id: Uuid,
    pub started_at: DateTime<Utc>,
    pub kind: TrafficKind,
    pub method: String,
    pub scheme: String,
    pub host: String,
    pub path: String,
    pub status: Option<u16>,
    pub duration_ms: u64,
    pub request_bytes: usize,
    pub response_bytes: usize,
    pub note_count: usize,
    pub has_response: bool,
    pub content_type: Option<String>,
    pub is_websocket: bool,
    #[serde(default)]
    pub has_match_replace: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub color_tag: Option<String>,
    #[serde(default)]
    pub has_user_note: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebSocketFrameDirection {
    ClientToServer,
    ServerToClient,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebSocketFrameKind {
    Text,
    Binary,
    Ping,
    Pong,
    Close,
    Other,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WebSocketFrameRecord {
    pub index: usize,
    pub captured_at: DateTime<Utc>,
    pub direction: WebSocketFrameDirection,
    pub kind: WebSocketFrameKind,
    pub body_preview: String,
    pub body_encoding: BodyEncoding,
    pub body_size: usize,
    pub preview_truncated: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WebSocketSessionRecord {
    pub id: Uuid,
    pub started_at: DateTime<Utc>,
    pub closed_at: Option<DateTime<Utc>>,
    pub duration_ms: Option<u64>,
    pub scheme: String,
    pub host: String,
    pub path: String,
    pub status: Option<u16>,
    pub request: MessageRecord,
    pub response: Option<MessageRecord>,
    pub frames: Vec<WebSocketFrameRecord>,
    pub notes: Vec<String>,
}

impl WebSocketSessionRecord {
    pub fn summary(&self) -> WebSocketSessionSummary {
        WebSocketSessionSummary {
            id: self.id,
            started_at: self.started_at,
            closed_at: self.closed_at,
            duration_ms: self.duration_ms,
            scheme: self.scheme.clone(),
            host: self.host.clone(),
            path: self.path.clone(),
            status: self.status,
            frame_count: self.frames.len(),
            note_count: self.notes.len(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WebSocketSessionSummary {
    pub id: Uuid,
    pub started_at: DateTime<Utc>,
    pub closed_at: Option<DateTime<Utc>>,
    pub duration_ms: Option<u64>,
    pub scheme: String,
    pub host: String,
    pub path: String,
    pub status: Option<u16>,
    pub frame_count: usize,
    pub note_count: usize,
}

fn header_records(headers: &HeaderMap) -> Vec<HeaderRecord> {
    headers
        .iter()
        .map(|(name, value)| HeaderRecord {
            name: name.as_str().to_string(),
            value: String::from_utf8_lossy(value.as_bytes()).into_owned(),
        })
        .collect()
}

fn is_textual_body(content_type: Option<&str>, sample: &[u8]) -> bool {
    if sample.is_empty() {
        return true;
    }

    if let Some(content_type) = content_type {
        let normalized = content_type.to_ascii_lowercase();
        if normalized.starts_with("text/")
            || normalized.contains("json")
            || normalized.contains("xml")
            || normalized.contains("javascript")
            || normalized.contains("x-www-form-urlencoded")
            || normalized.contains("graphql")
            || normalized.contains("yaml")
        {
            return true;
        }
    }

    std::str::from_utf8(sample).is_ok() && !sample.contains(&0)
}
