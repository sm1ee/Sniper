use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, Utc};
use http::HeaderMap;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, io::Read};
use uuid::Uuid;

const MAX_DECODED_CONTENT_BYTES: usize = 16 * 1024 * 1024;
const CLI_ANNOTATION_CLIENT_ID_PREFIX: &str = "sniper-cli:";

pub(crate) fn compact_annotation_client_versions_for_insert(
    versions: &mut BTreeMap<String, u64>,
    client_id: &str,
) {
    if client_id.starts_with(CLI_ANNOTATION_CLIENT_ID_PREFIX) {
        versions.retain(|stored_client_id, _| {
            !stored_client_id.starts_with(CLI_ANNOTATION_CLIENT_ID_PREFIX)
                || stored_client_id == client_id
        });
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrafficKind {
    #[default]
    Http,
    Tunnel,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BodyEncoding {
    #[default]
    Utf8,
    Base64,
}

#[derive(PartialEq, Clone, Debug, Serialize, Deserialize)]
pub struct HeaderRecord {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EditableRequest {
    pub scheme: String,
    pub host: String,
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub headers: Vec<HeaderRecord>,
    #[serde(default)]
    pub body: String,
    #[serde(default)]
    pub body_encoding: BodyEncoding,
    #[serde(default)]
    pub preview_truncated: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EditableResponse {
    pub status: u16,
    pub headers: Vec<HeaderRecord>,
    pub body: String,
    pub body_encoding: BodyEncoding,
}

impl EditableResponse {
    pub fn from_status_headers_body(status: u16, headers: &HeaderMap, body: &[u8]) -> Self {
        let content_type = headers
            .get(http::header::CONTENT_TYPE)
            .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned());

        // Decompress body based on Content-Encoding header (gzip, deflate, br)
        let decoded_body = decode_content_encoding(headers, body);
        let content_decoded = decoded_body.is_some();
        let body_ref = decoded_body.as_deref().unwrap_or(body);

        let body_encoding = if is_textual_body(content_type.as_deref(), body_ref) {
            BodyEncoding::Utf8
        } else {
            BodyEncoding::Base64
        };

        Self {
            status,
            headers: header_records_for_decoded_body(headers, content_decoded),
            body: match body_encoding {
                BodyEncoding::Utf8 => String::from_utf8_lossy(body_ref).into_owned(),
                BodyEncoding::Base64 => STANDARD.encode(body_ref),
            },
            body_encoding,
        }
    }

    pub fn body_bytes(&self) -> Vec<u8> {
        self.try_body_bytes().unwrap_or_default()
    }

    pub fn try_body_bytes(&self) -> Result<Vec<u8>, base64::DecodeError> {
        match self.body_encoding {
            BodyEncoding::Utf8 => Ok(self.body.as_bytes().to_vec()),
            BodyEncoding::Base64 => STANDARD.decode(self.body.as_bytes()),
        }
    }
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

        // Decompress body based on Content-Encoding header (gzip, deflate, br)
        let decoded_body = decode_content_encoding(headers, body);
        let content_decoded = decoded_body.is_some();
        let body_ref = decoded_body.as_deref().unwrap_or(body);

        let body_encoding = if is_textual_body(content_type.as_deref(), body_ref) {
            BodyEncoding::Utf8
        } else {
            BodyEncoding::Base64
        };

        let host = host.into();
        let mut headers = header_records_for_decoded_body(headers, content_decoded);
        // HTTP/2 sends the host as the :authority pseudo-header which hyper
        // places in the URI authority rather than in the headers map.  Ensure a
        // Host header is always present so match-replace rules and UI display
        // work consistently.
        if !headers.iter().any(|h| h.name.eq_ignore_ascii_case("host")) && !host.is_empty() {
            headers.insert(
                0,
                HeaderRecord {
                    name: "host".to_string(),
                    value: host.clone(),
                },
            );
        }

        Self {
            scheme: scheme.into(),
            host,
            method: method.into(),
            path: path.into(),
            headers,
            body: match body_encoding {
                BodyEncoding::Utf8 => String::from_utf8_lossy(body_ref).into_owned(),
                BodyEncoding::Base64 => STANDARD.encode(body_ref),
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
            headers: header_records_from_message(message),
            body: message.body_preview.clone(),
            body_encoding: message.body_encoding.clone(),
            preview_truncated: message.preview_truncated,
        }
    }

    pub fn body_bytes(&self) -> Vec<u8> {
        self.try_body_bytes().unwrap_or_default()
    }

    pub fn try_body_bytes(&self) -> Result<Vec<u8>, base64::DecodeError> {
        match self.body_encoding {
            BodyEncoding::Utf8 => Ok(self.body.as_bytes().to_vec()),
            BodyEncoding::Base64 => STANDARD.decode(self.body.as_bytes()),
        }
    }

    pub fn content_type(&self) -> Option<String> {
        self.headers
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case("content-type"))
            .map(|header| header.value.clone())
    }

    pub fn normalize_content_length(&mut self) {
        if !self
            .headers
            .iter()
            .any(|header| header.name.eq_ignore_ascii_case("content-length"))
        {
            return;
        }
        let Ok(body) = self.try_body_bytes() else {
            return;
        };
        normalize_content_length_records(&mut self.headers, body.len());
    }
}

fn normalize_content_length_records(headers: &mut Vec<HeaderRecord>, body_len: usize) {
    let mut had_content_length = false;
    headers.retain(|header| {
        if header.name.eq_ignore_ascii_case("content-length") {
            had_content_length = true;
            false
        } else {
            true
        }
    });
    if had_content_length {
        headers.push(HeaderRecord {
            name: "Content-Length".to_string(),
            value: body_len.to_string(),
        });
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageRecord {
    #[serde(default)]
    pub headers: Vec<HeaderRecord>,
    #[serde(default)]
    pub body_preview: String,
    #[serde(default)]
    pub body_encoding: BodyEncoding,
    #[serde(default)]
    pub body_size: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decoded_body_size: Option<usize>,
    #[serde(default)]
    pub preview_truncated: bool,
    pub content_type: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub content_decoded: bool,
}

impl MessageRecord {
    pub fn from_headers_and_body(headers: &HeaderMap, body: &[u8], max_preview: usize) -> Self {
        let content_type = headers
            .get(http::header::CONTENT_TYPE)
            .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned());

        // Decompress body based on Content-Encoding header
        let decoded_body = decode_content_encoding(headers, body);
        let content_decoded = decoded_body.is_some();
        let body_ref = decoded_body.as_deref().unwrap_or(body);
        let original_size = body.len();
        let decoded_body_size = decoded_body.as_ref().map(|body| body.len());

        let preview_len = max_preview.min(body_ref.len());
        let preview_bytes = &body_ref[..preview_len];
        let preview_truncated = body_ref.len() > max_preview;
        let textual =
            is_textual_body_preview(content_type.as_deref(), preview_bytes, preview_truncated);
        let preview_bytes = if textual {
            &preview_bytes[..utf8_preview_len(preview_bytes)]
        } else {
            preview_bytes
        };
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
            body_size: original_size,
            decoded_body_size,
            preview_truncated,
            content_type,
            content_decoded,
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
    #[serde(default)]
    pub kind: TrafficKind,
    /// Stable capture sequence number (1-based, monotonically increasing).
    #[serde(default)]
    pub sequence: u64,
    pub method: String,
    pub scheme: String,
    pub host: String,
    pub path: String,
    pub status: Option<u16>,
    #[serde(default)]
    pub duration_ms: u64,
    pub request: MessageRecord,
    pub response: Option<MessageRecord>,
    #[serde(default)]
    pub notes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub color_tag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_note: Option<String>,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub annotation_revision: u64,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotation_client_versions: BTreeMap<String, u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_request: Option<MessageRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_response: Option<MessageRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_http_version: Option<String>,
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
            sequence: 0,
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
            annotation_revision: 0,
            annotation_client_versions: BTreeMap::new(),
            original_request,
            original_response,
            http_version: None,
            response_http_version: None,
        }
    }

    pub fn with_request_http_version(mut self, version: http::Version) -> Self {
        self.http_version = Some(format_http_version(version));
        self
    }

    pub fn with_response_http_version(mut self, version: http::Version) -> Self {
        self.response_http_version = Some(format_http_version(version));
        self
    }

    pub fn with_http_version(mut self, version: http::Version) -> Self {
        self.http_version = Some(format_http_version(version));
        self
    }

    pub fn response_http_version(&self) -> Option<&str> {
        self.response_http_version
            .as_deref()
            .or(self.http_version.as_deref())
    }

    pub fn with_response(mut self, response: MessageRecord) -> Self {
        self.response = Some(response);
        self
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
            sequence: 0,
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
            annotation_revision: 0,
            annotation_client_versions: BTreeMap::new(),
            original_request: None,
            original_response: None,
            http_version: None,
            response_http_version: None,
        }
    }

    pub fn summary(&self) -> TransactionSummary {
        TransactionSummary {
            id: self.id,
            started_at: self.started_at,
            kind: self.kind.clone(),
            sequence: self.sequence,
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
            note_preview: note_preview(self.user_note.as_ref(), &self.notes),
            annotation_revision: self.annotation_revision,
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
        self.status == Some(101) && request_has_websocket_upgrade_headers(&self.request)
    }
}

fn request_has_websocket_upgrade_headers(request: &MessageRecord) -> bool {
    request_header_values_contain_token(request, "upgrade", "websocket")
        && request_header_values_contain_token(request, "connection", "upgrade")
}

fn request_header_values_contain_token(request: &MessageRecord, name: &str, token: &str) -> bool {
    request
        .headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case(name))
        .any(|header| header_value_contains_token(&header.value, token))
}

fn header_value_contains_token(value: &str, token: &str) -> bool {
    value
        .split(',')
        .any(|part| part.trim().eq_ignore_ascii_case(token))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionSummary {
    pub id: Uuid,
    pub started_at: DateTime<Utc>,
    pub kind: TrafficKind,
    #[serde(default)]
    pub sequence: u64,
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
    /// First line of the operator note, else the first recorded note, so the
    /// history table can show what a note says instead of only how many exist.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note_preview: Option<String>,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub annotation_revision: u64,
}

/// Longest note text carried in a summary. Summaries are sent for every row in
/// the history table, so the full note stays in the record and only a short
/// lead-in travels with the list.
const NOTE_PREVIEW_LIMIT: usize = 200;

fn note_preview(user_note: Option<&String>, notes: &[String]) -> Option<String> {
    let source = user_note
        .map(String::as_str)
        .filter(|note| !note.trim().is_empty())
        .or_else(|| {
            notes
                .iter()
                .map(String::as_str)
                .find(|note| !note.trim().is_empty())
        })?;
    let flattened = source.split_whitespace().collect::<Vec<_>>().join(" ");
    if flattened.is_empty() {
        return None;
    }
    Some(truncate_chars(&flattened, NOTE_PREVIEW_LIMIT))
}

fn truncate_chars(value: &str, limit: usize) -> String {
    if value.chars().count() <= limit {
        return value.to_string();
    }
    let mut out: String = value.chars().take(limit).collect();
    out.push('…');
    out
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
    #[serde(default)]
    pub index: usize,
    pub captured_at: DateTime<Utc>,
    pub direction: WebSocketFrameDirection,
    pub kind: WebSocketFrameKind,
    #[serde(default)]
    pub body_preview: String,
    #[serde(default)]
    pub body_encoding: BodyEncoding,
    #[serde(default)]
    pub body_size: usize,
    #[serde(default)]
    pub preview_truncated: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WebSocketSessionRecord {
    pub id: Uuid,
    #[serde(default)]
    pub sequence: u64,
    pub started_at: DateTime<Utc>,
    pub closed_at: Option<DateTime<Utc>>,
    pub duration_ms: Option<u64>,
    pub scheme: String,
    pub host: String,
    pub path: String,
    pub status: Option<u16>,
    pub request: MessageRecord,
    pub response: Option<MessageRecord>,
    #[serde(default)]
    pub frames: Vec<WebSocketFrameRecord>,
    #[serde(default)]
    pub notes: Vec<String>,
}

impl WebSocketSessionRecord {
    pub fn summary(&self) -> WebSocketSessionSummary {
        WebSocketSessionSummary {
            id: self.id,
            sequence: self.sequence,
            started_at: self.started_at,
            closed_at: self.closed_at,
            duration_ms: self.duration_ms,
            scheme: self.scheme.clone(),
            host: self.host.clone(),
            path: self.path.clone(),
            status: self.status,
            frame_count: websocket_total_frame_count(&self.frames),
            retained_frame_count: self.frames.len(),
            last_frame_index: self.frames.last().map(|frame| frame.index),
            note_count: self.notes.len(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WebSocketSessionSummary {
    pub id: Uuid,
    #[serde(default)]
    pub sequence: u64,
    pub started_at: DateTime<Utc>,
    pub closed_at: Option<DateTime<Utc>>,
    pub duration_ms: Option<u64>,
    pub scheme: String,
    pub host: String,
    pub path: String,
    pub status: Option<u16>,
    pub frame_count: usize,
    #[serde(default)]
    pub retained_frame_count: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_frame_index: Option<usize>,
    pub note_count: usize,
}

pub fn websocket_total_frame_count(frames: &[WebSocketFrameRecord]) -> usize {
    frames
        .iter()
        .map(|frame| frame.index)
        .max()
        .map(|last_index| last_index.saturating_add(1).max(frames.len()))
        .unwrap_or(0)
}

pub fn format_http_version(version: http::Version) -> String {
    match version {
        http::Version::HTTP_09 => "HTTP/0.9".to_string(),
        http::Version::HTTP_10 => "HTTP/1.0".to_string(),
        http::Version::HTTP_11 => "HTTP/1.1".to_string(),
        http::Version::HTTP_2 => "HTTP/2".to_string(),
        http::Version::HTTP_3 => "HTTP/3".to_string(),
        _ => format!("{version:?}"),
    }
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

fn header_records_for_decoded_body(
    headers: &HeaderMap,
    content_decoded: bool,
) -> Vec<HeaderRecord> {
    let records = header_records(headers);
    if content_decoded {
        sanitize_decoded_body_headers(records)
    } else {
        records
    }
}

fn header_records_from_message(message: &MessageRecord) -> Vec<HeaderRecord> {
    if message.content_decoded {
        sanitize_decoded_body_headers(message.headers.clone())
    } else {
        message.headers.clone()
    }
}

fn sanitize_decoded_body_headers(headers: Vec<HeaderRecord>) -> Vec<HeaderRecord> {
    headers
        .into_iter()
        .filter(|header| {
            !header.name.eq_ignore_ascii_case("content-encoding")
                && !header.name.eq_ignore_ascii_case("content-length")
        })
        .collect()
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn is_zero_u64(value: &u64) -> bool {
    *value == 0
}

pub(crate) fn decode_content_encoding(headers: &HeaderMap, body: &[u8]) -> Option<Vec<u8>> {
    decode_content_encoding_limited(headers, body, MAX_DECODED_CONTENT_BYTES)
}

fn decode_content_encoding_limited(
    headers: &HeaderMap,
    body: &[u8],
    max_decoded_bytes: usize,
) -> Option<Vec<u8>> {
    if body.is_empty() {
        return None;
    }
    let encodings = headers
        .get(http::header::CONTENT_ENCODING)?
        .to_str()
        .ok()?
        .split(',')
        .map(|encoding| encoding.trim().to_ascii_lowercase())
        .filter(|encoding| !encoding.is_empty())
        .collect::<Vec<_>>();
    if encodings.is_empty() {
        return None;
    }

    let mut decoded = body.to_vec();
    for encoding in encodings.iter().rev() {
        decoded = decode_single_content_encoding(encoding, &decoded, max_decoded_bytes)?;
    }

    Some(decoded)
}

fn decode_single_content_encoding(
    encoding: &str,
    body: &[u8],
    max_decoded_bytes: usize,
) -> Option<Vec<u8>> {
    match encoding {
        "gzip" | "x-gzip" => {
            let mut decoder = flate2::read::GzDecoder::new(body);
            read_limited_to_end(&mut decoder, max_decoded_bytes)
        }
        "deflate" => {
            let mut zlib_decoder = flate2::read::ZlibDecoder::new(body);
            if let Some(out) = read_limited_to_end(&mut zlib_decoder, max_decoded_bytes) {
                return Some(out);
            }
            let mut raw_decoder = flate2::read::DeflateDecoder::new(body);
            read_limited_to_end(&mut raw_decoder, max_decoded_bytes)
        }
        "br" => {
            let mut writer = LimitedVecWriter::new(max_decoded_bytes);
            brotli::BrotliDecompress(&mut std::io::Cursor::new(body), &mut writer).ok()?;
            Some(writer.into_inner())
        }
        "zstd" | "zstandard" => {
            let mut decoder = zstd::stream::read::Decoder::new(std::io::Cursor::new(body)).ok()?;
            read_limited_to_end(&mut decoder, max_decoded_bytes)
        }
        _ => None,
    }
}

fn read_limited_to_end<R: std::io::Read>(reader: &mut R, limit: usize) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    reader
        .take(limit.saturating_add(1) as u64)
        .read_to_end(&mut out)
        .ok()?;
    (out.len() <= limit).then_some(out)
}

struct LimitedVecWriter {
    out: Vec<u8>,
    limit: usize,
}

impl LimitedVecWriter {
    fn new(limit: usize) -> Self {
        Self {
            out: Vec::new(),
            limit,
        }
    }

    fn into_inner(self) -> Vec<u8> {
        self.out
    }
}

impl std::io::Write for LimitedVecWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.out.len().saturating_add(buf.len()) > self.limit {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "decoded content exceeds limit",
            ));
        }
        self.out.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn is_textual_body(content_type: Option<&str>, sample: &[u8]) -> bool {
    if sample.is_empty() {
        return true;
    }

    let valid_utf8 = std::str::from_utf8(sample).is_ok() && !sample.contains(&0);

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
            return valid_utf8;
        }
    }

    valid_utf8
}

fn is_textual_body_preview(content_type: Option<&str>, sample: &[u8], truncated: bool) -> bool {
    if sample.is_empty() {
        return true;
    }

    let valid_utf8 = match std::str::from_utf8(sample) {
        Ok(_) => true,
        Err(error) if truncated && error.error_len().is_none() => !sample.contains(&0),
        Err(_) => false,
    };

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
            return valid_utf8;
        }
    }

    valid_utf8
}

fn utf8_preview_len(sample: &[u8]) -> usize {
    match std::str::from_utf8(sample) {
        Ok(_) => sample.len(),
        Err(error) if error.error_len().is_none() => error.valid_up_to(),
        Err(_) => sample.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{
        write::{GzEncoder, ZlibEncoder},
        Compression,
    };
    use http::header::{CONNECTION, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, UPGRADE};
    use std::io::Write;

    fn gzip(body: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(body).unwrap();
        encoder.finish().unwrap()
    }

    fn zlib_deflate(body: &[u8]) -> Vec<u8> {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(body).unwrap();
        encoder.finish().unwrap()
    }

    fn compressed_headers(compressed_len: usize) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, "application/json".parse().unwrap());
        headers.insert(CONTENT_ENCODING, "gzip".parse().unwrap());
        headers.insert(CONTENT_LENGTH, compressed_len.to_string().parse().unwrap());
        headers
    }

    #[test]
    fn message_record_decodes_gzip_preview_but_keeps_wire_size() {
        let raw = br#"{"ok":true}"#;
        let compressed = gzip(raw);
        let headers = compressed_headers(compressed.len());

        let record = MessageRecord::from_headers_and_body(&headers, &compressed, 1024);

        assert_eq!(record.body_preview, String::from_utf8_lossy(raw));
        assert_eq!(record.body_encoding, BodyEncoding::Utf8);
        assert_eq!(record.body_size, compressed.len());
        assert_eq!(record.decoded_body_size, Some(raw.len()));
        assert!(!record.preview_truncated);
        assert!(record.content_decoded);
    }

    #[test]
    fn content_encoding_decode_respects_decoded_size_limit() {
        let raw = b"hello";
        let compressed = gzip(raw);
        let headers = compressed_headers(compressed.len());

        assert!(decode_content_encoding_limited(&headers, &compressed, raw.len()).is_some());
        assert!(decode_content_encoding_limited(&headers, &compressed, raw.len() - 1).is_none());

        let record = MessageRecord::from_headers_and_body(&headers, &compressed, 8);
        assert!(record.content_decoded);
        assert_eq!(record.decoded_body_size, Some(raw.len()));
    }

    #[test]
    fn message_record_decodes_zlib_wrapped_deflate() {
        let raw = br#"{"ok":"deflate"}"#;
        let compressed = zlib_deflate(raw);
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, "application/json".parse().unwrap());
        headers.insert(CONTENT_ENCODING, "deflate".parse().unwrap());
        headers.insert(
            CONTENT_LENGTH,
            compressed.len().to_string().parse().unwrap(),
        );

        let record = MessageRecord::from_headers_and_body(&headers, &compressed, 1024);

        assert_eq!(record.body_preview, String::from_utf8_lossy(raw));
        assert_eq!(record.body_size, compressed.len());
        assert_eq!(record.decoded_body_size, Some(raw.len()));
        assert!(record.content_decoded);
    }

    #[test]
    fn message_record_decodes_stacked_content_encodings() {
        let raw = br#"{"ok":"stacked"}"#;
        let compressed = gzip(&gzip(raw));
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, "application/json".parse().unwrap());
        headers.insert(CONTENT_ENCODING, "gzip, gzip".parse().unwrap());
        headers.insert(
            CONTENT_LENGTH,
            compressed.len().to_string().parse().unwrap(),
        );

        let record = MessageRecord::from_headers_and_body(&headers, &compressed, 1024);

        assert_eq!(record.body_preview, String::from_utf8_lossy(raw));
        assert_eq!(record.body_size, compressed.len());
        assert_eq!(record.decoded_body_size, Some(raw.len()));
        assert!(record.content_decoded);
    }

    #[test]
    fn message_record_text_preview_does_not_split_utf8_codepoint() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, "text/plain".parse().unwrap());

        let record = MessageRecord::from_headers_and_body(&headers, "ab😀cd".as_bytes(), 4);

        assert_eq!(record.body_preview, "ab");
        assert_eq!(record.body_encoding, BodyEncoding::Utf8);
        assert!(record.preview_truncated);
    }

    #[test]
    fn message_record_accepts_legacy_missing_body_metadata() {
        let record: MessageRecord = serde_json::from_value(serde_json::json!({
            "headers": [{ "name": "host", "value": "example.com" }]
        }))
        .expect("legacy message record should deserialize");

        assert_eq!(record.body_preview, "");
        assert_eq!(record.body_encoding, BodyEncoding::Utf8);
        assert_eq!(record.body_size, 0);
        assert_eq!(record.decoded_body_size, None);
        assert!(!record.preview_truncated);
        assert_eq!(record.header_value("host"), Some("example.com"));
    }

    #[test]
    fn websocket_record_accepts_legacy_missing_collections_and_frame_metadata() {
        let record: WebSocketSessionRecord = serde_json::from_value(serde_json::json!({
            "id": "00000000-0000-0000-0000-00000000f001",
            "started_at": "2026-01-01T00:00:00Z",
            "scheme": "wss",
            "host": "socket.example.com",
            "path": "/stream",
            "request": { "headers": [] },
            "frames": [{
                "captured_at": "2026-01-01T00:00:01Z",
                "direction": "server_to_client",
                "kind": "text"
            }]
        }))
        .expect("legacy websocket session should deserialize");

        assert!(record.notes.is_empty());
        assert_eq!(record.summary().frame_count, 1);
        assert_eq!(record.summary().retained_frame_count, 1);
        let frame = &record.frames[0];
        assert_eq!(frame.index, 0);
        assert_eq!(frame.body_preview, "");
        assert_eq!(frame.body_encoding, BodyEncoding::Utf8);
        assert_eq!(frame.body_size, 0);
        assert!(!frame.preview_truncated);
    }

    #[test]
    fn websocket_summary_counts_zero_based_retained_tail_frames() {
        let mut record: WebSocketSessionRecord = serde_json::from_value(serde_json::json!({
            "id": "00000000-0000-0000-0000-00000000f002",
            "started_at": "2026-01-01T00:00:00Z",
            "scheme": "wss",
            "host": "socket.example.com",
            "path": "/stream",
            "request": { "headers": [] },
            "frames": []
        }))
        .expect("websocket session should deserialize");
        record.frames = [7usize, 8, 9]
            .into_iter()
            .map(|index| WebSocketFrameRecord {
                index,
                captured_at: Utc::now(),
                direction: WebSocketFrameDirection::ServerToClient,
                kind: WebSocketFrameKind::Text,
                body_preview: format!("frame-{index}"),
                body_encoding: BodyEncoding::Utf8,
                body_size: 0,
                preview_truncated: false,
            })
            .collect();

        let summary = record.summary();

        assert_eq!(summary.frame_count, 10);
        assert_eq!(summary.retained_frame_count, 3);
        assert_eq!(summary.last_frame_index, Some(9));
    }

    #[test]
    fn transaction_record_accepts_legacy_missing_kind_duration_and_notes() {
        let record: TransactionRecord = serde_json::from_value(serde_json::json!({
            "id": "00000000-0000-0000-0000-00000000b001",
            "started_at": "2026-01-01T00:00:00Z",
            "method": "GET",
            "scheme": "https",
            "host": "example.com",
            "path": "/legacy",
            "status": 200,
            "request": {
                "headers": [{ "name": "host" }],
                "body_preview": "",
                "body_encoding": "utf8"
            }
        }))
        .expect("legacy transaction record should deserialize");

        assert!(matches!(record.kind, TrafficKind::Http));
        assert_eq!(record.duration_ms, 0);
        assert!(record.notes.is_empty());
        assert_eq!(record.summary().note_count, 0);
        assert_eq!(record.request.header_value("host"), Some(""));
    }

    #[test]
    fn transaction_record_detects_websocket_upgrade_token_lists() {
        let mut headers = HeaderMap::new();
        headers.insert(UPGRADE, "h2c, websocket".parse().unwrap());
        headers.insert(CONNECTION, "keep-alive, upgrade".parse().unwrap());
        let request = MessageRecord::from_headers_and_body(&headers, &[], 1024);
        let record = TransactionRecord::http(
            Utc::now(),
            "GET".to_string(),
            "https".to_string(),
            "socket.example.com".to_string(),
            "/ws".to_string(),
            Some(101),
            1,
            request,
            None,
            Vec::new(),
            None,
            None,
        );

        assert!(record.is_websocket());
        assert!(record.summary().is_websocket);
    }

    #[test]
    fn transaction_record_detects_websocket_upgrade_split_connection_headers() {
        let request = MessageRecord {
            headers: vec![
                HeaderRecord {
                    name: "Upgrade".to_string(),
                    value: "websocket".to_string(),
                },
                HeaderRecord {
                    name: "Connection".to_string(),
                    value: "keep-alive".to_string(),
                },
                HeaderRecord {
                    name: "Connection".to_string(),
                    value: "Upgrade".to_string(),
                },
            ],
            body_preview: String::new(),
            body_encoding: BodyEncoding::Utf8,
            body_size: 0,
            decoded_body_size: None,
            preview_truncated: false,
            content_type: None,
            content_decoded: false,
        };
        let record = TransactionRecord::http(
            Utc::now(),
            "GET".to_string(),
            "https".to_string(),
            "socket.example.com".to_string(),
            "/ws".to_string(),
            Some(101),
            1,
            request,
            None,
            Vec::new(),
            None,
            None,
        );

        assert!(record.is_websocket());
        assert!(record.summary().is_websocket);
    }

    #[test]
    fn transaction_record_does_not_treat_failed_upgrade_attempt_as_websocket() {
        let mut headers = HeaderMap::new();
        headers.insert(UPGRADE, "websocket".parse().unwrap());
        headers.insert(CONNECTION, "upgrade".parse().unwrap());
        let request = MessageRecord::from_headers_and_body(&headers, &[], 1024);
        let record = TransactionRecord::http(
            Utc::now(),
            "GET".to_string(),
            "https".to_string(),
            "socket.example.com".to_string(),
            "/ws".to_string(),
            Some(400),
            1,
            request,
            None,
            Vec::new(),
            None,
            None,
        );

        assert!(!record.is_websocket());
        assert!(!record.summary().is_websocket);
    }

    #[test]
    fn transaction_record_does_not_treat_status_101_alone_as_websocket() {
        let request = MessageRecord::from_headers_and_body(&HeaderMap::new(), &[], 1024);
        let record = TransactionRecord::http(
            Utc::now(),
            "GET".to_string(),
            "https".to_string(),
            "socket.example.com".to_string(),
            "/upgrade".to_string(),
            Some(101),
            1,
            request,
            None,
            Vec::new(),
            None,
            None,
        );

        assert!(!record.is_websocket());
        assert!(!record.summary().is_websocket);
    }

    #[test]
    fn editable_request_from_compressed_body_sanitizes_decoded_entity_headers() {
        let raw = br#"{"ok":true}"#;
        let compressed = gzip(raw);
        let headers = compressed_headers(compressed.len());

        let request = EditableRequest::from_headers_and_body(
            "https",
            "example.com",
            "POST",
            "/submit",
            &headers,
            &compressed,
        );

        assert_eq!(request.body, String::from_utf8_lossy(raw));
        assert!(request
            .headers
            .iter()
            .all(|h| !h.name.eq_ignore_ascii_case("content-encoding")));
        assert!(request
            .headers
            .iter()
            .all(|h| !h.name.eq_ignore_ascii_case("content-length")));
    }

    #[test]
    fn editable_request_from_decoded_message_sanitizes_entity_headers() {
        let raw = br#"{"ok":true}"#;
        let compressed = gzip(raw);
        let headers = compressed_headers(compressed.len());
        let message = MessageRecord::from_headers_and_body(&headers, &compressed, 1024);

        let request = EditableRequest::from_message_record(
            "https",
            "example.com",
            "POST",
            "/submit",
            &message,
        );

        assert_eq!(request.body, String::from_utf8_lossy(raw));
        assert!(request
            .headers
            .iter()
            .all(|h| !h.name.eq_ignore_ascii_case("content-encoding")));
        assert!(request
            .headers
            .iter()
            .all(|h| !h.name.eq_ignore_ascii_case("content-length")));
    }

    #[test]
    fn editable_request_preserves_invalid_utf8_text_body_as_base64() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, "text/plain".parse().unwrap());

        let request = EditableRequest::from_headers_and_body(
            "https",
            "example.com",
            "POST",
            "/upload",
            &headers,
            &[0xff],
        );

        assert_eq!(request.body_encoding, BodyEncoding::Base64);
        assert_eq!(request.try_body_bytes().unwrap(), vec![0xff]);
    }

    #[test]
    fn editable_response_preserves_invalid_utf8_text_body_as_base64() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, "text/plain".parse().unwrap());

        let response = EditableResponse::from_status_headers_body(200, &headers, &[0xff]);

        assert_eq!(response.body_encoding, BodyEncoding::Base64);
        assert_eq!(response.try_body_bytes().unwrap(), vec![0xff]);
    }

    #[test]
    fn editable_response_from_compressed_body_sanitizes_decoded_entity_headers() {
        let raw = br#"{"ok":true}"#;
        let compressed = gzip(raw);
        let headers = compressed_headers(compressed.len());

        let response = EditableResponse::from_status_headers_body(200, &headers, &compressed);

        assert_eq!(response.body, String::from_utf8_lossy(raw));
        assert!(response
            .headers
            .iter()
            .all(|h| !h.name.eq_ignore_ascii_case("content-encoding")));
        assert!(response
            .headers
            .iter()
            .all(|h| !h.name.eq_ignore_ascii_case("content-length")));
    }
}
