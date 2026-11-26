//! Explicit, bounded reads of literal URL origins in one retained response preview.
//! This is passive evidence: it never decodes, executes, fetches, or hydrates traffic.
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fs::File,
    io::{Read, Seek, SeekFrom},
};

use chrono::{DateTime, Utc};
use serde::{de::Visitor, Deserialize, Deserializer, Serialize};
use url::Url;
use uuid::Uuid;

use crate::{
    model::{BodyEncoding, TransactionRecord},
    service_map::{project_record, MAX_HEADERS, MAX_HEADER_BYTES, MAX_HEADER_VALUE_BYTES},
    session::BodyLocator,
};

pub const MAX_SCAN_BYTES: usize = 256 * 1024;
pub const MAX_SERIALIZED_ROW_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_ORIGINS: usize = 100;
pub const MAX_CANDIDATES: usize = 4096;
pub const MAX_CANDIDATE_BYTES: usize = 4096;
pub const MAX_OFFSETS_PER_ORIGIN: usize = 5;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServiceMapBodyLimits {
    pub scan_bytes: usize,
    pub serialized_row_bytes: usize,
    pub origins: usize,
    pub candidates: usize,
    pub candidate_bytes: usize,
    pub offsets_per_origin: usize,
}

impl Default for ServiceMapBodyLimits {
    fn default() -> Self {
        Self {
            scan_bytes: MAX_SCAN_BYTES,
            serialized_row_bytes: MAX_SERIALIZED_ROW_BYTES,
            origins: MAX_ORIGINS,
            candidates: MAX_CANDIDATES,
            candidate_bytes: MAX_CANDIDATE_BYTES,
            offsets_per_origin: MAX_OFFSETS_PER_ORIGIN,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServiceMapBodyReference {
    pub target_origin: String,
    pub occurrences: usize,
    pub preview_byte_offsets: Vec<usize>,
    pub omitted_offsets: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServiceMapBodyReferences {
    pub schema_version: u32,
    pub session_id: Uuid,
    pub evidence_id: String,
    pub available: bool,
    pub status: String,
    /// Completeness is limited to this literal scan, never runtime dependencies.
    pub complete: bool,
    pub reasons: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_origin: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_sequence: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_started_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retained_preview_bytes: Option<usize>,
    pub scanned_bytes: usize,
    pub capture_preview_truncated: bool,
    pub scan_prefix_truncated: bool,
    pub candidates_scanned: usize,
    pub omitted_reference_occurrences: usize,
    pub references: Vec<ServiceMapBodyReference>,
    pub limits: ServiceMapBodyLimits,
    pub coverage: String,
    pub offset_basis: String,
}

impl ServiceMapBodyReferences {
    pub fn missing(session_id: Uuid, evidence_id: String, reason: &str) -> Self {
        Self {
            schema_version: 1,
            session_id,
            evidence_id,
            available: false,
            status: "unavailable".into(),
            complete: false,
            reasons: vec![reason.into()],
            source_origin: None,
            source_sequence: None,
            source_started_at: None,
            retained_preview_bytes: None,
            scanned_bytes: 0,
            capture_preview_truncated: false,
            scan_prefix_truncated: false,
            candidates_scanned: 0,
            omitted_reference_occurrences: 0,
            references: Vec::new(),
            limits: ServiceMapBodyLimits::default(),
            coverage: "literal_absolute_http_urls".into(),
            offset_basis: "retained_utf8_preview".into(),
        }
    }

    pub(crate) fn unsupported(session_id: Uuid, evidence_id: String, reason: &str) -> Self {
        let mut result = Self::missing(session_id, evidence_id, reason);
        result.status = "unsupported".into();
        result
    }
}

/// Only bounded metadata is copied while the store lock is held. Response bodies
/// and potentially secret request fields are deliberately absent from this plan.
#[derive(Debug)]
pub(crate) struct BodySource {
    pub origin: String,
    pub sequence: u64,
    pub started_at: DateTime<Utc>,
    body_size: usize,
    decoded_body_size: Option<usize>,
    capture_preview_truncated: bool,
    content_decoded: bool,
}

const TEXT_RECORD_TYPES: &[&str] = &[
    "text/html",
    "application/xhtml+xml",
    "application/javascript",
    "text/javascript",
    "application/ecmascript",
    "text/ecmascript",
    "application/x-javascript",
    "application/json",
    "application/problem+json",
    "application/hal+json",
    "application/vnd.api+json",
    "text/plain",
    "application/xml",
    "text/xml",
];

impl BodySource {
    pub(crate) fn from_record(record: &TransactionRecord) -> Result<Self, &'static str> {
        Self::from_record_for_types(
            record,
            &[
                "text/html",
                "application/xhtml+xml",
                "application/javascript",
                "text/javascript",
                "application/ecmascript",
                "text/ecmascript",
                "application/x-javascript",
            ],
            false,
        )
    }

    /// Whether a record is a page or a script, or an error, root or
    /// API-document response, whose text can name the servers behind it. It
    /// is scanned for ASCII signatures only, so a page stored as base64
    /// because it is not UTF-8 (an EUC-KR page) is read too. The caller holds
    /// the record's map row, and a row exists only where the request projects,
    /// so the record is not projected again: doing so was a fifth of a map's
    /// build.
    pub(crate) fn text_record_is_readable(record: &TransactionRecord) -> bool {
        Self::check_record_for_types(record, TEXT_RECORD_TYPES, true).is_ok()
    }

    pub(crate) fn from_html_record(record: &TransactionRecord) -> Result<Self, &'static str> {
        Self::from_record_for_types(record, &["text/html"], false)
    }

    pub(crate) fn capture_preview_truncated(&self) -> bool {
        self.capture_preview_truncated
    }

    fn from_record_for_types(
        record: &TransactionRecord,
        content_types: &[&str],
        any_encoding: bool,
    ) -> Result<Self, &'static str> {
        Self::check_record_for_types(record, content_types, any_encoding)?;
        let response = record.response.as_ref().ok_or("response_unavailable")?;
        let row = project_record(record, String::new()).ok_or("unsupported_metadata")?;
        Ok(Self {
            origin: row.origin,
            sequence: record.sequence,
            started_at: record.started_at,
            body_size: response.body_size,
            decoded_body_size: response.decoded_body_size,
            capture_preview_truncated: response.preview_truncated,
            content_decoded: response.content_decoded,
        })
    }

    fn check_record_for_types(
        record: &TransactionRecord,
        content_types: &[&str],
        any_encoding: bool,
    ) -> Result<(), &'static str> {
        let response = record.response.as_ref().ok_or("response_unavailable")?;
        // An encoding hidden beyond the metadata cap must not be assumed absent.
        // One long value hides nothing: every name is still read below, and a
        // site's Content-Security-Policy often runs past 4 KiB, which once left
        // its page unread.
        let mut header_bytes = 0usize;
        if response.headers.len() > MAX_HEADERS {
            return Err("metadata_limit");
        }
        for header in &response.headers {
            header_bytes = header_bytes
                .saturating_add(header.name.len())
                .saturating_add(header.value.len());
            if header_bytes > MAX_HEADER_BYTES || header.name.len() > MAX_HEADER_VALUE_BYTES {
                return Err("metadata_limit");
            }
        }
        let content_type = response
            .content_type
            .as_deref()
            .ok_or("unsupported_content_type")?;
        if content_type.len() > MAX_HEADER_VALUE_BYTES {
            return Err("metadata_limit");
        }
        let mime = content_type.split(';').next().unwrap_or("").trim();
        if mime.len() > 128
            || !content_types
                .iter()
                .any(|supported| mime.eq_ignore_ascii_case(supported))
        {
            return Err("unsupported_content_type");
        }
        if response.body_encoding != BodyEncoding::Utf8 && !any_encoding {
            return Err("unsupported_body_encoding");
        }
        if !response.content_decoded
            && response.headers.iter().any(|header| {
                header.name.eq_ignore_ascii_case("content-encoding")
                    && !header
                        .value
                        .split(',')
                        .all(|encoding| encoding.trim().eq_ignore_ascii_case("identity"))
            })
        {
            return Err("unsupported_content_encoding");
        }
        Ok(())
    }

    pub(crate) fn expected_preview_bytes(&self) -> Option<usize> {
        if self.content_decoded {
            self.decoded_body_size
        } else {
            Some(self.body_size)
        }
    }

    pub(crate) fn proves_empty(&self) -> bool {
        self.expected_preview_bytes() == Some(0)
            && self.decoded_body_size.is_none_or(|size| size == 0)
            && !self.capture_preview_truncated
    }
}

#[derive(Debug)]
pub(crate) struct RetainedPreview {
    prefix: String,
    total_bytes: usize,
}

impl RetainedPreview {
    pub(crate) fn prefix(&self) -> &str {
        &self.prefix
    }

    pub(crate) fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    pub(crate) fn from_str(value: &str) -> Self {
        let mut end = value.len().min(MAX_SCAN_BYTES);
        while !value.is_char_boundary(end) {
            end -= 1;
        }
        Self {
            prefix: value[..end].to_owned(),
            total_bytes: value.len(),
        }
    }
}

impl<'de> Deserialize<'de> for RetainedPreview {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct PreviewVisitor;
        impl Visitor<'_> for PreviewVisitor {
            type Value = RetainedPreview;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a retained UTF-8 preview")
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(RetainedPreview::from_str(value))
            }
        }
        deserializer.deserialize_str(PreviewVisitor)
    }
}

// Unknown fields are skipped by serde rather than constructing MessageRecord or
// TransactionRecord. In particular request/original bodies are never hydrated.
#[derive(Deserialize)]
struct DiskBodyRow {
    id: Uuid,
    sequence: u64,
    started_at: DateTime<Utc>,
    response: Option<DiskResponse>,
}

#[derive(Deserialize)]
struct DiskResponse {
    #[serde(default)]
    body_preview: Option<RetainedPreview>,
    #[serde(default)]
    body_encoding: BodyEncoding,
    #[serde(default)]
    body_size: usize,
    #[serde(default)]
    decoded_body_size: Option<usize>,
    #[serde(default)]
    preview_truncated: bool,
    #[serde(default)]
    content_decoded: bool,
}

pub(crate) fn read_preview(
    mut file: File,
    locator: BodyLocator,
    record_id: Uuid,
    source: &BodySource,
) -> Result<RetainedPreview, &'static str> {
    let len = locator.len as usize;
    // Charge the serialized range before allocating, including ignored fields.
    if len > MAX_SERIALIZED_ROW_BYTES {
        return Err("serialized_row_limit");
    }
    let end = locator
        .offset
        .checked_add(u64::from(locator.len))
        .ok_or("body_identity_unverifiable")?;
    if len == 0 || end > file.metadata().map_err(|_| "body_read_failed")?.len() {
        return Err("body_read_failed");
    }
    file.seek(SeekFrom::Start(locator.offset))
        .map_err(|_| "body_read_failed")?;
    let mut bytes = vec![0u8; len];
    file.read_exact(&mut bytes)
        .map_err(|_| "body_read_failed")?;
    // Ignored JSON fields are still required to be valid UTF-8; serde's skipped
    // strings need not validate every byte themselves.
    std::str::from_utf8(&bytes).map_err(|_| "malformed_retained_row")?;
    let row: DiskBodyRow = serde_json::from_slice(&bytes).map_err(|_| "malformed_retained_row")?;
    if row.id != record_id || row.sequence != source.sequence || row.started_at != source.started_at
    {
        return Err("body_identity_unverifiable");
    }
    let response = row.response.ok_or("body_identity_unverifiable")?;
    if response.body_encoding != BodyEncoding::Utf8
        || response.body_size != source.body_size
        || response.decoded_body_size != source.decoded_body_size
        || response.preview_truncated != source.capture_preview_truncated
        || response.content_decoded != source.content_decoded
    {
        return Err("body_identity_unverifiable");
    }
    response.body_preview.ok_or("retained_preview_unavailable")
}

fn url_start(bytes: &[u8], offset: usize) -> bool {
    let remaining = &bytes[offset..];
    (remaining.len() >= 7 && remaining[..7].eq_ignore_ascii_case(b"http://"))
        || (remaining.len() >= 8 && remaining[..8].eq_ignore_ascii_case(b"https://"))
}

fn url_delimiter(byte: u8) -> bool {
    byte.is_ascii_whitespace()
        || byte.is_ascii_control()
        || matches!(
            byte,
            b'"' | b'\'' | b'<' | b'>' | b'`' | b'\\' | b'(' | b')' | b'{' | b'}'
        )
}

pub(crate) fn scan_preview(
    session_id: Uuid,
    evidence_id: String,
    source: BodySource,
    preview: RetainedPreview,
) -> ServiceMapBodyReferences {
    if preview.total_bytes == 0 && !source.proves_empty() {
        return ServiceMapBodyReferences::missing(
            session_id,
            evidence_id,
            "retained_preview_unavailable",
        );
    }
    let mut result = ServiceMapBodyReferences::missing(session_id, evidence_id, "");
    result.available = true;
    // Older rows may have lost a suffix without preserving the explicit flag.
    // Compare decoded bytes only when capture decoded the response; compressed
    // wire size says nothing about the retained text's length.
    result.capture_preview_truncated = source.capture_preview_truncated
        || source
            .expected_preview_bytes()
            .is_some_and(|expected| preview.total_bytes < expected);
    result.source_origin = Some(source.origin);
    result.source_sequence = Some(source.sequence.to_string());
    result.source_started_at = Some(source.started_at);
    result.retained_preview_bytes = Some(preview.total_bytes);
    result.scanned_bytes = preview.prefix.len();
    result.scan_prefix_truncated = preview.prefix.len() < preview.total_bytes;
    let mut reasons = BTreeSet::new();
    if result.capture_preview_truncated {
        reasons.insert("capture_preview_truncated");
    }
    if result.scan_prefix_truncated {
        reasons.insert("scan_prefix_truncated");
    }
    let bytes = preview.prefix.as_bytes();
    let mut references: BTreeMap<String, ServiceMapBodyReference> = BTreeMap::new();
    let mut offset = 0usize;
    while offset < bytes.len() {
        if !url_start(bytes, offset)
            || (offset > 0
                && (bytes[offset - 1].is_ascii_alphanumeric() || bytes[offset - 1] == b'_'))
        {
            offset += 1;
            continue;
        }
        let start = offset;
        while offset < bytes.len() && !url_delimiter(bytes[offset]) {
            offset += 1;
        }
        if result.candidates_scanned == MAX_CANDIDATES {
            reasons.insert("candidate_limit");
            continue;
        }
        result.candidates_scanned += 1;
        if offset - start > MAX_CANDIDATE_BYTES {
            reasons.insert("candidate_bytes");
            continue;
        }
        // A URL cut by our prefix cap is not evidence for a possibly truncated
        // authority. Even a parseable prefix must not become a fabricated origin.
        if offset == bytes.len()
            && (result.scan_prefix_truncated || result.capture_preview_truncated)
        {
            continue;
        }
        let Ok(candidate) = Url::parse(&preview.prefix[start..offset]) else {
            continue;
        };
        if !matches!(candidate.scheme(), "http" | "https") || candidate.host_str().is_none() {
            continue;
        }
        let origin = candidate.origin().ascii_serialization();
        if origin.len() > MAX_CANDIDATE_BYTES {
            reasons.insert("candidate_bytes");
            continue;
        }
        if !references.contains_key(&origin) && references.len() == MAX_ORIGINS {
            result.omitted_reference_occurrences += 1;
            reasons.insert("origin_limit");
            continue;
        }
        let reference =
            references
                .entry(origin.clone())
                .or_insert_with(|| ServiceMapBodyReference {
                    target_origin: origin,
                    occurrences: 0,
                    preview_byte_offsets: Vec::new(),
                    omitted_offsets: 0,
                });
        reference.occurrences += 1;
        if reference.preview_byte_offsets.len() < MAX_OFFSETS_PER_ORIGIN {
            reference.preview_byte_offsets.push(start);
        } else {
            reference.omitted_offsets += 1;
            reasons.insert("offset_limit");
        }
    }
    result.references = references.into_values().collect();
    result.complete = reasons.is_empty();
    result.status = if result.complete {
        "scanned"
    } else {
        "partial"
    }
    .into();
    result.reasons = reasons.into_iter().map(str::to_owned).collect();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{HeaderRecord, MessageRecord};

    fn record(body: &str) -> TransactionRecord {
        let response = MessageRecord {
            headers: Vec::new(),
            body_preview: body.into(),
            body_encoding: BodyEncoding::Utf8,
            body_size: body.len(),
            decoded_body_size: None,
            preview_truncated: false,
            content_type: Some("text/html; charset=utf-8".into()),
            content_decoded: false,
        };
        let mut record = TransactionRecord::http(
            Utc::now(),
            "GET".into(),
            "https".into(),
            "source.example.com".into(),
            "/private?session=secret".into(),
            Some(200),
            1,
            response.clone(),
            Some(response),
            Vec::new(),
            None,
            None,
        );
        record.sequence = 1;
        record
    }

    fn scan(record: &TransactionRecord) -> ServiceMapBodyReferences {
        scan_preview(
            Uuid::new_v4(),
            "test-evidence".into(),
            BodySource::from_record(record).unwrap(),
            RetainedPreview::from_str(&record.response.as_ref().unwrap().body_preview),
        )
    }

    #[test]
    fn body_references_are_canonical_origins_with_utf8_byte_offsets_only() {
        let body = "é <a href=\"HTTPS://user:password@Example.COM:443/private?token=secret#fragment\"> https://example.com/second http://[::1]:80/a 'https://xn--bcher-kva.example.com/path'";
        let result = scan(&record(body));
        assert!(result.complete);
        assert_eq!(result.status, "scanned");
        assert_eq!(result.references.len(), 3);
        let example = result
            .references
            .iter()
            .find(|r| r.target_origin == "https://example.com")
            .unwrap();
        assert_eq!(example.occurrences, 2);
        assert_eq!(
            example.preview_byte_offsets,
            vec![
                body.find("HTTPS://").unwrap(),
                body.find("https://example.com").unwrap()
            ]
        );
        let json = serde_json::to_string(&result).unwrap();
        for secret in [
            "user:", "password", "private", "token", "secret", "fragment", "href", "second",
        ] {
            assert!(!json.contains(secret), "response leaked {secret}");
        }
        assert_eq!(result.offset_basis, "retained_utf8_preview");
        assert_eq!(result.coverage, "literal_absolute_http_urls");
    }

    #[test]
    fn body_references_never_resolve_execute_or_decode_nonliteral_inputs() {
        let result = scan(&record("/relative //example.com window.location fetch(variable) aHR0cHM6Ly9leGFtcGxlLmNvbQ== https:\\/\\/example.com https&#58;//example.com data:text/plain,abc javascript:fetch('x')"));
        assert!(result.complete);
        assert!(result.references.is_empty());
        assert_eq!(result.candidates_scanned, 0);
    }

    #[test]
    fn body_references_separate_capture_and_scan_caps_without_fabricating_tail_origin() {
        let mut fixture = record(&format!(
            "{}https://cut.example.com/path",
            "x".repeat(MAX_SCAN_BYTES - 12) + " "
        ));
        fixture.response.as_mut().unwrap().preview_truncated = true;
        let result = scan(&fixture);
        assert_eq!(result.scanned_bytes, MAX_SCAN_BYTES);
        assert!(result.capture_preview_truncated);
        assert!(result.scan_prefix_truncated);
        assert!(result.reasons.contains(&"capture_preview_truncated".into()));
        assert!(result.reasons.contains(&"scan_prefix_truncated".into()));
        assert!(result.references.is_empty());
        assert_eq!(result.omitted_reference_occurrences, 0);
        let mut tail = record("https://cut.example");
        tail.response.as_mut().unwrap().preview_truncated = true;
        let result = scan(&tail);
        assert!(!result.scan_prefix_truncated);
        assert!(result.references.is_empty());
    }

    #[test]
    fn body_references_infer_missing_capture_suffix_without_comparing_compressed_wire_size() {
        let mut fixture = record("https://example.com/ ");
        fixture.response.as_mut().unwrap().body_size += 100;
        let result = scan(&fixture);
        assert!(result.capture_preview_truncated);
        assert!(!result.scan_prefix_truncated);
        assert_eq!(result.status, "partial");
        assert_eq!(result.references[0].target_origin, "https://example.com");

        let response = fixture.response.as_mut().unwrap();
        response.content_decoded = true;
        response.decoded_body_size = Some(response.body_preview.len());
        assert!(scan(&fixture).complete);
        fixture.response.as_mut().unwrap().decoded_body_size = Some(1000);
        assert!(scan(&fixture).capture_preview_truncated);

        let mut empty = record("");
        let response = empty.response.as_mut().unwrap();
        response.content_decoded = true;
        response.body_size = 20;
        response.decoded_body_size = Some(0);
        assert!(scan(&empty).complete);
        empty.response.as_mut().unwrap().decoded_body_size = None;
        assert!(!scan(&empty).available);
    }

    #[test]
    fn body_references_scan_prefix_respects_utf8_boundary() {
        let fixture = record(&("x".repeat(MAX_SCAN_BYTES - 1) + "€ https://example.com/"));
        let result = scan(&fixture);
        assert_eq!(result.scanned_bytes, MAX_SCAN_BYTES - 1);
        assert!(result.scan_prefix_truncated);
        assert!(result.references.is_empty());
    }

    #[test]
    fn body_references_bound_origins_candidates_candidate_bytes_and_offset_samples() {
        let many = (0..101)
            .map(|i| format!("https://h{i}.example.com/a "))
            .collect::<String>();
        let result = scan(&record(&many));
        assert_eq!(result.references.len(), MAX_ORIGINS);
        assert_eq!(result.omitted_reference_occurrences, 1);
        assert!(result.reasons.contains(&"origin_limit".into()));

        let many = "https://example.com/a ".repeat(MAX_CANDIDATES + 1);
        let result = scan(&record(&many));
        assert_eq!(result.candidates_scanned, MAX_CANDIDATES);
        assert_eq!(result.references[0].occurrences, MAX_CANDIDATES);
        assert_eq!(
            result.references[0].preview_byte_offsets.len(),
            MAX_OFFSETS_PER_ORIGIN
        );
        assert_eq!(
            result.references[0].omitted_offsets,
            MAX_CANDIDATES - MAX_OFFSETS_PER_ORIGIN
        );
        assert_eq!(result.omitted_reference_occurrences, 0);
        assert!(result.reasons.contains(&"candidate_limit".into()));
        assert!(result.reasons.contains(&"offset_limit".into()));

        let large = format!(
            "https://example.com/{} https://kept.example.com/ ",
            "x".repeat(MAX_CANDIDATE_BYTES)
        );
        let result = scan(&record(&large));
        assert_eq!(result.candidates_scanned, 2);
        assert_eq!(
            result.references[0].target_origin,
            "https://kept.example.com"
        );
        assert_eq!(result.omitted_reference_occurrences, 0);
        assert!(result.reasons.contains(&"candidate_bytes".into()));
    }

    #[test]
    fn body_references_bound_canonical_unicode_host_expansion() {
        let literal = format!("https://{}example.com/", "é.".repeat(600));
        assert!(literal.len() <= MAX_CANDIDATE_BYTES);
        assert!(
            Url::parse(&literal)
                .unwrap()
                .origin()
                .ascii_serialization()
                .len()
                > MAX_CANDIDATE_BYTES
        );
        let result = scan(&record(&(literal + " ")));
        assert_eq!(result.status, "partial");
        assert_eq!(result.candidates_scanned, 1);
        assert_eq!(result.reasons, ["candidate_bytes"]);
        assert_eq!(result.omitted_reference_occurrences, 0);
        assert!(result.references.is_empty());
    }

    #[test]
    fn body_references_reject_unsupported_mime_encoding_and_uncapped_metadata() {
        let mut fixture = record("https://example.com/");
        for mime in [
            None,
            Some("application/json"),
            Some("text/plain"),
            Some("image/svg+xml"),
        ] {
            fixture.response.as_mut().unwrap().content_type = mime.map(str::to_owned);
            assert_eq!(
                BodySource::from_record(&fixture).unwrap_err(),
                "unsupported_content_type"
            );
        }
        fixture.response.as_mut().unwrap().content_type =
            Some("Text/JavaScript; charset=utf-8".into());
        assert!(BodySource::from_record(&fixture).is_ok());
        fixture.response.as_mut().unwrap().body_encoding = BodyEncoding::Base64;
        assert_eq!(
            BodySource::from_record(&fixture).unwrap_err(),
            "unsupported_body_encoding"
        );
        fixture.response.as_mut().unwrap().body_encoding = BodyEncoding::Utf8;
        fixture.response.as_mut().unwrap().headers = vec![HeaderRecord {
            name: "CONTENT-ENCODING".into(),
            value: "gzip".into(),
        }];
        assert_eq!(
            BodySource::from_record(&fixture).unwrap_err(),
            "unsupported_content_encoding"
        );
        fixture.response.as_mut().unwrap().content_decoded = true;
        assert!(BodySource::from_record(&fixture).is_ok());
        fixture.response.as_mut().unwrap().content_decoded = false;
        fixture.response.as_mut().unwrap().headers[0].value = "identity, identity".into();
        assert!(BodySource::from_record(&fixture).is_ok());
        fixture.response.as_mut().unwrap().headers.resize(
            MAX_HEADERS + 1,
            HeaderRecord {
                name: "x".into(),
                value: String::new(),
            },
        );
        assert_eq!(
            BodySource::from_record(&fixture).unwrap_err(),
            "metadata_limit"
        );
    }

    #[test]
    fn body_references_distinguish_proven_empty_from_missing_preview() {
        assert!(scan(&record("")).complete);
        let mut fixture = record("");
        fixture.response.as_mut().unwrap().body_size = 1;
        let result = scan(&fixture);
        assert!(!result.available);
        assert_eq!(result.reasons, ["retained_preview_unavailable"]);
        fixture.response.as_mut().unwrap().body_size = 0;
        fixture.response.as_mut().unwrap().decoded_body_size = Some(1);
        assert!(!scan(&fixture).available);
        fixture.response.as_mut().unwrap().decoded_body_size = None;
        fixture.response.as_mut().unwrap().preview_truncated = true;
        assert!(!scan(&fixture).available);
    }

    #[test]
    fn body_references_disk_projection_ignores_other_bodies_and_retains_only_prefix() {
        let mut fixture =
            record(&("https://example.com/ ".to_owned() + &"x".repeat(MAX_SCAN_BYTES + 32)));
        fixture.request.body_preview = "sensitive request".repeat(20_000);
        fixture.original_response = Some(fixture.request.clone());
        let source = BodySource::from_record(&fixture).unwrap();
        let mut value = serde_json::to_value(&fixture).unwrap();
        // This deliberately is not a full MessageRecord: the reader must ignore
        // request/original fields rather than deserializing or hydrating them.
        value["request"]["body_preview"] = serde_json::json!({"unused": [1, 2, 3]});
        let bytes = serde_json::to_vec(&value).unwrap();
        let path = std::env::temp_dir().join(format!("sniper-body-projection-{}", Uuid::new_v4()));
        std::fs::write(&path, &bytes).unwrap();
        let preview = read_preview(
            File::open(&path).unwrap(),
            BodyLocator {
                offset: 0,
                len: bytes.len() as u32,
            },
            fixture.id,
            &source,
        )
        .unwrap();
        assert_eq!(preview.prefix.len(), MAX_SCAN_BYTES);
        assert_eq!(
            preview.total_bytes,
            fixture.response.as_ref().unwrap().body_preview.len()
        );
        std::fs::remove_file(path).unwrap();
    }
}
