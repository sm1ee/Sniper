//! Exact retained packet projections, not reconstructed wire messages.
//! Counting and emission share a borrowed projection: no record/body clone is
//! allowed to precede the packet budget, and unrelated annotations stay private.
use std::{
    fmt,
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
};

use chrono::{DateTime, Utc};
use serde::{
    de::{DeserializeSeed, Error, MapAccess, Visitor},
    Deserialize, Serialize,
};
use uuid::Uuid;

use crate::{
    model::{BodyEncoding, HeaderRecord, MessageRecord, TransactionRecord},
    session::BodyLocator,
};

pub const MAX_PACKET_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_SERIALIZED_ROW_BYTES: usize = crate::service_map_body::MAX_SERIALIZED_ROW_BYTES;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PacketVariant {
    Current,
    Original,
}

#[derive(Serialize)]
struct Limits {
    packet_bytes: usize,
    serialized_row_bytes: usize,
}
#[derive(Serialize)]
struct Source {
    record_id: Uuid,
    sequence: String,
    started_at: DateTime<Utc>,
}
#[derive(Serialize)]
struct Originals {
    request: bool,
    response: bool,
}
#[derive(Serialize)]
struct Packet<'a> {
    schema_version: u32,
    session_id: Uuid,
    evidence_id: &'a str,
    variant: PacketVariant,
    available: bool,
    status: &'static str,
    reason: Option<&'static str>,
    source: Option<Source>,
    limits: Limits,
    originals: Option<Originals>,
    request: Option<Side<'a>>,
    response: Option<Side<'a>>,
}
#[derive(Serialize)]
struct Side<'a> {
    status: &'static str,
    message: Option<Message<'a>>,
}
#[derive(Serialize)]
struct Message<'a> {
    method: Option<&'a str>,
    scheme: Option<&'a str>,
    authority: Option<&'a str>,
    path: Option<&'a str>,
    http_version: Option<&'a str>,
    status_code: Option<u16>,
    headers: &'a [HeaderRecord],
    body: Body<'a>,
}
#[derive(Serialize)]
struct Body<'a> {
    available: bool,
    reason: Option<&'static str>,
    body_preview: Option<&'a str>,
    body_encoding: &'a BodyEncoding,
    body_size: usize,
    decoded_body_size: Option<usize>,
    preview_truncated: bool,
    content_decoded: bool,
    content_type: Option<&'a str>,
}

// A writer bounds even highly escaped strings before allocating output. The
// second pass is bounded too, rather than trusting a growing Vec's capacity.
struct BudgetWriter {
    count: usize,
    limit: usize,
    output: Option<Vec<u8>>,
}
impl Write for BudgetWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.count) {
            return Err(io::Error::other("packet_view_limit"));
        }
        self.count += bytes.len();
        if let Some(output) = &mut self.output {
            output.extend_from_slice(bytes);
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn encode<T: Serialize>(value: &T, limit: usize) -> Result<Vec<u8>, &'static str> {
    let mut counter = BudgetWriter {
        count: 0,
        limit,
        output: None,
    };
    serde_json::to_writer(&mut counter, value).map_err(|_| "packet_view_limit")?;
    let mut writer = BudgetWriter {
        count: 0,
        limit: counter.count,
        output: Some(Vec::with_capacity(counter.count)),
    };
    serde_json::to_writer(&mut writer, value).map_err(|_| "packet_view_limit")?;
    if writer.count != counter.count {
        return Err("packet_view_limit");
    }
    Ok(writer.output.expect("output writer"))
}

fn admit_borrowed_leaves(packet: &Packet<'_>) -> Result<(), &'static str> {
    // JSON cannot be shorter than these literal UTF-8 leaves. Reject an
    // enormous unescaped leaf before serde's escape scanner traverses it;
    // the exact counting pass still charges all escaping and punctuation.
    let mut remaining = MAX_PACKET_BYTES;
    let mut charge = |bytes: usize| {
        remaining = remaining.checked_sub(bytes).ok_or("packet_view_limit")?;
        Ok::<_, &'static str>(())
    };
    for side in [&packet.request, &packet.response].into_iter().flatten() {
        let Some(message) = &side.message else {
            continue;
        };
        for value in [
            message.method,
            message.scheme,
            message.authority,
            message.path,
            message.http_version,
            message.body.content_type,
            message.body.body_preview,
        ]
        .into_iter()
        .flatten()
        {
            charge(value.len())?;
        }
        for header in message.headers {
            charge(1)?; // Even empty header objects consume structural bytes.
            charge(header.name.len())?;
            charge(header.value.len())?;
        }
    }
    Ok(())
}

fn empty_packet(session_id: Uuid, evidence_id: &str, variant: PacketVariant) -> Packet<'_> {
    Packet {
        schema_version: 1,
        session_id,
        evidence_id,
        variant,
        available: false,
        status: "unavailable",
        reason: None,
        source: None,
        limits: Limits {
            packet_bytes: MAX_PACKET_BYTES,
            serialized_row_bytes: MAX_SERIALIZED_ROW_BYTES,
        },
        originals: None,
        request: None,
        response: None,
    }
}
pub fn unavailable(
    session_id: Uuid,
    evidence_id: &str,
    variant: PacketVariant,
    reason: &'static str,
) -> Vec<u8> {
    let evidence_id = if evidence_id.len() <= 200 {
        evidence_id
    } else {
        ""
    };
    let mut packet = empty_packet(session_id, evidence_id, variant);
    packet.reason = Some(reason);
    // API/store callers have already validated the bounded evidence token.
    encode(&packet, MAX_PACKET_BYTES).expect("bounded unavailable packet")
}

fn proves_empty(message: &MessageRecord) -> bool {
    let size = if message.content_decoded {
        message.decoded_body_size
    } else {
        Some(message.body_size)
    };
    size == Some(0) && !message.preview_truncated
}
fn preview<'a>(
    message: &MessageRecord,
    value: Option<&'a str>,
    unavailable: Option<&'static str>,
) -> (Option<&'a str>, Option<&'static str>) {
    // Verified complete-empty metadata needs no disk bytes. In particular a
    // decoded empty entity may still have a nonzero encoded body_size.
    if proves_empty(message) && value.is_none_or(str::is_empty) {
        return (Some(""), None);
    }
    if let Some(reason) = unavailable {
        return (None, Some(reason));
    }
    match value {
        Some(value) if !value.is_empty() || proves_empty(message) => (Some(value), None),
        _ => (None, Some("retained_preview_unavailable")),
    }
}

pub(crate) fn selected(
    record: &TransactionRecord,
    variant: PacketVariant,
) -> (Option<&MessageRecord>, Option<&MessageRecord>) {
    match variant {
        PacketVariant::Current => (Some(&record.request), record.response.as_ref()),
        PacketVariant::Original => (
            record.original_request.as_ref(),
            record.original_response.as_ref(),
        ),
    }
}

fn packet_side<'a>(
    record: &'a TransactionRecord,
    variant: PacketVariant,
    message: Option<&'a MessageRecord>,
    disk_message: Option<&'a DiskMessage>,
    uses_disk: bool,
    body_unavailable: Option<&'static str>,
    is_request: bool,
) -> Side<'a> {
    let Some(message) = message else {
        return Side {
            status: "not_retained",
            message: None,
        };
    };
    let value = match uses_disk {
        true => disk_message.and_then(|m| m.body_preview.as_deref()),
        false => Some(message.body_preview.as_str()),
    };
    let (body_preview, reason) = preview(message, value, body_unavailable);
    let current = variant == PacketVariant::Current;
    Side {
        status: "retained",
        message: Some(Message {
            method: if is_request {
                if current {
                    Some(record.method.as_str())
                } else {
                    record.original_method.as_deref()
                }
            } else {
                None
            },
            scheme: (is_request && current).then_some(record.scheme.as_str()),
            authority: (is_request && current).then_some(record.host.as_str()),
            path: if is_request {
                if current {
                    Some(record.path.as_str())
                } else {
                    record.original_path.as_deref()
                }
            } else {
                None
            },
            http_version: if !current {
                None
            } else if is_request {
                record.http_version.as_deref()
            } else {
                record.response_http_version.as_deref()
            },
            status_code: if !is_request && current {
                record.status
            } else {
                None
            },
            headers: &message.headers,
            body: Body {
                available: reason.is_none(),
                reason,
                body_preview,
                body_encoding: &message.body_encoding,
                body_size: message.body_size,
                decoded_body_size: message.decoded_body_size,
                preview_truncated: message.preview_truncated,
                content_decoded: message.content_decoded,
                content_type: message.content_type.as_deref(),
            },
        }),
    }
}

pub(crate) fn encode_record(
    session_id: Uuid,
    evidence_id: &str,
    variant: PacketVariant,
    record: &TransactionRecord,
    disk: Option<&DiskPair>,
    body_unavailable: Option<&'static str>,
) -> Result<Vec<u8>, &'static str> {
    let (request, response) = selected(record, variant);
    if let Some(disk) = disk {
        disk.verify(record, variant)?;
    }
    let mut packet = empty_packet(session_id, evidence_id, variant);
    packet.available = true;
    packet.status = "available";
    packet.source = Some(Source {
        record_id: record.id,
        sequence: record.sequence.to_string(),
        started_at: record.started_at,
    });
    packet.originals = Some(Originals {
        request: record.original_request.is_some(),
        response: record.original_response.is_some(),
    });
    packet.request = Some(packet_side(
        record,
        variant,
        request,
        disk.and_then(|r| r.request.as_ref()),
        disk.is_some(),
        body_unavailable,
        true,
    ));
    packet.response = Some(packet_side(
        record,
        variant,
        response,
        disk.and_then(|r| r.response.as_ref()),
        disk.is_some(),
        body_unavailable,
        false,
    ));
    admit_borrowed_leaves(&packet)?;
    encode(&packet, MAX_PACKET_BYTES)
}

#[derive(Deserialize)]
pub(crate) struct DiskMessage {
    #[serde(default)]
    headers: Vec<HeaderRecord>,
    body_preview: Option<String>,
    #[serde(default)]
    body_encoding: BodyEncoding,
    #[serde(default)]
    body_size: usize,
    decoded_body_size: Option<usize>,
    #[serde(default)]
    preview_truncated: bool,
    #[serde(default)]
    content_decoded: bool,
    content_type: Option<String>,
}
impl DiskMessage {
    fn matches(&self, message: &MessageRecord) -> bool {
        self.headers == message.headers
            && self.body_encoding == message.body_encoding
            && self.body_size == message.body_size
            && self.decoded_body_size == message.decoded_body_size
            && self.preview_truncated == message.preview_truncated
            && self.content_decoded == message.content_decoded
            && self.content_type == message.content_type
    }
}
pub(crate) struct DiskPair {
    id: Uuid,
    sequence: u64,
    started_at: DateTime<Utc>,
    request: Option<DiskMessage>,
    response: Option<DiskMessage>,
}
impl DiskPair {
    fn verify(
        &self,
        record: &TransactionRecord,
        variant: PacketVariant,
    ) -> Result<(), &'static str> {
        let (request, response) = selected(record, variant);
        let same =
            |disk: Option<&DiskMessage>, message: Option<&MessageRecord>| match (disk, message) {
                (None, None) => true,
                (Some(disk), Some(message)) => disk.matches(message),
                _ => false,
            };
        if self.id != record.id
            || self.sequence != record.sequence
            || self.started_at != record.started_at
            || !same(self.request.as_ref(), request)
            || !same(self.response.as_ref(), response)
        {
            return Err("body_identity_unverifiable");
        }
        Ok(())
    }
}
struct PairSeed(PacketVariant);
impl<'de> DeserializeSeed<'de> for PairSeed {
    type Value = DiskPair;
    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_map(self)
    }
}
impl<'de> Visitor<'de> for PairSeed {
    type Value = DiskPair;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a retained transaction row")
    }
    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
        let mut id = None;
        let mut sequence = None;
        let mut started_at = None;
        let mut request = None;
        let mut response = None;
        let mut request_seen = false;
        let mut response_seen = false;
        let (request_key, response_key) = match self.0 {
            PacketVariant::Current => ("request", "response"),
            PacketVariant::Original => ("original_request", "original_response"),
        };
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "id" => {
                    if id.is_some() {
                        return Err(M::Error::duplicate_field("id"));
                    }
                    id = Some(map.next_value()?);
                }
                "sequence" => {
                    if sequence.is_some() {
                        return Err(M::Error::duplicate_field("sequence"));
                    }
                    sequence = Some(map.next_value()?);
                }
                "started_at" => {
                    if started_at.is_some() {
                        return Err(M::Error::duplicate_field("started_at"));
                    }
                    started_at = Some(map.next_value()?);
                }
                name if name == request_key => {
                    if request_seen {
                        return Err(M::Error::custom("duplicate selected request"));
                    }
                    request_seen = true;
                    request = map.next_value()?;
                }
                name if name == response_key => {
                    if response_seen {
                        return Err(M::Error::custom("duplicate selected response"));
                    }
                    response_seen = true;
                    response = map.next_value()?;
                }
                _ => {
                    map.next_value::<serde::de::IgnoredAny>()?;
                }
            }
        }
        Ok(DiskPair {
            id: id.ok_or_else(|| M::Error::missing_field("id"))?,
            sequence: sequence.ok_or_else(|| M::Error::missing_field("sequence"))?,
            started_at: started_at.ok_or_else(|| M::Error::missing_field("started_at"))?,
            request,
            response,
        })
    }
}

pub(crate) fn read_pair(
    mut file: File,
    locator: BodyLocator,
    variant: PacketVariant,
) -> Result<DiskPair, &'static str> {
    let len = locator.len as usize;
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
    let mut bytes = vec![0; len];
    file.read_exact(&mut bytes)
        .map_err(|_| "body_read_failed")?;
    std::str::from_utf8(&bytes).map_err(|_| "malformed_retained_row")?;
    let mut deserializer = serde_json::Deserializer::from_slice(&bytes);
    let pair = PairSeed(variant)
        .deserialize(&mut deserializer)
        .map_err(|_| "malformed_retained_row")?;
    deserializer.end().map_err(|_| "malformed_retained_row")?;
    Ok(pair)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn record() -> TransactionRecord {
        let message = MessageRecord {
            headers: vec![],
            body_preview: String::new(),
            body_encoding: BodyEncoding::Utf8,
            body_size: 0,
            decoded_body_size: None,
            preview_truncated: false,
            content_type: None,
            content_decoded: false,
        };
        let mut record = TransactionRecord::http(
            Utc::now(),
            "POST".into(),
            "https".into(),
            "example.com:443".into(),
            "/path?q=1".into(),
            Some(201),
            1,
            message.clone(),
            Some(message),
            vec!["private note".into()],
            None,
            None,
        );
        record.sequence = 9_007_199_254_740_993;
        record.http_version = Some("HTTP/2.0".into());
        record
    }
    fn view(record: &TransactionRecord, variant: PacketVariant) -> serde_json::Value {
        serde_json::from_slice(
            &encode_record(Uuid::nil(), "token", variant, record, None, None).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn packet_counting_is_exact_for_escaping_unicode_nulls_and_refuses_before_emission() {
        struct Observed<'a> {
            calls: &'a Cell<usize>,
            value: &'a str,
        }
        impl Serialize for Observed<'_> {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                self.calls.set(self.calls.get() + 1);
                serializer.serialize_str(self.value)
            }
        }
        for value in ["", "\0\n\r\t\"\\", "한글😀", "flag"] {
            let calls = Cell::new(0);
            let value = Observed {
                calls: &calls,
                value,
            };
            let expected = serde_json::to_vec(&value).unwrap();
            calls.set(0);
            assert_eq!(encode(&value, expected.len()).unwrap(), expected);
            assert_eq!(calls.get(), 2);
            calls.set(0);
            assert_eq!(
                encode(&value, expected.len() - 1).unwrap_err(),
                "packet_view_limit"
            );
            assert_eq!(calls.get(), 1, "refusal must not reach emission");
        }
        assert_eq!(encode(&Option::<String>::None, 4).unwrap(), b"null");
        assert!(encode(&Option::<String>::None, 3).is_err());
    }

    #[test]
    fn packet_preserves_pair_header_order_large_sequence_and_unknown_protocol() {
        let mut record = record();
        record.request.headers = vec![
            HeaderRecord {
                name: "Cookie".into(),
                value: "a=1".into(),
            },
            HeaderRecord {
                name: "Cookie".into(),
                value: "b=2".into(),
            },
        ];
        record.user_note = Some("not exported".into());
        let packet = view(&record, PacketVariant::Current);
        assert_eq!(packet["source"]["sequence"], "9007199254740993");
        assert_eq!(packet["request"]["message"]["authority"], "example.com:443");
        assert_eq!(
            packet["request"]["message"]["headers"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            packet["response"]["message"]["http_version"],
            serde_json::Value::Null
        );
        assert_eq!(packet["response"]["message"]["status_code"], 201);
        let text = packet.to_string();
        assert!(
            !text.contains("private note")
                && !text.contains("not exported")
                && !text.contains("user_note")
        );
    }

    #[test]
    fn packet_originals_are_explicit_and_never_borrow_current_lines() {
        let mut record = record();
        assert_eq!(
            view(&record, PacketVariant::Original)["request"]["status"],
            "not_retained"
        );
        record.original_request = Some(record.request.clone());
        record.original_response = record.response.clone();
        record.original_method = Some("PUT".into());
        record.original_path = Some("/before".into());
        let packet = view(&record, PacketVariant::Original);
        assert_eq!(packet["request"]["message"]["method"], "PUT");
        assert_eq!(packet["request"]["message"]["path"], "/before");
        for name in ["scheme", "authority", "http_version", "status_code"] {
            assert!(packet["request"]["message"][name].is_null());
            assert!(packet["response"]["message"][name].is_null());
        }
        assert!(packet["originals"]["request"].as_bool().unwrap());
    }

    #[test]
    fn packet_distinguishes_decoded_empty_missing_and_truncated_previews_without_decoding() {
        let mut record = record();
        record.request.body_size = 20;
        record.request.content_decoded = true;
        record.request.decoded_body_size = Some(0);
        let packet = view(&record, PacketVariant::Current);
        assert_eq!(packet["request"]["message"]["body"]["body_preview"], "");
        assert_eq!(packet["request"]["message"]["body"]["available"], true);
        record.request.decoded_body_size = None;
        let packet = view(&record, PacketVariant::Current);
        assert_eq!(packet["request"]["message"]["body"]["available"], false);
        assert!(packet["request"]["message"]["body"]["body_preview"].is_null());
        record.request.body_preview = "AAE=".into();
        record.request.body_encoding = BodyEncoding::Base64;
        record.request.preview_truncated = true;
        let packet = view(&record, PacketVariant::Current);
        assert_eq!(packet["request"]["message"]["body"]["body_preview"], "AAE=");
        assert_eq!(
            packet["request"]["message"]["body"]["preview_truncated"],
            true
        );
    }

    #[test]
    fn packet_has_only_the_whole_json_limit_not_catalog_or_scanner_mini_limits() {
        let mut record = record();
        record.request.headers = (0..129)
            .map(|i| HeaderRecord {
                name: format!("X-{i}"),
                value: "v".into(),
            })
            .collect();
        record.request.headers[0].value = "v".repeat(4097);
        record.request.body_preview = "a".repeat(129 * 1024);
        record.request.body_size = record.request.body_preview.len();
        assert!(encode_record(
            Uuid::nil(),
            "t",
            PacketVariant::Current,
            &record,
            None,
            None
        )
        .is_ok());
        record.request.body_preview = "\0".repeat(MAX_PACKET_BYTES / 6);
        record.request.body_size = record.request.body_preview.len();
        assert_eq!(
            encode_record(
                Uuid::nil(),
                "t",
                PacketVariant::Current,
                &record,
                None,
                None
            )
            .unwrap_err(),
            "packet_view_limit"
        );
        let packet: serde_json::Value = serde_json::from_slice(&unavailable(
            Uuid::nil(),
            "t",
            PacketVariant::Current,
            "packet_view_limit",
        ))
        .unwrap();
        for key in ["source", "originals", "request", "response"] {
            assert!(packet[key].is_null());
        }
    }

    #[test]
    fn packet_disk_projection_ignores_unselected_fields_but_checks_selected_metadata() {
        let mut record = record();
        record.original_request = Some(record.request.clone());
        let mut raw = serde_json::to_value(&record).unwrap();
        raw["notes"] = serde_json::json!({"ignored":"arbitrary old annotations"});
        raw["response"] = serde_json::json!({"body_preview":false});
        let bytes = serde_json::to_vec(&raw).unwrap();
        let mut parser = serde_json::Deserializer::from_slice(&bytes);
        let original = PairSeed(PacketVariant::Original)
            .deserialize(&mut parser)
            .unwrap();
        assert!(original.verify(&record, PacketVariant::Original).is_ok());
        let mut parser = serde_json::Deserializer::from_slice(&bytes);
        assert!(PairSeed(PacketVariant::Current)
            .deserialize(&mut parser)
            .is_err());
    }
}
