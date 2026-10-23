//! Bounded, passive projections of retained HTTP metadata. No body reads, probes,
//! persistent indexes, or claims about unobserved upstream infrastructure.
use std::collections::{BTreeMap, BTreeSet, HashMap};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;

use crate::service_map_technology::{
    self as technology, TechnologyAggregate, TechnologyObservation,
};
use crate::{model::TransactionRecord, scope};

pub const DEFAULT_MAX_RECORDS: usize = 10_000;
pub const MAX_RECORDS: usize = 50_000;
pub const MAX_METADATA_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_ORIGINS: usize = 500;
pub const MAX_ENDPOINTS: usize = 2_000;
pub const MAX_ENDPOINTS_PER_ORIGIN: usize = 500;
pub const MAX_EVIDENCE: usize = 3;
pub const MAX_REDIRECTS_PER_ORIGIN: usize = 100;
pub const MAX_HEADER_LINKS_PER_ORIGIN: usize = 100;
pub const MAX_TECHNOLOGY_CLUES_PER_ROW: usize = 8;
pub const MAX_PATH_BYTES: usize = 2_048;
pub const MAX_HOST_BYTES: usize = 512;
pub const MAX_METHOD_BYTES: usize = 32;
pub const MAX_HEADERS: usize = 128;
pub const MAX_HEADER_BYTES: usize = 32 * 1024;
pub const MAX_HEADER_VALUE_BYTES: usize = 4_096;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServiceMapLimits {
    pub max_records: usize,
    pub metadata_bytes: usize,
    pub origins: usize,
    pub endpoints: usize,
    pub endpoints_per_origin: usize,
    pub evidence_per_item: usize,
    pub redirects_per_origin: usize,
    pub header_links_per_origin: usize,
    pub technology_clues_per_row: usize,
    #[serde(
        default,
        deserialize_with = "optional_present",
        skip_serializing_if = "Option::is_none"
    )]
    pub technology_observations_per_row: Option<usize>,
    #[serde(
        default,
        deserialize_with = "optional_present",
        skip_serializing_if = "Option::is_none"
    )]
    pub technology_observations_per_origin: Option<usize>,
    #[serde(
        default,
        deserialize_with = "optional_present",
        skip_serializing_if = "Option::is_none"
    )]
    pub technology_observations: Option<usize>,
    #[serde(
        default,
        deserialize_with = "optional_present",
        skip_serializing_if = "Option::is_none"
    )]
    pub technology_version_bytes: Option<usize>,
    #[serde(
        default,
        deserialize_with = "optional_present",
        skip_serializing_if = "Option::is_none"
    )]
    pub technology_token_candidates_per_row: Option<usize>,
    pub statuses_per_endpoint: usize,
    pub content_types_per_endpoint: usize,
    pub path_bytes: usize,
    pub host_bytes: usize,
    pub method_bytes: usize,
    pub headers_per_row: usize,
    pub header_bytes_per_row: usize,
    pub header_value_bytes: usize,
}

impl ServiceMapLimits {
    fn new(max_records: usize) -> Self {
        Self {
            max_records,
            metadata_bytes: MAX_METADATA_BYTES,
            origins: MAX_ORIGINS,
            endpoints: MAX_ENDPOINTS,
            endpoints_per_origin: MAX_ENDPOINTS_PER_ORIGIN,
            evidence_per_item: MAX_EVIDENCE,
            redirects_per_origin: MAX_REDIRECTS_PER_ORIGIN,
            header_links_per_origin: MAX_HEADER_LINKS_PER_ORIGIN,
            technology_clues_per_row: MAX_TECHNOLOGY_CLUES_PER_ROW,
            technology_observations_per_row: Some(technology::MAX_OBSERVATIONS_PER_ROW),
            technology_observations_per_origin: Some(technology::MAX_OBSERVATIONS_PER_ORIGIN),
            technology_observations: Some(technology::MAX_OBSERVATIONS),
            technology_version_bytes: Some(technology::MAX_VERSION_BYTES),
            technology_token_candidates_per_row: Some(technology::MAX_TOKEN_CANDIDATES_PER_ROW),
            statuses_per_endpoint: 32,
            content_types_per_endpoint: 16,
            path_bytes: MAX_PATH_BYTES,
            host_bytes: MAX_HOST_BYTES,
            method_bytes: MAX_METHOD_BYTES,
            headers_per_row: MAX_HEADERS,
            header_bytes_per_row: MAX_HEADER_BYTES,
            header_value_bytes: MAX_HEADER_VALUE_BYTES,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServiceMapSnapshot {
    pub window_order: String,
    /// A fresh response ID; this is not a persistent cache or replayable cursor.
    pub id: Uuid,
    /// Store incarnation. Reopening an inactive session may invalidate evidence.
    pub generation: Uuid,
    pub captured_at: DateTime<Utc>,
    pub first_retained_started_at: Option<DateTime<Utc>>,
    pub last_retained_started_at: Option<DateTime<Utc>>,
    pub oldest_considered_at: Option<DateTime<Utc>>,
    pub latest_considered_at: Option<DateTime<Utc>>,
    pub retained_rows: usize,
    pub considered_rows: usize,
    pub non_http_rows: usize,
    /// Considered rows hidden by the request's display filter, as HTTP history
    /// would hide them. Absent when nothing was hidden, as from older servers,
    /// so an unfiltered map keeps its earlier shape.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub filtered_rows: usize,
    pub projected_rows: usize,
    pub included_rows: usize,
    pub excluded_rows: usize,
    pub omitted_rows: usize,
    pub origin_count: usize,
    pub endpoint_count: usize,
    pub complete: bool,
    pub stopped_by: Vec<String>,
    pub limits: ServiceMapLimits,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServiceMap {
    pub schema_version: u32,
    /// Absent means the legacy revision-1 contract; explicit requests are marked.
    #[serde(
        default,
        deserialize_with = "optional_present",
        skip_serializing_if = "Option::is_none"
    )]
    pub technology_catalog_version: Option<u32>,
    pub session_id: Uuid,
    pub snapshot: ServiceMapSnapshot,
    pub in_scope_only: bool,
    pub origin_filter: Option<String>,
    pub origins: Vec<ServiceOrigin>,
    /// The clients that sent the analyzed rows, busiest first. Absent when
    /// none, as on older servers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub clients: Vec<ServiceClient>,
    pub unavailable: Vec<String>,
    pub deferred: Vec<String>,
    pub warnings: Vec<String>,
}

/// A client its User-Agent names, and the origins it sent rows to.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServiceClient {
    /// One of `service_map_clients::KINDS`.
    pub kind: String,
    pub name: String,
    /// The major versions its rows named, newest first: one browser updated
    /// over a session is one client, not one per version.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub versions: Vec<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    pub request_count: usize,
    /// The addresses it connected to the proxy from: this machine, or a phone
    /// on the network. At most 8; absent when none was kept.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<String>,
    /// Busiest first.
    pub origins: Vec<ClientOrigin>,
    pub evidence: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientOrigin {
    pub origin: String,
    pub request_count: usize,
    /// Rows the client sent here itself, with no Origin or Referer (a typed
    /// address, a bookmark, an app's call), by request kind. Absent when a
    /// page started every row.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub entry_kinds: BTreeMap<String, usize>,
}

const MAX_CLIENTS: usize = 16;
const MAX_CLIENT_ORIGINS: usize = 64;
const MAX_CLIENT_ADDRESSES: usize = 8;
const MAX_UNNAMED: usize = 16;
const MAX_UNNAMED_PER_ROW: usize = 16;
/// Distinct unnamed values or auth names one read tracks per origin and kind
/// before `finish` keeps the most widespread: a server that names a header or a
/// cookie afresh on every answer must not grow the read without end.
const MAX_TRACKED_PER_ORIGIN_KIND: usize = 256;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServiceOrigin {
    pub origin: String,
    pub host: String,
    pub scheme: String,
    pub port: u16,
    pub in_scope: bool,
    /// Captured rows, not distinct UUIDs or inferred calls.
    pub request_count: usize,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub endpoints: Vec<ServiceEndpoint>,
    pub technology_clues: Vec<TechnologyClue>,
    #[serde(
        default,
        deserialize_with = "optional_present",
        skip_serializing_if = "Option::is_none"
    )]
    pub technology_observations: Option<Vec<TechnologyAggregate>>,
    pub redirects: Vec<RedirectInstruction>,
    pub header_links: Vec<HeaderLink>,
    /// The same rows per source origin, a row naming it in both headers counted
    /// once, so an arrow for both counts requests. Absent when none, as on older
    /// servers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub header_sources: Vec<HeaderSource>,
    /// Library and framework versions retained scripts and pages declare; see
    /// `service_map_libraries`. Absent when none, as on older servers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub front_technologies: Vec<FrontTechnology>,
    /// What the origin's own headers, cookies and bodies say about the servers
    /// behind it, and what they expose. See `service_map_servers`. Absent when
    /// none, as on older servers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub server_technologies: Vec<ServerTechnology>,
    /// The evidence of the origin's newest retained icon, which the GUI's card
    /// shows. See `favicon_origin`. Absent when none was captured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub favicon: Option<String>,
    /// How its requests authenticate, read from names and shapes only. See
    /// `service_map_auth`. Absent when no row named a method.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub auth: Vec<AuthMethod>,
    /// What its responses carried that no rule names, for a reader to judge:
    /// a `Server` or `X-Powered-By` value, a header name, a cookie name.
    /// Absent when everything was named.
    #[serde(default, skip_serializing_if = "Unnamed::is_empty")]
    pub unnamed: Unnamed,
}

/// Signals no rule names, busiest first, at most 16 of each.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Unnamed {
    /// `Server` and `X-Powered-By` values, as `server: HeRay`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub banners: Vec<UnnamedSignal>,
    /// Response header names no server sends by default.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<UnnamedSignal>,
    /// Names of the cookies its responses set.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cookies: Vec<UnnamedSignal>,
}

impl Unnamed {
    pub fn is_empty(&self) -> bool {
        self.banners.is_empty() && self.headers.is_empty() && self.cookies.is_empty()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnnamedSignal {
    pub value: String,
    pub row_count: usize,
    pub evidence: Vec<String>,
}

/// One way an origin's requests authenticate: a scheme, an API key header, a
/// session cookie, or a sign-in flow, with the rows that showed it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthMethod {
    /// One of `service_map_auth::KINDS`.
    pub kind: String,
    /// The header, cookie or parameter name, or the scheme, when the kind has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub row_count: usize,
    pub evidence: Vec<String>,
}

/// A server-side technology, or an exposure, an origin's own responses name.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerTechnology {
    pub product_id: String,
    pub name: String,
    /// One of `service_map_servers::CATEGORIES`.
    pub category: String,
    /// Absent when no row named one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Where it was seen: `header`, `cookie` or `body`.
    pub signals: Vec<String>,
    pub row_count: usize,
    pub evidence: Vec<String>,
}

const MAX_SERVER_TECHNOLOGIES_PER_ORIGIN: usize = 32;

/// A front-end technology a retained script, page or asset URL names. An asset's
/// goes to the page that loaded it (its Referer) when that page is in the map,
/// else to the asset's own origin; a page's stays with the page.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FrontTechnology {
    pub product_id: String,
    pub name: String,
    /// One of `service_map_libraries::CATEGORIES`.
    pub category: String,
    /// Absent when no row named one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Where every retained evidence row in this group was served from.
    pub source_origin: String,
    pub row_count: usize,
    pub evidence: Vec<String>,
}

const MAX_FRONT_TECHNOLOGIES_PER_ORIGIN: usize = 32;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServiceEndpoint {
    pub method: String,
    /// Exact captured path without query or fragment. Never a guessed route.
    pub path: String,
    /// A display hint only; exact endpoints are never merged by this value.
    pub path_group: Option<String>,
    pub request_count: usize,
    pub statuses: Vec<u16>,
    pub content_types: Vec<String>,
    pub evidence: Vec<String>,
    /// The `service_map_auth::KINDS` its rows showed, in that order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub auth: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TechnologyClue {
    pub name: String,
    pub source: String,
    pub header_name: String,
    pub confidence: String,
    pub evidence: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RedirectInstruction {
    pub target_origin: String,
    pub target_path: String,
    pub relationship: String,
    pub source: String,
    pub evidence: Vec<String>,
    /// Analyzed rows that gave this instruction. Absent from older servers.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub request_count: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HeaderLink {
    pub source_origin: String,
    pub relationship: String,
    pub source: String,
    pub evidence: Vec<String>,
    /// Analyzed rows carrying this declaration, and how many were each kind of
    /// request (see `request_kind`). Absent from older servers.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub request_count: usize,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub request_kinds: BTreeMap<String, usize>,
    /// Of those rows, how many responses let this source origin read them (a
    /// single Access-Control-Allow-Origin naming it or `*`), and how many named
    /// it and allowed credentials too. Absent when none, as on older servers.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub cors_allowed_count: usize,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub cors_credentials_count: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HeaderSource {
    pub source_origin: String,
    pub request_count: usize,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub request_kinds: BTreeMap<String, usize>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub cors_allowed_count: usize,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub cors_credentials_count: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HeaderLinkSource {
    pub source_origin: String,
    pub relationship: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HeaderClue {
    pub name: String,
    pub header_name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RedirectTarget {
    pub target_origin: String,
    pub target_path: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServiceMapRow {
    // URL canonicalization can compress IPv6 or encode IDNs differently from
    // the shared history matcher. Retain the bounded captured authority only
    // for internal scope decisions; never serialize potential userinfo.
    #[serde(skip)]
    pub(crate) scope_host: String,
    pub evidence_id: String,
    pub record_id: Uuid,
    /// String preserves row identity in JavaScript beyond 2^53.
    pub sequence: String,
    pub started_at: DateTime<Utc>,
    pub method: String,
    pub origin: String,
    pub host: String,
    pub scheme: String,
    pub port: u16,
    pub path: String,
    pub status: Option<u16>,
    pub content_type: Option<String>,
    pub is_websocket: bool,
    pub technology_clues: Vec<HeaderClue>,
    #[serde(
        default,
        deserialize_with = "optional_present",
        skip_serializing_if = "Option::is_none"
    )]
    pub technology_observations: Option<Vec<TechnologyObservation>>,
    pub redirect: Option<RedirectTarget>,
    pub header_links: Vec<HeaderLinkSource>,
    pub metadata_complete: bool,
    pub omitted: Vec<String>,
    /// Aggregated onto links only; exact evidence keeps its earlier shape.
    #[serde(skip)]
    pub request_kind: &'static str,
    /// A single Access-Control-Allow-Origin value as sent, and whether
    /// credentials were allowed with it; aggregated onto links only.
    #[serde(skip)]
    pub cors: Option<(String, bool)>,
    /// The technologies this row's URL names, then those its script or page
    /// body declares, which the store reads once per row revision.
    #[serde(skip)]
    pub libraries: Vec<crate::service_map_libraries::Detection>,
    /// The client its User-Agent and Client Hints name; aggregated only.
    #[serde(skip)]
    pub client: Option<crate::service_map_clients::Client>,
    /// Response headers no rule named: (`banner`, `header` or `cookie`, value).
    #[serde(skip)]
    pub unnamed: Vec<(&'static str, String)>,
    /// Sent from Replay, or kept by Template Scan because a template matched
    /// it: a request someone chose, whose answer is read whatever its status.
    #[serde(skip)]
    pub sent_from_replay: bool,
    /// The address the client connected to the proxy from, when kept.
    #[serde(skip)]
    pub client_address: Option<std::net::IpAddr>,
    /// It sent an Origin or Referer: a page started it, not the client itself.
    #[serde(skip)]
    pub initiated: bool,
    /// How it authenticated; aggregated only.
    #[serde(skip)]
    pub auth: Vec<crate::service_map_auth::AuthSignal>,
}

/// Every value `request_kind` returns, in the order clients present them.
pub const REQUEST_KINDS: [&str; 6] = ["api", "navigation", "frame", "script", "static", "other"];

/// What a row's request was, so a page loading an image is not drawn like a
/// page calling an API. Browsers declare it in `Sec-Fetch-Dest`; a client that
/// sends none (an app, a script) is judged by the response type, and then by an
/// Origin header or a non-GET method, which mark an API call.
pub(crate) fn request_kind(record: &TransactionRecord) -> &'static str {
    let header = |name: &str| {
        let mut values = record
            .request
            .headers
            .iter()
            .filter(|header| header.name.eq_ignore_ascii_case(name));
        match (values.next(), values.next()) {
            (Some(header), None) => Some(header.value.trim().to_ascii_lowercase()),
            _ => None,
        }
    };
    if let Some(dest) = header("sec-fetch-dest") {
        return match dest.as_str() {
            "empty" => "api",
            "document" => "navigation",
            "iframe" | "frame" | "embed" | "object" | "fencedframe" => "frame",
            "script" | "worker" | "sharedworker" | "serviceworker" | "audioworklet"
            | "paintworklet" | "xslt" => "script",
            "image" | "style" | "font" | "audio" | "video" | "track" | "manifest" => "static",
            _ => "other",
        };
    }
    let content_type = record
        .response
        .as_ref()
        .and_then(|response| response.content_type.as_deref())
        .unwrap_or("")
        .to_ascii_lowercase();
    if content_type.contains("html") {
        return "navigation";
    }
    if content_type.contains("javascript") || content_type.contains("ecmascript") {
        return "script";
    }
    // Before the data types: an SVG image is `image/svg+xml`.
    if ["image/", "font/", "audio/", "video/", "text/css"]
        .iter()
        .any(|prefix| content_type.starts_with(prefix))
        || content_type.contains("font")
    {
        return "static";
    }
    if ["json", "xml", "protobuf", "grpc", "graphql"]
        .iter()
        .any(|kind| content_type.contains(kind))
    {
        return "api";
    }
    if header("origin").is_some() || !matches!(record.method.as_str(), "GET" | "HEAD") {
        return "api";
    }
    "other"
}

/// Extensions may be absent on old servers, but a present null is malformed.
fn optional_present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

fn is_zero(value: &usize) -> bool {
    *value == 0
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServiceMapEvidence {
    pub schema_version: u32,
    /// Absent means the legacy revision-1 contract; explicit requests are marked.
    #[serde(
        default,
        deserialize_with = "optional_present",
        skip_serializing_if = "Option::is_none"
    )]
    pub technology_catalog_version: Option<u32>,
    pub session_id: Uuid,
    pub evidence_id: String,
    pub available: bool,
    pub reason: Option<String>,
    pub source: String,
    pub row: Option<ServiceMapRow>,
    /// Explicit exact-source extension. Omitted from the default v1 response and
    /// never part of the aggregate metadata projection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socket_peer: Option<ServiceMapSocketPeerEvidence>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceMapSocketPeerStatus {
    Observed,
    NotRecorded,
    Unavailable,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceMapSocketPeerEvidence {
    pub status: ServiceMapSocketPeerStatus,
    pub observation: Option<crate::model::ObservedSocketPeer>,
}

impl ServiceMapSocketPeerEvidence {
    pub(crate) fn from_record(record: &TransactionRecord) -> Self {
        let observation = record
            .observed_socket_peer
            .as_ref()
            .filter(|observation| observation.is_valid())
            .cloned();
        let status = match observation.as_ref() {
            Some(observation) if observation.address.is_some() => {
                ServiceMapSocketPeerStatus::Observed
            }
            Some(_) => ServiceMapSocketPeerStatus::Unavailable,
            None => ServiceMapSocketPeerStatus::NotRecorded,
        };
        Self {
            status,
            observation,
        }
    }
}

impl ServiceMapEvidence {
    pub(crate) fn missing(session_id: Uuid, evidence_id: String, reason: &str) -> Self {
        Self {
            schema_version: 1,
            technology_catalog_version: None,
            session_id,
            evidence_id,
            available: false,
            reason: Some(reason.into()),
            source: "captured_http_metadata".into(),
            row: None,
            socket_peer: None,
        }
    }

    pub(crate) fn found(session_id: Uuid, row: ServiceMapRow) -> Self {
        Self {
            schema_version: 1,
            technology_catalog_version: None,
            session_id,
            evidence_id: row.evidence_id.clone(),
            available: true,
            reason: None,
            source: "captured_http_metadata".into(),
            row: Some(row),
            socket_peer: None,
        }
    }
}

#[derive(Clone)]
pub(crate) struct MetadataSnapshot {
    pub generation: Uuid,
    pub captured_at: DateTime<Utc>,
    pub first_retained_started_at: Option<DateTime<Utc>>,
    pub last_retained_started_at: Option<DateTime<Utc>>,
    pub oldest_considered_at: Option<DateTime<Utc>>,
    pub latest_considered_at: Option<DateTime<Utc>>,
    pub retained_rows: usize,
    pub considered_rows: usize,
    pub non_http_rows: usize,
    pub filtered_rows: usize,
    pub omitted_rows: usize,
    pub stopped_by: BTreeSet<String>,
    pub rows: Vec<ServiceMapRow>,
    /// Each origin's newest icon row by evidence, read before the display
    /// filter, which hides `ico` and `png` rows by default.
    pub favicons: BTreeMap<String, String>,
}

#[derive(Debug)]
pub(crate) struct EvidenceKey {
    pub session_id: Uuid,
    pub generation: Uuid,
    pub sequence: u64,
    pub revision: Uuid,
    pub record_id: Uuid,
}

impl EvidenceKey {
    pub(crate) fn parse(value: &str) -> Option<Self> {
        if value.len() > 200 {
            return None;
        }
        let fields: Vec<_> = value.split('.').collect();
        if fields.len() != 6 || fields[0] != "v1" {
            return None;
        }
        let sequence = fields[3].parse::<u64>().ok()?;
        if sequence.to_string() != fields[3] {
            return None;
        }
        Some(Self {
            session_id: fields[1].parse().ok()?,
            generation: fields[2].parse().ok()?,
            sequence,
            revision: fields[4].parse().ok()?,
            record_id: fields[5].parse().ok()?,
        })
    }
}

pub(crate) fn evidence_id(
    session_id: Uuid,
    generation: Uuid,
    revision: Uuid,
    record: &TransactionRecord,
) -> String {
    format!(
        "v1.{session_id}.{generation}.{}.{revision}.{}",
        record.sequence, record.id
    )
}

/// Normalize an HTTP(S) URL to a safe origin. Filter callers also require exact
/// equality with the input so credentials, paths and queries are not accepted.
/// URL's origin serialization never includes userinfo.
pub fn canonical_origin(value: &str) -> Option<String> {
    if value.len() > MAX_HOST_BYTES + 32 {
        return None;
    }
    let url = Url::parse(value).ok()?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return None;
    }
    Some(url.origin().ascii_serialization())
}

pub(crate) fn request_target(record: &TransactionRecord) -> Option<(Url, String)> {
    if record.scheme.len() > 8
        || record.host.len() > MAX_HOST_BYTES
        || record.method.is_empty()
        || record.method.len() > MAX_METHOD_BYTES
        || !record
            .method
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
        || record.host.contains(['/', '?', '#', '\\'])
        || record
            .host
            .chars()
            .any(|c| c.is_whitespace() || c.is_control())
    {
        return None;
    }
    let scheme = record.scheme.to_ascii_lowercase();
    if !matches!(scheme.as_str(), "http" | "https") {
        return None;
    }
    let base = Url::parse(&format!("{scheme}://{}/", record.host)).ok()?;
    if base.host_str()?.len() > MAX_HOST_BYTES {
        return None;
    }
    // The query is never read, and a path longer than an endpoint may hold
    // still names its origin: a tracking pixel's 6 KiB query, a script's
    // encoded path. The map leaves out only that endpoint.
    let path = record.path.split(['?', '#']).next().unwrap_or("");
    if !path.starts_with('/') || path.chars().any(char::is_control) {
        return None;
    }
    Some((base, path.to_string()))
}

fn mime(value: &str) -> Option<String> {
    if value.len() > MAX_HEADER_VALUE_BYTES {
        return None;
    }
    let value = value.split(';').next()?.trim();
    if value.len() > 128
        || !value.contains('/')
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'.' | b'+' | b'_'))
    {
        return None;
    }
    Some(value.to_ascii_lowercase())
}

fn product(value: &str, expected: &str) -> bool {
    value
        .get(..expected.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(expected))
        && value
            .as_bytes()
            .get(expected.len())
            .is_none_or(|b| matches!(b, b'/' | b' ' | b';' | b','))
}

/// The most ways one origin's requests authenticate that the map lists.
const MAX_AUTH_METHODS: usize = 16;

/// The largest icon the map serves; a site's favicon is a few KiB.
pub(crate) const MAX_FAVICON_BYTES: usize = 64 * 1024;

/// The origin whose own icon this row is: a GET answered 200 with an image
/// at a `favicon…` or `apple-touch-icon…` path, kept whole. The map shows it
/// instead of a letter; it never asks a target for one.
pub(crate) fn favicon_origin(record: &TransactionRecord) -> Option<String> {
    if record.method != "GET" || record.status != Some(200) {
        return None;
    }
    // The file name first: it rules out nearly every row without allocating.
    let name = record.path.split(['?', '#']).next()?.rsplit('/').next()?;
    let named = |prefix: &str| {
        name.get(..prefix.len())
            .is_some_and(|start| start.eq_ignore_ascii_case(prefix))
    };
    if !named("favicon") && !named("apple-touch-icon") {
        return None;
    }
    let response = record.response.as_ref()?;
    let image = response.content_type.as_deref().is_some_and(|value| {
        let value = value.trim_start().to_ascii_lowercase();
        value.starts_with("image/") && !value.contains("svg")
    });
    if !image || response.preview_truncated || response.body_size > MAX_FAVICON_BYTES {
        return None;
    }
    Some(request_target(record)?.0.origin().ascii_serialization())
}

/// The type an icon's own bytes declare. Only raster formats: an SVG can carry
/// script, and the response header may say anything.
pub(crate) fn favicon_type(bytes: &[u8]) -> Option<&'static str> {
    match bytes {
        _ if bytes.len() > MAX_FAVICON_BYTES => None,
        [0x89, b'P', b'N', b'G', ..] => Some("image/png"),
        [0, 0, 1, 0, ..] => Some("image/x-icon"),
        [b'G', b'I', b'F', b'8', ..] => Some("image/gif"),
        [0xFF, 0xD8, 0xFF, ..] => Some("image/jpeg"),
        [b'R', b'I', b'F', b'F', _, _, _, _, b'W', b'E', b'B', b'P', ..] => Some("image/webp"),
        _ => None,
    }
}

pub(crate) fn project_record(record: &TransactionRecord, id: String) -> Option<ServiceMapRow> {
    project_record_for_catalog(record, id, technology::CatalogVersion::V1)
}

pub(crate) fn project_record_for_catalog(
    record: &TransactionRecord,
    id: String,
    catalog: technology::CatalogVersion,
) -> Option<ServiceMapRow> {
    if record.method == "CONNECT" {
        return None;
    }
    let (base, path) = request_target(record)?;
    let origin = base.origin().ascii_serialization();
    let host = base.host_str()?.trim_matches(['[', ']']).to_string();
    let mut row = ServiceMapRow {
        scope_host: record.host.clone(),
        evidence_id: id,
        record_id: record.id,
        sequence: record.sequence.to_string(),
        started_at: record.started_at,
        method: record.method.clone(),
        origin,
        host,
        scheme: base.scheme().into(),
        port: base.port_or_known_default()?,
        path,
        status: record.status,
        content_type: record
            .response
            .as_ref()
            .and_then(|m| m.content_type.as_deref())
            .and_then(mime),
        is_websocket: false,
        technology_clues: vec![],
        technology_observations: Some(vec![]),
        redirect: None,
        header_links: vec![],
        metadata_complete: true,
        omitted: vec![],
        request_kind: request_kind(record),
        cors: None,
        libraries: Vec::new(),
        client: None,
        unnamed: Vec::new(),
        sent_from_replay: record.notes.iter().any(|note| {
            note == crate::model::REPLAY_NOTE
                || note == crate::model::TEMPLATE_SCAN_NOTE
                || note == crate::model::LEGACY_TEMPLATE_SCAN_NOTE
                || note == crate::model::FUZZER_NOTE
        }),
        client_address: record.client_address,
        initiated: false,
        auth: Vec::new(),
    };
    // A script, stylesheet or image URL can name its product without a body.
    if matches!(row.request_kind, "script" | "static") {
        row.libraries =
            crate::service_map_libraries::detect_url(&format!("{}{}", row.origin, row.path));
    }
    if record
        .response
        .as_ref()
        .and_then(|m| m.content_type.as_ref())
        .is_some()
        && row.content_type.is_none()
    {
        row.omitted.push("unsupported_content_type".into());
    }
    let mut request_header_bytes = 0usize;
    let mut request_headers_scanned = 0usize;
    let mut websocket_upgrade = false;
    let mut connection_upgrade = false;
    let mut origin_values = Vec::new();
    let mut referer_values = Vec::new();
    let (mut user_agent, mut brands, mut platform) = (None, None, None);
    for (index, header) in record.request.headers.iter().enumerate() {
        request_header_bytes = request_header_bytes
            .saturating_add(header.name.len())
            .saturating_add(header.value.len());
        if index >= MAX_HEADERS || request_header_bytes > MAX_HEADER_BYTES {
            row.omitted.push("request_header_scan_limit".into());
            break;
        }
        request_headers_scanned += 1;
        if header.value.len() > MAX_HEADER_VALUE_BYTES {
            row.omitted.push("request_header_value_limit".into());
            continue;
        }
        if header.name.eq_ignore_ascii_case("upgrade") {
            websocket_upgrade |= header
                .value
                .split(',')
                .any(|value| value.trim().eq_ignore_ascii_case("websocket"));
        }
        if header.name.eq_ignore_ascii_case("connection") {
            connection_upgrade |= header
                .value
                .split(',')
                .any(|value| value.trim().eq_ignore_ascii_case("upgrade"));
        }
        if header.name.eq_ignore_ascii_case("origin") {
            origin_values.push(header.value.as_str());
        }
        if header.name.eq_ignore_ascii_case("referer") {
            referer_values.push(header.value.as_str());
        }
        for (name, value) in [
            ("user-agent", &mut user_agent),
            ("sec-ch-ua", &mut brands),
            ("sec-ch-ua-platform", &mut platform),
        ] {
            if header.name.eq_ignore_ascii_case(name) {
                value.get_or_insert(header.value.as_str());
            }
        }
    }
    row.is_websocket = record.status == Some(101) && websocket_upgrade && connection_upgrade;
    row.client = Some(crate::service_map_clients::classify(
        user_agent, brands, platform,
    ));
    row.initiated = !origin_values.is_empty() || !referer_values.is_empty();
    row.auth = crate::service_map_auth::detect(record);
    if !row
        .omitted
        .iter()
        .any(|reason| reason.starts_with("request_header_"))
    {
        for (values, relationship) in [
            (&origin_values, "origin_header"),
            (&referer_values, "referer_header"),
        ] {
            if values.len() > 1 {
                row.omitted.push(format!("ambiguous_{relationship}"));
            } else if let Some(value) = values.first() {
                if let Some(source_origin) =
                    declared_header_origin(value, relationship == "origin_header")
                {
                    row.header_links.push(HeaderLinkSource {
                        source_origin,
                        relationship: relationship.into(),
                    });
                }
            }
        }
    }
    let Some(response) = &record.response else {
        row.metadata_complete = row.omitted.is_empty();
        return Some(row);
    };
    let mut header_bytes = request_header_bytes;
    let mut locations = Vec::new();
    let mut allowed_origins = Vec::new();
    let mut credentials = false;
    // A value too long to read hides only what its own header says: an unread
    // Location or Access-Control-Allow-Origin leaves the redirect or the CORS
    // answer unproven, a long Content-Security-Policy does not.
    let mut unread_location = false;
    let mut unread_allowed_origin = false;
    let mut technology_budget = technology::TokenScanBudget::default();
    for (index, header) in response.headers.iter().enumerate() {
        header_bytes = header_bytes
            .saturating_add(header.name.len())
            .saturating_add(header.value.len());
        if index.saturating_add(request_headers_scanned) >= MAX_HEADERS
            || header_bytes > MAX_HEADER_BYTES
        {
            row.omitted.push("header_scan_limit".into());
            break;
        }
        if header.value.len() > MAX_HEADER_VALUE_BYTES {
            row.omitted.push("header_value_limit".into());
            unread_location |= header.name.eq_ignore_ascii_case("location");
            unread_allowed_origin |= header
                .name
                .eq_ignore_ascii_case("access-control-allow-origin");
            continue;
        }
        let header_name = header.name.to_ascii_lowercase();
        if technology::observe_header_for_catalog(
            &header_name,
            &header.value,
            index,
            row.technology_observations.as_mut().unwrap(),
            &mut technology_budget,
            catalog,
        ) {
            row.omitted.push("technology_observations_limit".into());
        }
        if header_name == "location" {
            locations.push(header.value.as_str());
        }
        if header_name == "access-control-allow-origin" {
            allowed_origins.push(header.value.trim());
        }
        // Browsers accept only the exact value `true`.
        if header_name == "access-control-allow-credentials" {
            credentials |= header.value.trim() == "true";
        }
        let products: &[(&str, &str)] = match header_name.as_str() {
            "server" => &[
                ("nginx", "nginx"),
                ("apache", "Apache"),
                ("caddy", "Caddy"),
                ("cloudflare", "Cloudflare"),
                ("microsoft-iis", "Microsoft IIS"),
                ("envoy", "Envoy"),
            ],
            "x-powered-by" => &[
                ("php", "PHP"),
                ("express", "Express"),
                ("asp.net", "ASP.NET"),
            ],
            "x-generator" => &[("wordpress", "WordPress"), ("drupal", "Drupal")],
            _ => &[],
        };
        for (prefix, name) in products {
            if product(header.value.trim(), prefix)
                && !row
                    .technology_clues
                    .iter()
                    .any(|clue| clue.name == *name && clue.header_name == header_name)
            {
                if row.technology_clues.len() < MAX_TECHNOLOGY_CLUES_PER_ROW {
                    row.technology_clues.push(HeaderClue {
                        name: (*name).into(),
                        header_name: header_name.clone(),
                    });
                } else {
                    row.omitted.push("technology_clues_limit".into());
                }
            }
        }
    }
    if technology_budget.omitted {
        row.omitted.push("technology_token_scan_limit".into());
    }
    // A browser lets another origin read the response only under exactly one
    // Access-Control-Allow-Origin, which it compares with the origin as written,
    // so keep the value unnormalized; a partial scan cannot prove there was one.
    // Credentials never apply to `*`.
    let partial_scan = row
        .omitted
        .iter()
        .any(|reason| reason == "header_scan_limit");
    if allowed_origins.len() == 1 && !partial_scan && !unread_allowed_origin {
        let allowed = allowed_origins[0];
        row.cors = Some((allowed.into(), credentials && allowed != "*"));
    }
    if record
        .status
        .is_some_and(|status| matches!(status, 300 | 301 | 302 | 303 | 307 | 308))
    {
        if locations.len() > 1 {
            row.omitted.push("ambiguous_location_headers".into());
        } else if let Some(location) = locations.first() {
            // A partial header scan cannot prove there was only one Location.
            if !partial_scan && !unread_location {
                let request_url = Url::parse(&format!("{}{}", row.origin, row.path)).ok();
                let target = request_url.and_then(|url| url.join(location.trim()).ok());
                match target.filter(|url| {
                    matches!(url.scheme(), "http" | "https")
                        && url.path().len() <= MAX_PATH_BYTES
                        && url
                            .host_str()
                            .is_some_and(|host| host.len() <= MAX_HOST_BYTES)
                }) {
                    Some(url) => {
                        row.redirect = Some(RedirectTarget {
                            target_origin: url.origin().ascii_serialization(),
                            target_path: url.path().into(),
                        })
                    }
                    None => row.omitted.push("unsupported_location".into()),
                }
            }
        }
    }
    // What the responding servers say about themselves: vendor headers, values
    // the catalog does not name, and the cookies they set. A header neither
    // names is kept for a reader to judge; a `Via` value can name an internal
    // host, so only its presence counts.
    for (index, header) in response.headers.iter().enumerate().take(MAX_HEADERS) {
        if header.value.len() > MAX_HEADER_VALUE_BYTES {
            continue;
        }
        let detections = crate::service_map_servers::detect_header(&header.name, &header.value);
        let named = !detections.is_empty()
            || row
                .technology_observations
                .iter()
                .flatten()
                .any(|observation| observation.header_index == index);
        for detection in detections {
            crate::service_map_libraries::merge(&mut row.libraries, detection);
        }
        if named {
            continue;
        }
        let name = header.name.to_ascii_lowercase();
        let value = header.value.trim();
        let unnamed = match name.as_str() {
            "server" | "x-powered-by"
                if (1..=64).contains(&value.len())
                    && value.bytes().all(|b| (0x20..0x7f).contains(&b)) =>
            {
                Some(("banner", format!("{name}: {value}")))
            }
            "set-cookie" => value
                .split(['=', ';'])
                .next()
                .map(str::trim)
                .filter(|cookie| {
                    (1..=64).contains(&cookie.len())
                        && cookie
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b))
                })
                .map(|cookie| ("cookie", cookie.to_string())),
            _ if name.len() <= 64
                && !crate::service_map_servers::standard_header(&name)
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') =>
            {
                Some(("header", name))
            }
            _ => None,
        };
        // A header or cookie a row repeats is one signal, and one row of it.
        if let Some(signal) = unnamed.filter(|signal| !row.unnamed.contains(signal)) {
            if row.unnamed.len() < MAX_UNNAMED_PER_ROW {
                row.unnamed.push(signal);
            } else {
                row.omitted.push("unnamed_signals_per_row_limit".into());
            }
        }
    }
    row.omitted.sort();
    row.omitted.dedup();
    row.metadata_complete = row.omitted.is_empty();
    Some(row)
}

fn declared_header_origin(value: &str, origin_header: bool) -> Option<String> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > MAX_HEADER_VALUE_BYTES
        || value
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    {
        return None;
    }
    if !(value
        .get(..7)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("http://"))
        || value
            .get(..8)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("https://")))
        || value.contains('\\')
    {
        return None;
    }
    if origin_header {
        // URL parsing repairs extra authority slashes and removes dot segments,
        // so validate the declared structure before normalization. Keep the
        // existing allowance for one trailing slash, but never raw userinfo.
        let (_, authority) = value.split_once("://")?;
        let authority = authority.strip_suffix('/').unwrap_or(authority);
        if authority.is_empty() || authority.contains(['/', '?', '#', '@', ',']) {
            return None;
        }
    }
    let url = Url::parse(value).ok()?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str()?.len() > MAX_HOST_BYTES {
        return None;
    }
    // Origin is one origin, not an arbitrary URL or an origin-list. Reject
    // credentials there; Referer may contain userinfo, which is never returned.
    if origin_header
        && (url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
            || !url.username().is_empty()
            || url.password().is_some())
    {
        return None;
    }
    Some(url.origin().ascii_serialization())
}

pub fn path_group(path: &str) -> Option<String> {
    let mut changed = false;
    let grouped = path
        .split('/')
        .map(|part| {
            if !part.is_empty() && part.len() <= 18 && part.bytes().all(|b| b.is_ascii_digit()) {
                changed = true;
                "{number}"
            } else if part.len() == 36
                && Uuid::parse_str(part).is_ok()
                && part.as_bytes()[8] == b'-'
                && part.as_bytes()[13] == b'-'
                && part.as_bytes()[18] == b'-'
                && part.as_bytes()[23] == b'-'
            {
                changed = true;
                "{uuid}"
            } else if (16..=128).contains(&part.len())
                && part.bytes().all(|b| b.is_ascii_hexdigit())
                && part.bytes().any(|b| b.is_ascii_digit())
                && part.bytes().any(|b| b.is_ascii_alphabetic())
            {
                // A MongoDB ObjectId (24 hex digits) or a hash names one
                // object as a number does; a word never has a digit in it.
                changed = true;
                "{hex}"
            } else {
                part
            }
        })
        .collect::<Vec<_>>()
        .join("/");
    changed.then_some(grouped)
}

fn sample(values: &mut Vec<String>, id: &str) {
    if values.len() < MAX_EVIDENCE {
        values.push(id.into());
    }
}

// These preparation limits mirror the runtime scope lists. Reject oversized
// snapshots rather than truncating rules and changing the resulting scope.
const MAX_SCOPE_PATTERN_ENTRIES: usize = 500;
const MAX_SCOPE_PATTERN_BYTES: usize = 512;
const MAX_SCOPE_WORK: usize = 8 * 1024 * 1024;
const MAX_SCOPE_CACHE_ENTRIES: usize = 512;
const MAX_SCOPE_CACHE_KEY_BYTES: usize = 128 * 1024;

pub(crate) struct BoundedScope {
    prepared: scope::PreparedScope,
    empty: bool,
    remaining: usize,
    cache: BTreeMap<String, bool>,
    cache_key_bytes: usize,
}

impl BoundedScope {
    pub(crate) fn new(
        include: &[String],
        exclude: &[String],
    ) -> Result<Self, scope::ScopeWorkLimit> {
        let prepared = scope::PreparedScope::try_new(
            include,
            exclude,
            MAX_SCOPE_PATTERN_ENTRIES,
            MAX_SCOPE_PATTERN_BYTES,
        )
        .ok_or(scope::ScopeWorkLimit)?;
        Ok(Self {
            prepared,
            empty: include.is_empty() && exclude.is_empty(),
            remaining: MAX_SCOPE_WORK,
            cache: BTreeMap::new(),
            cache_key_bytes: 0,
        })
    }

    pub(crate) fn contains(&mut self, raw_host: &str) -> Result<bool, scope::ScopeWorkLimit> {
        // The common unscoped path needs neither normalization nor cache keys.
        if self.empty {
            return Ok(true);
        }
        if let Some(result) = self.cache.get(raw_host) {
            return Ok(*result);
        }
        let result = self
            .prepared
            .contains_bounded(raw_host, &mut self.remaining)?;
        // Cache completed true and false decisions by the exact captured host.
        // Capacity exhaustion affects reuse only, never rows or the job budget.
        if self.cache.len() < MAX_SCOPE_CACHE_ENTRIES
            && raw_host.len() <= MAX_SCOPE_CACHE_KEY_BYTES - self.cache_key_bytes
        {
            self.cache.insert(raw_host.to_owned(), result);
            self.cache_key_bytes += raw_host.len();
        }
        Ok(result)
    }
}

pub(crate) fn build_bounded(
    session_id: Uuid,
    snapshot: MetadataSnapshot,
    max_records: usize,
    in_scope_only: bool,
    origin_filter: Option<String>,
    include: &[String],
    exclude: &[String],
) -> Result<ServiceMap, scope::ScopeWorkLimit> {
    let mut scope = BoundedScope::new(include, exclude)?;
    build_with_scope(
        session_id,
        snapshot,
        max_records,
        in_scope_only,
        origin_filter,
        |host| scope.contains(host),
    )
}

#[cfg(test)]
pub(crate) fn build(
    session_id: Uuid,
    snapshot: MetadataSnapshot,
    max_records: usize,
    in_scope_only: bool,
    origin_filter: Option<String>,
    include: &[String],
    exclude: &[String],
) -> ServiceMap {
    build_with_scope(
        session_id,
        snapshot,
        max_records,
        in_scope_only,
        origin_filter,
        |host| Ok(scope::is_host_in_scope(host, include, exclude)),
    )
    .expect("legacy scope matching is unbounded")
}

/// Whether a row's response let `source` read it (a single
/// Access-Control-Allow-Origin naming it or `*`), and also allowed credentials.
fn cors_answer(cors: &Option<(String, bool)>, source: &str) -> (usize, usize) {
    match cors {
        Some((allowed, credentials)) if allowed == "*" || allowed == source => {
            (1, usize::from(*credentials))
        }
        _ => (0, 0),
    }
}

/// The page an asset row's technologies belong to: its Referer's origin. A
/// page row's own stay with it.
pub(crate) fn library_page(row: &ServiceMapRow) -> Option<String> {
    (crate::service_map_libraries::kind(row) != Some(crate::service_map_libraries::Kind::Page))
        .then(|| {
            row.header_links
                .iter()
                .find(|link| link.relationship == "referer_header")
                .map(|link| link.source_origin.clone())
        })
        .flatten()
}

type FrontKey = (Option<String>, String, String, Option<String>);

#[derive(Default)]
struct ClientTally {
    rows: usize,
    versions: BTreeSet<u32>,
    addresses: BTreeSet<std::net::IpAddr>,
    /// Rows per origin, and its own visits there by request kind.
    origins: BTreeMap<String, (usize, BTreeMap<&'static str, usize>)>,
    evidence: Vec<String>,
}

struct FrontHit {
    name: String,
    category: &'static str,
    /// The server signals among them; front-end ones are not kept.
    signals: BTreeSet<&'static str>,
    rows: usize,
    evidence: Vec<String>,
}

fn hit(
    hits: &mut BTreeMap<FrontKey, FrontHit>,
    page: Option<String>,
    source_origin: &str,
    detection: crate::service_map_libraries::Detection,
    evidence: &str,
) {
    // A server's own header, cookie or body is about it, never about the page
    // that loaded the row.
    let page = (!crate::service_map_servers::server_signal(&detection))
        .then_some(page)
        .flatten();
    let signal = detection.signal;
    let hit = hits
        .entry((
            page,
            source_origin.to_string(),
            detection.product_id,
            detection.version,
        ))
        .or_insert_with(|| FrontHit {
            name: detection.name,
            category: detection.category,
            signals: BTreeSet::new(),
            rows: 0,
            evidence: Vec::new(),
        });
    if !signal.is_empty() {
        hit.signals.insert(signal);
    }
    hit.rows += 1;
    sample(&mut hit.evidence, evidence);
}

/// Folds projected rows, newest first, into a map. `build_with_scope` feeds it a
/// materialized snapshot; the store feeds it rows as it reads them, so a map
/// over a whole retained history holds no copy of its rows.
pub(crate) struct MapBuilder {
    in_scope_only: bool,
    origin_filter: Option<String>,
    stopped_by: BTreeSet<String>,
    origins: BTreeMap<String, ServiceOrigin>,
    endpoint_indexes: BTreeMap<(String, String, String), usize>,
    technology_observation_count: usize,
    /// Rows naming each technology, by the page they may belong to and the
    /// origin they were served from, attributed once every page is known.
    front_hits: BTreeMap<FrontKey, FrontHit>,
    /// By kind, name and operating system; versions are gathered apart.
    clients: BTreeMap<(&'static str, &'static str, Option<&'static str>), ClientTally>,
    /// Rows per origin, auth kind and name.
    auth: BTreeMap<(String, &'static str, Option<String>), (usize, Vec<String>)>,
    /// Rows per origin, unnamed signal kind and value.
    unnamed: BTreeMap<(String, &'static str, String), (usize, Vec<String>)>,
    /// Distinct keys `auth` and `unnamed` hold per origin and kind.
    tracked: HashMap<(String, &'static str), usize>,
    projected_rows: usize,
    included_rows: usize,
    excluded_rows: usize,
    omitted_rows: usize,
}

impl MapBuilder {
    /// Counts a new key for an origin and kind, or refuses it at the bound.
    /// Takes the field, not `self`: callers hold an origin borrowed from it.
    fn track(
        tracked: &mut HashMap<(String, &'static str), usize>,
        origin: &str,
        kind: &'static str,
    ) -> bool {
        let count = tracked.entry((origin.to_string(), kind)).or_default();
        *count < MAX_TRACKED_PER_ORIGIN_KIND && {
            *count += 1;
            true
        }
    }

    pub(crate) fn new(in_scope_only: bool, origin_filter: Option<String>) -> Self {
        Self {
            in_scope_only,
            origin_filter,
            stopped_by: BTreeSet::new(),
            origins: BTreeMap::new(),
            endpoint_indexes: BTreeMap::new(),
            technology_observation_count: 0,
            front_hits: BTreeMap::new(),
            clients: BTreeMap::new(),
            auth: BTreeMap::new(),
            unnamed: BTreeMap::new(),
            tracked: HashMap::new(),
            projected_rows: 0,
            included_rows: 0,
            excluded_rows: 0,
            omitted_rows: 0,
        }
    }

    /// Folds one row. False when the row was excluded or left out by a cap.
    pub(crate) fn add(&mut self, mut row: ServiceMapRow, in_scope: bool) -> bool {
        self.projected_rows += 1;
        if (self.in_scope_only && !in_scope)
            || self
                .origin_filter
                .as_ref()
                .is_some_and(|origin| origin != &row.origin)
        {
            self.excluded_rows += 1;
            self.keep_for_page(&mut row);
            return false;
        }
        for reason in &row.omitted {
            self.stopped_by.insert(reason.clone());
        }
        if !self.origins.contains_key(&row.origin) && self.origins.len() == MAX_ORIGINS {
            self.stopped_by.insert("origins_limit".into());
            self.omitted_rows += 1;
            self.keep_for_page(&mut row);
            return false;
        }
        let origin = self
            .origins
            .entry(row.origin.clone())
            .or_insert_with(|| ServiceOrigin {
                origin: row.origin.clone(),
                host: row.host.clone(),
                scheme: row.scheme.clone(),
                port: row.port,
                in_scope,
                request_count: 0,
                first_seen: row.started_at,
                last_seen: row.started_at,
                endpoints: vec![],
                technology_clues: vec![],
                technology_observations: Some(vec![]),
                redirects: vec![],
                header_links: vec![],
                header_sources: vec![],
                front_technologies: vec![],
                server_technologies: vec![],
                favicon: None,
                auth: vec![],
                unnamed: Unnamed::default(),
            });
        origin.in_scope |= in_scope;
        origin.request_count += 1;
        origin.first_seen = origin.first_seen.min(row.started_at);
        origin.last_seen = origin.last_seen.max(row.started_at);
        self.included_rows += 1;
        if let Some(client) = row.client {
            let tally = self
                .clients
                .entry((client.kind, client.name, client.os))
                .or_default();
            tally.rows += 1;
            tally.versions.extend(client.version);
            if let Some(address) = row.client_address {
                if tally.addresses.len() < MAX_CLIENT_ADDRESSES {
                    tally.addresses.insert(address);
                }
            }
            sample(&mut tally.evidence, &row.evidence_id);
            let (rows, entries) = tally.origins.entry(row.origin.clone()).or_default();
            *rows += 1;
            if !row.initiated {
                *entries.entry(row.request_kind).or_default() += 1;
            }
        }
        if !row.libraries.is_empty() {
            let page = library_page(&row);
            for detection in std::mem::take(&mut row.libraries) {
                hit(
                    &mut self.front_hits,
                    page.clone(),
                    &row.origin,
                    detection,
                    &row.evidence_id,
                );
            }
        }
        let key = (row.origin.clone(), row.method.clone(), row.path.clone());
        let endpoint_index = if row.path.len() > MAX_PATH_BYTES {
            // The row still counts for its origin; only its endpoint is left out.
            self.stopped_by.insert("path_limit".into());
            None
        } else if let Some(index) = self.endpoint_indexes.get(&key) {
            Some(*index)
        } else if self.endpoint_indexes.len() >= MAX_ENDPOINTS
            || origin.endpoints.len() >= MAX_ENDPOINTS_PER_ORIGIN
        {
            self.stopped_by.insert("endpoints_limit".into());
            None
        } else {
            let index = origin.endpoints.len();
            self.endpoint_indexes.insert(key, index);
            origin.endpoints.push(ServiceEndpoint {
                method: row.method.clone(),
                path: row.path.clone(),
                path_group: path_group(&row.path),
                request_count: 0,
                statuses: vec![],
                content_types: vec![],
                evidence: vec![],
                auth: vec![],
            });
            Some(index)
        };
        if let Some(index) = endpoint_index {
            let endpoint = &mut origin.endpoints[index];
            endpoint.request_count += 1;
            if let Some(status) = row.status {
                if !endpoint.statuses.contains(&status) {
                    if endpoint.statuses.len() < 32 {
                        endpoint.statuses.push(status);
                    } else {
                        self.stopped_by.insert("statuses_limit".into());
                    }
                }
            }
            if let Some(mime) = &row.content_type {
                if !endpoint.content_types.contains(mime) {
                    if endpoint.content_types.len() < 16 {
                        endpoint.content_types.push(mime.clone());
                    } else {
                        self.stopped_by.insert("content_types_limit".into());
                    }
                }
            }
            sample(&mut endpoint.evidence, &row.evidence_id);
        }
        for (kind, value) in std::mem::take(&mut row.unnamed) {
            let key = (row.origin.clone(), kind, value);
            if !self.unnamed.contains_key(&key)
                && !Self::track(&mut self.tracked, &row.origin, kind)
            {
                self.stopped_by
                    .insert("unnamed_signals_per_origin_limit".into());
                continue;
            }
            let (rows, evidence) = self.unnamed.entry(key).or_default();
            *rows += 1;
            sample(evidence, &row.evidence_id);
        }
        for signal in std::mem::take(&mut row.auth) {
            if let Some(index) = endpoint_index {
                let kinds = &mut origin.endpoints[index].auth;
                if !kinds.iter().any(|kind| kind == signal.kind) {
                    kinds.push(signal.kind.into());
                }
            }
            let key = (row.origin.clone(), signal.kind, signal.name);
            if !self.auth.contains_key(&key)
                && !Self::track(&mut self.tracked, &row.origin, signal.kind)
            {
                self.stopped_by.insert("auth_methods_limit".into());
                continue;
            }
            let (rows, evidence) = self.auth.entry(key).or_default();
            *rows += 1;
            sample(evidence, &row.evidence_id);
        }
        for clue in row.technology_clues {
            if let Some(existing) = origin
                .technology_clues
                .iter_mut()
                .find(|c| c.name == clue.name && c.header_name == clue.header_name)
            {
                sample(&mut existing.evidence, &row.evidence_id);
            } else {
                origin.technology_clues.push(TechnologyClue {
                    name: clue.name,
                    header_name: clue.header_name,
                    source: "response_header".into(),
                    confidence: "observed_header".into(),
                    evidence: vec![row.evidence_id.clone()],
                });
            }
        }
        let observations = origin.technology_observations.as_mut().unwrap();
        let mut row_tuples = BTreeSet::new();
        for observation in row.technology_observations.into_iter().flatten() {
            let key = (
                observation.product_id.clone(),
                observation.header_name.clone(),
                observation.reported_version.clone(),
                observation.version_status,
            );
            if !row_tuples.insert(key) {
                continue;
            }
            if let Some(existing) = observations.iter_mut().find(|existing| {
                existing.product_id == observation.product_id
                    && existing.header_name == observation.header_name
                    && existing.reported_version == observation.reported_version
                    && existing.version_status == observation.version_status
            }) {
                // A cardinality cap must not stop counts for retained tuples.
                existing.row_count += 1;
                existing.first_seen = existing.first_seen.min(row.started_at);
                existing.last_seen = existing.last_seen.max(row.started_at);
                sample(&mut existing.evidence, &row.evidence_id);
            } else if observations.len() >= technology::MAX_OBSERVATIONS_PER_ORIGIN {
                self.stopped_by
                    .insert("technology_observations_per_origin_limit".into());
            } else if self.technology_observation_count >= technology::MAX_OBSERVATIONS {
                self.stopped_by
                    .insert("technology_observations_map_limit".into());
            } else {
                observations.push(TechnologyAggregate {
                    product_id: observation.product_id,
                    name: observation.name,
                    catalog_category: observation.catalog_category,
                    reported_version: observation.reported_version,
                    version_status: observation.version_status,
                    source: observation.source,
                    strength: observation.strength,
                    header_name: observation.header_name,
                    row_count: 1,
                    first_seen: row.started_at,
                    last_seen: row.started_at,
                    evidence: vec![row.evidence_id.clone()],
                });
                self.technology_observation_count += 1;
            }
        }
        let sources: BTreeSet<String> = row
            .header_links
            .iter()
            .map(|link| link.source_origin.clone())
            .collect();
        for source_origin in sources {
            let (cors_allowed, cors_credentials) = cors_answer(&row.cors, &source_origin);
            if let Some(existing) = origin
                .header_sources
                .iter_mut()
                .find(|source| source.source_origin == source_origin)
            {
                existing.request_count += 1;
                *existing
                    .request_kinds
                    .entry(row.request_kind.into())
                    .or_default() += 1;
                existing.cors_allowed_count += cors_allowed;
                existing.cors_credentials_count += cors_credentials;
            } else if origin.header_sources.len() < MAX_HEADER_LINKS_PER_ORIGIN {
                origin.header_sources.push(HeaderSource {
                    source_origin,
                    request_count: 1,
                    request_kinds: BTreeMap::from([(row.request_kind.into(), 1)]),
                    cors_allowed_count: cors_allowed,
                    cors_credentials_count: cors_credentials,
                });
            }
        }
        for link in row.header_links {
            let (cors_allowed, cors_credentials) = cors_answer(&row.cors, &link.source_origin);
            if let Some(existing) = origin.header_links.iter_mut().find(|r| {
                r.source_origin == link.source_origin && r.relationship == link.relationship
            }) {
                existing.request_count += 1;
                *existing
                    .request_kinds
                    .entry(row.request_kind.into())
                    .or_default() += 1;
                existing.cors_allowed_count += cors_allowed;
                existing.cors_credentials_count += cors_credentials;
                sample(&mut existing.evidence, &row.evidence_id);
            } else if origin.header_links.len() < MAX_HEADER_LINKS_PER_ORIGIN {
                origin.header_links.push(HeaderLink {
                    source_origin: link.source_origin,
                    relationship: link.relationship,
                    source: "request_header_declaration".into(),
                    evidence: vec![row.evidence_id.clone()],
                    request_count: 1,
                    request_kinds: BTreeMap::from([(row.request_kind.into(), 1)]),
                    cors_allowed_count: cors_allowed,
                    cors_credentials_count: cors_credentials,
                });
            } else {
                self.stopped_by.insert("header_links_limit".into());
            }
        }
        if let Some(target) = row.redirect {
            if let Some(existing) = origin.redirects.iter_mut().find(|r| {
                r.target_origin == target.target_origin && r.target_path == target.target_path
            }) {
                existing.request_count += 1;
                sample(&mut existing.evidence, &row.evidence_id);
            } else if origin.redirects.len() < MAX_REDIRECTS_PER_ORIGIN {
                origin.redirects.push(RedirectInstruction {
                    target_origin: target.target_origin,
                    target_path: target.target_path,
                    relationship: "redirect_instruction".into(),
                    source: "response_location_header".into(),
                    evidence: vec![row.evidence_id.clone()],
                    request_count: 1,
                });
            } else {
                self.stopped_by.insert("redirects_limit".into());
            }
        }
        true
    }

    /// Whether what a row names may go to the page that loaded it: any page,
    /// or in a one-origin map only the origin asked about.
    pub(crate) fn wants_page(&self, page: Option<&String>) -> bool {
        page.is_some_and(|page| {
            self.origin_filter
                .as_ref()
                .is_none_or(|origin| origin == page)
        })
    }

    /// What a row left out of the map names still belongs to the page that
    /// loaded it, as in a whole map: a one-origin, in-scope or capped map keeps
    /// the jQuery a page took from a CDN. `finish` drops it unless that page is
    /// in the map.
    fn keep_for_page(&mut self, row: &mut ServiceMapRow) {
        let page = library_page(row);
        if self.wants_page(page.as_ref()) {
            for detection in std::mem::take(&mut row.libraries) {
                hit(
                    &mut self.front_hits,
                    page.clone(),
                    &row.origin,
                    detection,
                    &row.evidence_id,
                );
            }
        }
    }

    /// Technologies read from a row's body after it was folded or left out.
    pub(crate) fn add_libraries(
        &mut self,
        page: Option<String>,
        source_origin: String,
        found: Vec<crate::service_map_libraries::Detection>,
        evidence: String,
    ) {
        for detection in found {
            hit(
                &mut self.front_hits,
                page.clone(),
                &source_origin,
                detection,
                &evidence,
            );
        }
    }

    /// The map, with the snapshot's own counts and stop reasons merged in.
    pub(crate) fn finish(
        mut self,
        session_id: Uuid,
        snapshot: MetadataSnapshot,
        max_records: usize,
    ) -> ServiceMap {
        for (origin, evidence) in &snapshot.favicons {
            if let Some(item) = self.origins.get_mut(origin) {
                item.favicon = Some(evidence.clone());
            }
        }
        let rank = |kind: &str| {
            crate::service_map_auth::KINDS
                .iter()
                .position(|known| *known == kind)
        };
        for ((origin, kind, name), (row_count, evidence)) in std::mem::take(&mut self.auth) {
            if let Some(item) = self.origins.get_mut(&origin) {
                item.auth.push(AuthMethod {
                    kind: kind.into(),
                    name,
                    row_count,
                    evidence,
                });
            }
        }
        for ((origin, kind, value), (row_count, evidence)) in std::mem::take(&mut self.unnamed) {
            if let Some(item) = self.origins.get_mut(&origin) {
                let signals = match kind {
                    "banner" => &mut item.unnamed.banners,
                    "header" => &mut item.unnamed.headers,
                    _ => &mut item.unnamed.cookies,
                };
                signals.push(UnnamedSignal {
                    value,
                    row_count,
                    evidence,
                });
            }
        }
        for item in self.origins.values_mut() {
            for signals in [
                &mut item.unnamed.banners,
                &mut item.unnamed.headers,
                &mut item.unnamed.cookies,
            ] {
                signals.sort_by(|a, b| (b.row_count, &a.value).cmp(&(a.row_count, &b.value)));
                if signals.len() > MAX_UNNAMED {
                    signals.truncate(MAX_UNNAMED);
                    self.stopped_by
                        .insert("unnamed_signals_per_origin_limit".into());
                }
            }
            item.auth.sort_by(|a, b| {
                (b.row_count, rank(&a.kind), &a.name).cmp(&(a.row_count, rank(&b.kind), &b.name))
            });
            if item.auth.len() > MAX_AUTH_METHODS {
                item.auth.truncate(MAX_AUTH_METHODS);
                self.stopped_by.insert("auth_methods_limit".into());
            }
            for endpoint in &mut item.endpoints {
                endpoint.auth.sort_by_key(|kind| rank(kind));
            }
        }
        // An asset's technology belongs to the page that loaded it when that
        // page is in the map; a CDN serving the file is only where it was found.
        for ((page, source_origin, product_id, version), hit) in
            std::mem::take(&mut self.front_hits)
        {
            let owner = page
                .filter(|page| self.origins.contains_key(page))
                .unwrap_or_else(|| source_origin.clone());
            let Some(origin) = self.origins.get_mut(&owner) else {
                continue;
            };
            if crate::service_map_servers::CATEGORIES.contains(&hit.category) {
                let signals = hit.signals.iter().map(|signal| signal.to_string());
                if let Some(existing) = origin
                    .server_technologies
                    .iter_mut()
                    .find(|item| item.product_id == product_id && item.version == version)
                {
                    existing.row_count += hit.rows;
                    for signal in signals {
                        if !existing.signals.contains(&signal) {
                            existing.signals.push(signal);
                        }
                    }
                    for evidence in &hit.evidence {
                        sample(&mut existing.evidence, evidence);
                    }
                } else {
                    origin.server_technologies.push(ServerTechnology {
                        product_id,
                        name: hit.name,
                        category: hit.category.into(),
                        version,
                        signals: signals.collect(),
                        row_count: hit.rows,
                        evidence: hit.evidence,
                    });
                }
                continue;
            }
            // Source buttons use this origin for every evidence token. Merging
            // two serving origins would make the later origin's rows unverifiable.
            if let Some(existing) = origin.front_technologies.iter_mut().find(|item| {
                item.product_id == product_id
                    && item.version == version
                    && item.source_origin == source_origin
            }) {
                existing.row_count += hit.rows;
                for evidence in &hit.evidence {
                    sample(&mut existing.evidence, evidence);
                }
            } else {
                origin.front_technologies.push(FrontTechnology {
                    product_id,
                    name: hit.name,
                    category: hit.category.into(),
                    version,
                    source_origin,
                    row_count: hit.rows,
                    evidence: hit.evidence,
                });
            }
        }
        let rank = |category: &str| {
            crate::service_map_libraries::CATEGORIES
                .iter()
                .position(|known| *known == category)
        };
        for origin in self.origins.values_mut() {
            let found = &mut origin.front_technologies;
            // A product some row named a version of needs no versionless entry.
            let versioned: BTreeSet<String> = found
                .iter()
                .filter(|item| item.version.is_some())
                .map(|item| item.product_id.clone())
                .collect();
            found.retain(|item| item.version.is_some() || !versioned.contains(&item.product_id));
            found.sort_by(|a, b| {
                (rank(&a.category), &a.name, &a.version, &a.source_origin).cmp(&(
                    rank(&b.category),
                    &b.name,
                    &b.version,
                    &b.source_origin,
                ))
            });
            if found.len() > MAX_FRONT_TECHNOLOGIES_PER_ORIGIN {
                found.truncate(MAX_FRONT_TECHNOLOGIES_PER_ORIGIN);
                self.stopped_by.insert("front_technologies_limit".into());
            }
            let servers = &mut origin.server_technologies;
            let versioned: BTreeSet<String> = servers
                .iter()
                .filter(|item| item.version.is_some())
                .map(|item| item.product_id.clone())
                .collect();
            servers.retain(|item| item.version.is_some() || !versioned.contains(&item.product_id));
            let layer = |category: &str| {
                crate::service_map_servers::CATEGORIES
                    .iter()
                    .position(|known| *known == category)
            };
            servers.sort_by(|a, b| {
                (layer(&a.category), &a.name, &a.version).cmp(&(
                    layer(&b.category),
                    &b.name,
                    &b.version,
                ))
            });
            for item in servers.iter_mut() {
                item.signals.sort();
            }
            if servers.len() > MAX_SERVER_TECHNOLOGIES_PER_ORIGIN {
                servers.truncate(MAX_SERVER_TECHNOLOGIES_PER_ORIGIN);
                self.stopped_by.insert("server_technologies_limit".into());
            }
        }
        let mut clients: Vec<ServiceClient> = std::mem::take(&mut self.clients)
            .into_iter()
            .map(|((kind, name, os), tally)| {
                let mut origins: Vec<ClientOrigin> = tally
                    .origins
                    .into_iter()
                    .map(|(origin, (request_count, entries))| ClientOrigin {
                        origin,
                        request_count,
                        entry_kinds: entries
                            .into_iter()
                            .map(|(kind, rows)| (kind.to_string(), rows))
                            .collect(),
                    })
                    .collect();
                origins.sort_by(|a, b| {
                    (b.request_count, &a.origin).cmp(&(a.request_count, &b.origin))
                });
                if origins.len() > MAX_CLIENT_ORIGINS {
                    origins.truncate(MAX_CLIENT_ORIGINS);
                    self.stopped_by.insert("client_origins_limit".into());
                }
                ServiceClient {
                    kind: kind.into(),
                    name: name.into(),
                    versions: tally.versions.into_iter().rev().take(8).collect(),
                    os: os.map(Into::into),
                    request_count: tally.rows,
                    addresses: tally.addresses.iter().map(ToString::to_string).collect(),
                    origins,
                    evidence: tally.evidence,
                }
            })
            .collect();
        let kind_rank = |kind: &str| {
            crate::service_map_clients::KINDS
                .iter()
                .position(|known| *known == kind)
        };
        clients.sort_by(|a, b| {
            (b.request_count, kind_rank(&a.kind), &a.name, &a.os).cmp(&(
                a.request_count,
                kind_rank(&b.kind),
                &b.name,
                &b.os,
            ))
        });
        if clients.len() > MAX_CLIENTS {
            clients.truncate(MAX_CLIENTS);
            self.stopped_by.insert("clients_limit".into());
        }
        let stopped_by: BTreeSet<String> = self
            .stopped_by
            .union(&snapshot.stopped_by)
            .cloned()
            .collect();
        let mut origins: Vec<_> = self.origins.into_values().collect();
        for origin in &mut origins {
            origin
                .endpoints
                .sort_by(|a, b| (&a.path, &a.method).cmp(&(&b.path, &b.method)));
            for endpoint in &mut origin.endpoints {
                endpoint.statuses.sort_unstable();
                endpoint.content_types.sort();
            }
            origin
                .technology_clues
                .sort_by(|a, b| (&a.name, &a.header_name).cmp(&(&b.name, &b.header_name)));
            if let Some(observations) = &mut origin.technology_observations {
                observations.sort_by(|a, b| {
                    (
                        &a.product_id,
                        &a.header_name,
                        &a.reported_version,
                        a.version_status,
                    )
                        .cmp(&(
                            &b.product_id,
                            &b.header_name,
                            &b.reported_version,
                            b.version_status,
                        ))
                });
            }
            origin.header_links.sort_by(|a, b| {
                (&a.source_origin, &a.relationship).cmp(&(&b.source_origin, &b.relationship))
            });
            origin
                .header_sources
                .sort_by(|a, b| a.source_origin.cmp(&b.source_origin));
            origin.redirects.sort_by(|a, b| {
                (&a.target_origin, &a.target_path).cmp(&(&b.target_origin, &b.target_path))
            });
        }
        ServiceMap { schema_version: 1, technology_catalog_version: None, session_id,
            snapshot: ServiceMapSnapshot {
                window_order: "newest_capture_sequence".into(), id: Uuid::new_v4(), generation: snapshot.generation,
                captured_at: snapshot.captured_at,
                first_retained_started_at: snapshot.first_retained_started_at, last_retained_started_at: snapshot.last_retained_started_at,
                oldest_considered_at: snapshot.oldest_considered_at, latest_considered_at: snapshot.latest_considered_at,
                retained_rows: snapshot.retained_rows,
                considered_rows: snapshot.considered_rows,
                non_http_rows: snapshot.non_http_rows, filtered_rows: snapshot.filtered_rows, projected_rows: self.projected_rows,
                included_rows: self.included_rows, excluded_rows: self.excluded_rows, omitted_rows: self.omitted_rows + snapshot.omitted_rows,
                origin_count: origins.len(), endpoint_count: self.endpoint_indexes.len(), complete: stopped_by.is_empty(),
                stopped_by: stopped_by.into_iter().collect(), limits: ServiceMapLimits::new(max_records) },
            in_scope_only: self.in_scope_only, origin_filter: self.origin_filter, origins, clients,
            unavailable: vec!["initiator".into(), "remote_ip".into(), "tls_certificate".into()],
            deferred: vec!["response_body_references".into()],
            warnings: vec!["Counts describe analyzed rows in a newest-capture-sequence window, not all-time traffic. Removed or uncaptured traffic is unavailable; retained first/last timestamps are capture-order boundaries.".into(),
                "Header clues do not prove software identity or a backend chain. Redirect instructions and Origin/Referer declarations do not prove a follow-up or initiating call.".into(),
                "Evidence samples are bounded. Queries, fragments, userinfo, raw headers, and bodies are omitted. Origin in_scope means at least one analyzed row matches scope using its captured host.".into()],
        }
    }
}

fn build_with_scope(
    session_id: Uuid,
    mut snapshot: MetadataSnapshot,
    max_records: usize,
    in_scope_only: bool,
    origin_filter: Option<String>,
    mut is_in_scope: impl FnMut(&str) -> Result<bool, scope::ScopeWorkLimit>,
) -> Result<ServiceMap, scope::ScopeWorkLimit> {
    let mut builder = MapBuilder::new(in_scope_only, origin_filter);
    for row in std::mem::take(&mut snapshot.rows) {
        let in_scope = is_in_scope(&row.scope_host)?;
        builder.add(row, in_scope);
    }
    Ok(builder.finish(session_id, snapshot, max_records))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        model::{HeaderRecord, MessageRecord},
        store::TransactionStore,
    };

    fn record(path: &str) -> TransactionRecord {
        let message =
            MessageRecord::from_headers_and_body(&http::HeaderMap::new(), b"BODY_SENTINEL", 1024);
        TransactionRecord::http(
            Utc::now(),
            "GET".into(),
            "https".into(),
            "example.com".into(),
            path.into(),
            Some(200),
            1,
            message.clone(),
            Some(message),
            vec![],
            None,
            None,
        )
    }

    fn headers(values: &[(&str, &str)]) -> Vec<HeaderRecord> {
        values
            .iter()
            .map(|(name, value)| HeaderRecord {
                name: (*name).into(),
                value: (*value).into(),
            })
            .collect()
    }

    async fn map(records: Vec<TransactionRecord>) -> ServiceMap {
        let id = Uuid::new_v4();
        let store = TransactionStore::from_records(records);
        build(
            id,
            store.service_map_snapshot(id, DEFAULT_MAX_RECORDS).await,
            DEFAULT_MAX_RECORDS,
            false,
            None,
            &[],
            &[],
        )
    }

    #[tokio::test]
    async fn service_map_never_serializes_credentials_bodies_or_arbitrary_header_values() {
        let mut row = record("/login?password=QUERY_SENTINEL#FRAGMENT_SENTINEL");
        row.host = "USER_SENTINEL:PASS_SENTINEL@example.com:443".into();
        row.status = Some(302);
        row.request.headers = headers(&[("Authorization", "Bearer AUTH_SENTINEL"),
            ("Referer", "https://REFUSER_SENTINEL:REFPASS_SENTINEL@source.example.com/private?token=REFQUERY_SENTINEL#REFHASH_SENTINEL")]);
        row.response.as_mut().unwrap().headers = headers(&[("Server", "nginx/SECRET_VERSION_SENTINEL"),
            ("Set-Cookie", "session=COOKIE_SENTINEL"),
            ("Location", "https://REDIRUSER_SENTINEL:REDIRPASS_SENTINEL@other.example.com/next?token=REDIRQUERY_SENTINEL#REDIRHASH_SENTINEL")]);
        let result = map(vec![row]).await;
        let json = serde_json::to_string(&result).unwrap();
        assert!(
            !json.contains("SENTINEL"),
            "safe projection leaked synthetic sensitive data"
        );
        let origin = &result.origins[0];
        assert_eq!(origin.origin, "https://example.com");
        assert_eq!(origin.endpoints[0].path, "/login");
        assert_eq!(origin.technology_clues[0].name, "nginx");
        let observation = &origin.technology_observations.as_ref().unwrap()[0];
        assert_eq!(
            observation.version_status,
            technology::VersionStatus::UnsupportedFormat
        );
        assert!(observation.reported_version.is_none());
        assert_eq!(
            origin.redirects[0].target_origin,
            "https://other.example.com"
        );
        assert_eq!(origin.redirects[0].target_path, "/next");
        assert_eq!(origin.redirects[0].relationship, "redirect_instruction");
        assert_eq!(
            origin.header_links[0].source_origin,
            "https://source.example.com"
        );
        assert_eq!(result.snapshot.included_rows, 1);
        assert_eq!(result.snapshot.origin_count, 1);
    }

    #[tokio::test]
    async fn service_map_preserves_exact_methods_paths_and_only_hints_at_groups() {
        let mut lower = record("/users/12?x=1");
        lower.method = "get".into();
        let mut custom = record("/users/12?x=2");
        custom.method = "M-SEARCH2!".into();
        let result = map(vec![
            record("/users/12"),
            record("/users/34"),
            lower,
            custom,
            record("/users/550e8400-e29b-41d4-a716-446655440000"),
            record("/static/v2"),
        ])
        .await;
        let endpoints = &result.origins[0].endpoints;
        assert_eq!(endpoints.len(), 6);
        assert!(endpoints.iter().any(|e| e.method == "get"));
        assert!(endpoints.iter().any(|e| e.method == "M-SEARCH2!"));
        assert_eq!(path_group("/users/12"), Some("/users/{number}".into()));
        assert_eq!(
            path_group("/users/550e8400-e29b-41d4-a716-446655440000"),
            Some("/users/{uuid}".into())
        );
        assert_eq!(path_group("/static/v2/0x10/1234567890123456789"), None);
        assert_eq!(
            path_group("/web/chats/481708212407212/posts/6ac5f9f2e9cba87a1381140d"),
            Some("/web/chats/{number}/posts/{hex}".into())
        );
        assert_eq!(
            path_group("/users/73c4fa901f2b13362bd79cdaae2488a2f4cc29c5055df2e1b74a0967962840d2"),
            Some("/users/{hex}".into())
        );
        // Short hex, or hex letters with no digit, is a word or a version.
        assert_eq!(path_group("/static/deadbeef/cafe/facade"), None);
        assert_eq!(path_group("/assets/abcdefabcdefabcdef"), None);
    }

    #[tokio::test]
    async fn service_map_duplicate_uuid_evidence_resolves_exact_retained_row() {
        let session = Uuid::new_v4();
        let old = record("/old");
        let mut new = old.clone();
        new.path = "/new".into();
        let store = TransactionStore::from_records(vec![new.clone(), old]);
        let snapshot = store.service_map_snapshot(session, 10).await;
        assert_eq!(snapshot.rows.len(), 2);
        assert_eq!(store.get(new.id).await.unwrap().path, "/new");
        for row in snapshot.rows {
            let evidence = store.service_map_evidence(session, &row.evidence_id).await;
            assert!(evidence.available);
            assert_eq!(evidence.row.unwrap().path, row.path);
        }
        let result = build(
            session,
            store.service_map_snapshot(session, 10).await,
            10,
            false,
            None,
            &[],
            &[],
        );
        assert_eq!(result.origins[0].request_count, 2);
        assert_eq!(result.origins[0].endpoints.len(), 2);
    }

    #[tokio::test]
    async fn socket_peer_extension_is_explicit_exact_and_never_part_of_map_projection() {
        use crate::model::{ObservedSocketPeer, ObservedSocketPeerRoute};
        let session = Uuid::new_v4();
        let mut observed = record("/observed");
        observed.observed_socket_peer = Some(ObservedSocketPeer::from_remote_addr(
            observed.started_at,
            ObservedSocketPeerRoute::SocksProxy,
            Some("[2001:db8::1]:1080".parse().unwrap()),
        ));
        let mut unavailable = record("/unavailable");
        unavailable.observed_socket_peer = Some(ObservedSocketPeer::from_remote_addr(
            unavailable.started_at,
            ObservedSocketPeerRoute::Unknown,
            None,
        ));
        let mut invalid = observed.clone();
        invalid.id = Uuid::new_v4();
        invalid.path = "/invalid".into();
        invalid.observed_socket_peer.as_mut().unwrap().reason =
            Some(crate::model::ObservedSocketPeerReason::RemoteAddrUnavailable);
        let store =
            TransactionStore::from_records(vec![observed, unavailable, invalid, record("/legacy")]);
        let snapshot = store.service_map_snapshot(session, 10).await;
        for row in &snapshot.rows {
            assert!(!serde_json::to_string(row).unwrap().contains("socket_peer"));
            let default = store.service_map_evidence(session, &row.evidence_id).await;
            assert!(default.socket_peer.is_none());
            assert!(serde_json::to_value(default)
                .unwrap()
                .get("socket_peer")
                .is_none());
            let explicit = store
                .service_map_evidence_with_socket_peer(session, &row.evidence_id, true)
                .await;
            let extension = explicit.socket_peer.unwrap();
            match row.path.as_str() {
                "/observed" => {
                    assert_eq!(extension.status, ServiceMapSocketPeerStatus::Observed);
                    let observation = extension.observation.unwrap();
                    assert_eq!(observation.route, ObservedSocketPeerRoute::SocksProxy);
                    assert_eq!(observation.address.unwrap().ip.to_string(), "2001:db8::1");
                }
                "/unavailable" => {
                    assert_eq!(extension.status, ServiceMapSocketPeerStatus::Unavailable);
                    assert!(extension.observation.unwrap().address.is_none());
                }
                _ => {
                    assert_eq!(extension.status, ServiceMapSocketPeerStatus::NotRecorded);
                    assert!(extension.observation.is_none());
                }
            }
            let wrong_session = store
                .service_map_evidence_with_socket_peer(Uuid::new_v4(), &row.evidence_id, true)
                .await;
            assert!(!wrong_session.available);
            assert!(wrong_session.socket_peer.is_none());
        }
        let projection = build(session, snapshot, 10, false, None, &[], &[]);
        let json = serde_json::to_string(&projection).unwrap();
        assert!(!json.contains("socket_peer"));
        assert!(!json.contains("2001:db8::1"));
        assert!(projection
            .unavailable
            .iter()
            .any(|field| field == "remote_ip"));
    }

    #[tokio::test]
    async fn service_map_evidence_invalidates_updated_trimmed_and_reconstructed_rows() {
        let session = Uuid::new_v4();
        let row = record("/before");
        let id = row.id;
        let store = TransactionStore::from_records_with_max_entries(vec![row.clone()], Some(2));
        let token = store.service_map_snapshot(session, 10).await.rows[0]
            .evidence_id
            .clone();
        assert_eq!(
            store
                .service_map_evidence(Uuid::new_v4(), &token)
                .await
                .reason
                .as_deref(),
            Some("session_mismatch")
        );
        store.insert(record("/other")).await;
        assert!(store.service_map_evidence(session, &token).await.available);
        store
            .update_record(id, |row| row.path = "/after".into())
            .await;
        assert_eq!(
            store
                .service_map_evidence(session, &token)
                .await
                .reason
                .as_deref(),
            Some("record_changed")
        );
        let current = store
            .service_map_snapshot(session, 10)
            .await
            .rows
            .into_iter()
            .find(|r| r.record_id == id)
            .unwrap()
            .evidence_id;
        store.insert(record("/trim")).await;
        assert_eq!(
            store
                .service_map_evidence(session, &current)
                .await
                .reason
                .as_deref(),
            Some("record_missing")
        );
        let reconstructed = TransactionStore::from_records(vec![row]);
        assert_eq!(
            reconstructed
                .service_map_evidence(session, &token)
                .await
                .reason
                .as_deref(),
            Some("stale_generation")
        );
        assert_eq!(
            store
                .service_map_evidence(session, "bad")
                .await
                .reason
                .as_deref(),
            Some("invalid_evidence_id")
        );
    }

    #[tokio::test]
    async fn service_map_durable_deletion_removes_exact_evidence_without_uuid_fallback() {
        let dir =
            std::env::temp_dir().join(format!("sniper-service-map-delete-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let row = record("/gone");
        let id = row.id;
        let session = Uuid::new_v4();
        let store = TransactionStore::from_records_with_journal(
            vec![row],
            dir.join("transactions.journal"),
            None,
        );
        let token = store.service_map_snapshot(session, 10).await.rows[0]
            .evidence_id
            .clone();
        store.delete_ids(&[id]).await.unwrap();
        assert_eq!(
            store
                .service_map_evidence(session, &token)
                .await
                .reason
                .as_deref(),
            Some("record_missing")
        );
        assert_eq!(
            store.service_map_snapshot(session, 10).await.retained_rows,
            0
        );
        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn service_map_scope_uses_shared_include_exclude_and_origin_filter() {
        let mut a = record("/a");
        a.host = "API.Example.COM.:443".into();
        let mut b = record("/b");
        b.host = "excluded.example.com".into();
        let mut c = record("/c");
        c.host = "[::1]:8443".into();
        let store = TransactionStore::from_records(vec![a, b, c]);
        let id = Uuid::new_v4();
        let result = build(
            id,
            store.service_map_snapshot(id, 100).await,
            100,
            true,
            None,
            &["*.example.com".into()],
            &["excluded.example.com".into()],
        );
        assert_eq!(result.origins.len(), 1);
        assert!(result.origins[0].in_scope);
        assert_eq!(result.snapshot.excluded_rows, 2);
        let filtered = build(
            id,
            store.service_map_snapshot(id, 100).await,
            100,
            false,
            Some("https://[::1]:8443".into()),
            &[],
            &[],
        );
        assert_eq!(filtered.origins.len(), 1);
        assert_eq!(filtered.origins[0].port, 8443);
    }

    #[tokio::test]
    async fn service_map_header_declarations_work_without_responses_and_reject_ambiguity() {
        let mut row = record("/");
        row.response = None;
        row.status = None;
        row.request.headers = headers(&[
            ("Origin", "https://source.example.com"),
            ("Referer", "https://source.example.com/path?q=secret"),
        ]);
        let projected = project_record(&row, "test".into()).unwrap();
        assert_eq!(projected.header_links.len(), 2);
        for value in [
            "null",
            "https://a.example.com https://b.example.com",
            "javascript:alert(1)",
            "/relative",
            "https://a.example.com/path",
            "https://user:secret@a.example.com",
        ] {
            assert!(declared_header_origin(value, true).is_none());
        }
        row.request.headers.push(HeaderRecord {
            name: "Origin".into(),
            value: "https://other.example.com".into(),
        });
        let projected = project_record(&row, "test".into()).unwrap();
        assert_eq!(projected.header_links.len(), 1);
        assert!(projected
            .omitted
            .contains(&"ambiguous_origin_header".into()));
    }

    fn header_declaration_cases() -> Vec<(&'static str, &'static str, Option<&'static str>)> {
        let mut cases = vec![
            (
                "Origin",
                "https://source.example.com",
                Some("https://source.example.com"),
            ),
            (
                "Origin",
                "HTTPS://SOURCE.Example.COM:443",
                Some("https://source.example.com"),
            ),
            (
                "Origin",
                "http://source.example.com:80",
                Some("http://source.example.com"),
            ),
            (
                "Origin",
                "https://source.example.com:8443",
                Some("https://source.example.com:8443"),
            ),
            (
                "Origin",
                "https://source.example.com/",
                Some("https://source.example.com"),
            ),
            (
                "Origin",
                " https://source.example.com:443/ ",
                Some("https://source.example.com"),
            ),
            (
                "Origin",
                "https://[2001:db8:0:0:0:0:0:1]:443",
                Some("https://[2001:db8::1]"),
            ),
            (
                "Origin",
                "http://[2001:db8::1]:8080/",
                Some("http://[2001:db8::1]:8080"),
            ),
            (
                "Referer",
                "https://source.example.com/path?q=QUERY_SENTINEL#FRAGMENT_SENTINEL",
                Some("https://source.example.com"),
            ),
            (
                "Referer",
                "https://source.example.com/a/..",
                Some("https://source.example.com"),
            ),
            (
                "Referer",
                "https://source.example.com/%2e",
                Some("https://source.example.com"),
            ),
            (
                "Referer",
                "https://USER_SENTINEL:PASS_SENTINEL@source.example.com/path",
                Some("https://source.example.com"),
            ),
        ];
        cases.extend(
            [
                "",
                "null",
                "/relative",
                "javascript:alert(1)",
                "https://",
                "https:///source.example.com",
                "https:////source.example.com",
                "http://///source.example.com/",
                "https://source.example.com//",
                "https://source.example.com/path",
                "https://source.example.com/.",
                "https://source.example.com/..",
                "https://source.example.com/a/..",
                "https://source.example.com/a/../",
                "https://source.example.com/%2e",
                "https://source.example.com/%2E/",
                "https://source.example.com/a/%2e%2e",
                "https://source.example.com/a/.%2e",
                "https://source.example.com/a/%2E.",
                "https://source.example.com/a/%2e%2E/",
                "https://@source.example.com",
                "https://:@source.example.com",
                "https://user@source.example.com",
                "https://user:secret@source.example.com",
                "https://source.example.com?",
                "https://source.example.com/?q=secret",
                "https://source.example.com#",
                "https://source.example.com/#fragment",
                "https://source.example.com https://other.example.com",
                "https://source.example.com,https://other.example.com",
                "https://source.example.com, null",
                "https://source.example.com,null",
                "https://source.example.com,",
                "https://source.example.com\\path",
            ]
            .into_iter()
            .map(|value| ("Origin", value, None)),
        );
        cases
    }

    #[test]
    fn service_map_header_declaration_rows_validate_raw_origin_structure() {
        for (header_name, value, expected) in header_declaration_cases() {
            for with_response in [false, true] {
                let mut row = record("/captured");
                row.request.headers = headers(&[(header_name, value)]);
                if !with_response {
                    row.response = None;
                    row.status = None;
                }
                let projected = project_record(&row, "test".into()).unwrap();
                assert_eq!(
                    projected.header_links.len(),
                    usize::from(expected.is_some()),
                    "{header_name}: {value:?}; with_response={with_response}"
                );
                if let Some(expected) = expected {
                    let link = &projected.header_links[0];
                    assert_eq!(link.source_origin, expected, "{header_name}: {value:?}");
                    assert_eq!(
                        link.relationship,
                        format!("{}_header", header_name.to_ascii_lowercase())
                    );
                }
                assert_eq!(projected.origin, "https://example.com");
                assert_eq!(projected.path, "/captured");
                assert!(projected.metadata_complete);
                assert!(!serde_json::to_string(&projected)
                    .unwrap()
                    .contains("SENTINEL"));
            }
        }
    }

    #[tokio::test]
    async fn service_map_header_declaration_aggregates_validate_raw_origin_structure() {
        for (header_name, value, expected) in header_declaration_cases() {
            let mut row = record("/captured");
            row.request.headers = headers(&[(header_name, value)]);
            let result = map(vec![row]).await;
            assert!(result.snapshot.complete);
            assert_eq!(result.snapshot.included_rows, 1);
            assert_eq!(result.snapshot.origin_count, 1);
            assert_eq!(result.snapshot.endpoint_count, 1);
            let origin = &result.origins[0];
            assert_eq!(origin.origin, "https://example.com");
            assert_eq!(origin.request_count, 1);
            assert_eq!(origin.endpoints[0].path, "/captured");
            assert_eq!(
                origin.header_links.len(),
                usize::from(expected.is_some()),
                "{header_name}: {value:?}"
            );
            if let Some(expected) = expected {
                let link = &origin.header_links[0];
                assert_eq!(link.source_origin, expected, "{header_name}: {value:?}");
                assert_eq!(
                    link.relationship,
                    format!("{}_header", header_name.to_ascii_lowercase())
                );
                assert_eq!(link.source, "request_header_declaration");
                assert_eq!(link.evidence, origin.endpoints[0].evidence);
            }
            assert!(!serde_json::to_string(&result).unwrap().contains("SENTINEL"));
        }
    }

    #[tokio::test]
    async fn service_map_redirect_is_only_an_unambiguous_3xx_instruction() {
        let mut row = record("/a/b");
        row.response.as_mut().unwrap().headers = headers(&[("Location", "../next?secret=gone")]);
        assert!(project_record(&row, "test".into())
            .unwrap()
            .redirect
            .is_none());
        row.status = Some(302);
        let projected = project_record(&row, "test".into()).unwrap();
        assert_eq!(projected.redirect.unwrap().target_path, "/next");
        row.response.as_mut().unwrap().headers.push(HeaderRecord {
            name: "Location".into(),
            value: "/other".into(),
        });
        let projected = project_record(&row, "test".into()).unwrap();
        assert!(projected.redirect.is_none());
        assert!(!projected.metadata_complete);
        assert!(projected
            .omitted
            .contains(&"ambiguous_location_headers".into()));
        // A long policy hides no Location; an unread Location may be a second.
        row.response.as_mut().unwrap().headers = headers(&[
            ("Location", "/next"),
            (
                "Content-Security-Policy",
                &"x".repeat(MAX_HEADER_VALUE_BYTES + 1),
            ),
        ]);
        let projected = project_record(&row, "test".into()).unwrap();
        assert_eq!(projected.redirect.unwrap().target_path, "/next");
        assert!(projected.omitted.contains(&"header_value_limit".into()));
        row.response.as_mut().unwrap().headers[1].name = "location".into();
        assert!(project_record(&row, "test".into())
            .unwrap()
            .redirect
            .is_none());
    }

    fn link_header_record() -> TransactionRecord {
        let mut row = record("/start");
        row.status = Some(302);
        row.request.headers = headers(&[("Origin", "https://page.example.com")]);
        row.response.as_mut().unwrap().headers = headers(&[
            ("Location", "https://next.example.com/next"),
            ("Access-Control-Allow-Origin", "https://page.example.com"),
            ("Access-Control-Allow-Credentials", "true"),
        ]);
        row
    }

    fn assert_independent_link_header_limit(unread_location: bool) {
        for catalog in [
            technology::CatalogVersion::V1,
            technology::CatalogVersion::V2,
        ] {
            for duplicate in [false, true] {
                for reverse in [false, true] {
                    for wildcard in [false, true] {
                        let mut row = link_header_record();
                        let response = row.response.as_mut().unwrap();
                        if wildcard {
                            response.headers[1].value = "*".into();
                        }
                        let index = usize::from(!unread_location);
                        let mut oversized = response.headers[index].clone();
                        oversized.name = if unread_location {
                            "lOcAtIoN".into()
                        } else {
                            "aCcEsS-cOnTrOl-AlLoW-oRiGiN".into()
                        };
                        oversized.value = "x".repeat(MAX_HEADER_VALUE_BYTES + 1);
                        if duplicate {
                            response.headers.push(oversized);
                        } else {
                            response.headers[index] = oversized;
                        }
                        if reverse {
                            response.headers.reverse();
                        }
                        let projected =
                            project_record_for_catalog(&row, "test".into(), catalog).unwrap();
                        assert!(!projected.metadata_complete);
                        assert_eq!(projected.omitted, ["header_value_limit"]);
                        assert_eq!(projected.redirect.is_some(), !unread_location);
                        assert_eq!(projected.cors.is_some(), unread_location);
                        if let Some(redirect) = projected.redirect {
                            assert_eq!(redirect.target_origin, "https://next.example.com");
                            assert_eq!(redirect.target_path, "/next");
                        }
                        if let Some(cors) = projected.cors {
                            assert_eq!(
                                cors,
                                (
                                    if wildcard {
                                        "*"
                                    } else {
                                        "https://page.example.com"
                                    }
                                    .into(),
                                    !wildcard,
                                )
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn service_map_oversized_location_preserves_independent_cors() {
        assert_independent_link_header_limit(true);
    }

    #[test]
    fn service_map_oversized_acao_preserves_independent_redirect() {
        assert_independent_link_header_limit(false);
    }

    #[test]
    fn service_map_link_header_value_boundary_and_duplicates_remain_conservative() {
        for index in [0, 1] {
            for length in [MAX_HEADER_VALUE_BYTES, MAX_HEADER_VALUE_BYTES + 1] {
                for duplicate in [false, true] {
                    let mut row = link_header_record();
                    let response = row.response.as_mut().unwrap();
                    let mut bounded = response.headers[index].clone();
                    bounded
                        .value
                        .push_str(&" ".repeat(length - bounded.value.len()));
                    if duplicate {
                        response.headers.push(bounded);
                    } else {
                        response.headers[index] = bounded;
                    }
                    let projected = project_record(&row, "test".into()).unwrap();
                    let own_admitted = !duplicate && length == MAX_HEADER_VALUE_BYTES;
                    assert_eq!(projected.redirect.is_some(), index != 0 || own_admitted);
                    assert_eq!(projected.cors.is_some(), index != 1 || own_admitted);
                    assert_eq!(
                        projected.omitted.contains(&"header_value_limit".into()),
                        length > MAX_HEADER_VALUE_BYTES
                    );
                    assert_eq!(
                        projected
                            .omitted
                            .contains(&"ambiguous_location_headers".into()),
                        index == 0 && duplicate && length == MAX_HEADER_VALUE_BYTES
                    );
                }
            }
        }
    }

    #[test]
    fn service_map_partial_link_header_scan_still_suppresses_both_proofs() {
        for byte_cap in [false, true] {
            for reverse in [false, true] {
                let mut row = link_header_record();
                if byte_cap {
                    let mut used: usize = row
                        .request
                        .headers
                        .iter()
                        .chain(&row.response.as_ref().unwrap().headers)
                        .map(|header| header.name.len() + header.value.len())
                        .sum();
                    let response = row.response.as_mut().unwrap();
                    while used < MAX_HEADER_BYTES {
                        let size = (MAX_HEADER_BYTES - used).min(MAX_HEADER_VALUE_BYTES + 1);
                        response.headers.push(HeaderRecord {
                            name: "x".into(),
                            value: "a".repeat(size - 1),
                        });
                        used += size;
                    }
                } else {
                    let needed = MAX_HEADERS
                        - row.request.headers.len()
                        - row.response.as_ref().unwrap().headers.len();
                    row.response
                        .as_mut()
                        .unwrap()
                        .headers
                        .extend(headers(&vec![("x", "a"); needed]));
                }
                if reverse {
                    row.response.as_mut().unwrap().headers.reverse();
                }
                let exact = project_record(&row, "test".into()).unwrap();
                assert!(exact.redirect.is_some());
                assert!(exact.cors.is_some());
                assert!(exact.metadata_complete);
                // Even an unrelated unread header could hide later duplicates.
                row.response.as_mut().unwrap().headers.push(HeaderRecord {
                    name: "x".into(),
                    value: String::new(),
                });
                let over = project_record(&row, "test".into()).unwrap();
                assert!(over.redirect.is_none());
                assert!(over.cors.is_none());
                assert_eq!(over.omitted, ["header_scan_limit"]);
                assert!(!over.metadata_complete);
            }
        }
    }

    #[tokio::test]
    async fn service_map_header_limits_and_exact_path_limits_are_explicit() {
        let mut row = record("/");
        row.status = Some(302);
        row.response.as_mut().unwrap().headers = (0..=MAX_HEADERS)
            .map(|_| HeaderRecord {
                name: "x-test".into(),
                value: "a".into(),
            })
            .collect();
        row.response.as_mut().unwrap().headers[0] = HeaderRecord {
            name: "location".into(),
            value: "/next".into(),
        };
        // A path past the endpoint cap, and a query past any header's, still
        // count for their origin; only the long path's endpoint is left out.
        let long_query = record(&format!("/pixel?d={}", "x".repeat(MAX_PATH_BYTES * 4)));
        let result = map(vec![
            row,
            record(&format!("/{}", "x".repeat(MAX_PATH_BYTES))),
            long_query,
        ])
        .await;
        assert!(!result.snapshot.complete);
        assert!(result
            .snapshot
            .stopped_by
            .contains(&"header_scan_limit".into()));
        assert!(result.snapshot.stopped_by.contains(&"path_limit".into()));
        assert!(!result
            .snapshot
            .stopped_by
            .contains(&"unsupported_or_oversized_metadata".into()));
        assert_eq!(result.snapshot.omitted_rows, 0);
        assert_eq!(result.origins[0].request_count, 3);
        let paths: Vec<_> = result.origins[0]
            .endpoints
            .iter()
            .map(|endpoint| endpoint.path.as_str())
            .collect();
        assert_eq!(paths.len(), 2, "{paths:?}");
        assert!(paths.contains(&"/pixel"));
        assert!(result.origins[0].redirects.is_empty());
    }

    #[tokio::test]
    async fn service_map_a_repeated_unnamed_header_is_one_signal_and_one_row() {
        let mut row = record("/unnamed");
        row.response.as_mut().unwrap().headers = (0..MAX_UNNAMED_PER_ROW + 4)
            .map(|_| HeaderRecord {
                name: "x-synthetic-repeat".into(),
                value: "fixture".into(),
            })
            .collect();
        let projected = project_record(&row, "test".into()).unwrap();
        assert_eq!(projected.unnamed.len(), 1);
        assert!(projected.metadata_complete, "{:?}", projected.omitted);
        let result = map(vec![row]).await;
        assert!(result.snapshot.complete);
        let signals = &result.origins[0].unnamed.headers;
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].row_count, 1);
    }

    #[tokio::test]
    async fn service_map_unnamed_row_cap_reports_signal_loss_without_omitting_rows() {
        for count in [0, MAX_UNNAMED_PER_ROW, MAX_UNNAMED_PER_ROW + 1, 24] {
            let mut row = record("/unnamed");
            row.response.as_mut().unwrap().headers = (0..count)
                .map(|index| HeaderRecord {
                    name: format!("x-synthetic-{index:02}"),
                    value: "fixture".into(),
                })
                .collect();
            let projected = project_record(&row, "test".into()).unwrap();
            assert_eq!(projected.unnamed.len(), count.min(MAX_UNNAMED_PER_ROW));
            let expected = if count > MAX_UNNAMED_PER_ROW {
                vec!["unnamed_signals_per_row_limit".to_string()]
            } else {
                vec![]
            };
            assert_eq!(projected.omitted, expected);
            assert_eq!(projected.metadata_complete, expected.is_empty());
            let result = map(vec![row]).await;
            assert_eq!(result.snapshot.stopped_by, expected);
            assert_eq!(result.snapshot.complete, expected.is_empty());
            assert_eq!(result.snapshot.omitted_rows, 0);
            assert_eq!(result.snapshot.included_rows, 1);
            assert_eq!(
                result.origins[0].unnamed.headers.len(),
                count.min(MAX_UNNAMED_PER_ROW)
            );
        }
    }

    #[tokio::test]
    async fn service_map_unnamed_origin_caps_report_each_kind_and_keep_exact_available_counts() {
        for kind in ["banner", "header", "cookie"] {
            for count in [MAX_UNNAMED, MAX_UNNAMED + 1, 24] {
                let records = (0..count)
                    .map(|index| {
                        let mut row = record("/unnamed");
                        let (name, value) = match kind {
                            "banner" => ("Server".into(), format!("Synthetic{index:02}")),
                            "cookie" => {
                                ("Set-Cookie".into(), format!("synthetic_{index:02}=fixture"))
                            }
                            _ => (format!("x-synthetic-{index:02}"), "fixture".into()),
                        };
                        row.response.as_mut().unwrap().headers = vec![HeaderRecord { name, value }];
                        row
                    })
                    .collect();
                let result = map(records).await;
                let expected = if count > MAX_UNNAMED {
                    vec!["unnamed_signals_per_origin_limit".to_string()]
                } else {
                    vec![]
                };
                assert_eq!(result.snapshot.stopped_by, expected, "{kind} {count}");
                assert_eq!(result.snapshot.complete, expected.is_empty());
                assert_eq!(result.snapshot.omitted_rows, 0);
                assert_eq!(result.snapshot.included_rows, count);
                let unnamed = &result.origins[0].unnamed;
                let signals = match kind {
                    "banner" => &unnamed.banners,
                    "cookie" => &unnamed.cookies,
                    _ => &unnamed.headers,
                };
                assert_eq!(signals.len(), MAX_UNNAMED);
                assert!(signals
                    .iter()
                    .all(|signal| signal.row_count == 1 && signal.evidence.len() == 1));
            }
        }
    }

    #[test]
    fn a_read_tracks_a_bounded_number_of_names_per_origin_and_kind() {
        let mut tracked = HashMap::new();
        for _ in 0..MAX_TRACKED_PER_ORIGIN_KIND {
            assert!(MapBuilder::track(
                &mut tracked,
                "https://a.example.com",
                "header"
            ));
        }
        assert!(!MapBuilder::track(
            &mut tracked,
            "https://a.example.com",
            "header"
        ));
        assert!(MapBuilder::track(
            &mut tracked,
            "https://a.example.com",
            "cookie"
        ));
        assert!(MapBuilder::track(
            &mut tracked,
            "https://b.example.com",
            "header"
        ));
    }

    #[tokio::test]
    async fn service_map_newest_window_and_evidence_samples_are_bounded() {
        let store = TransactionStore::from_records(
            (0..10)
                .rev()
                .map(|index| {
                    let mut r = record("/same");
                    r.status = Some(200 + index);
                    r
                })
                .collect(),
        );
        let session = Uuid::new_v4();
        let result = build(
            session,
            store.service_map_snapshot(session, 5).await,
            5,
            false,
            None,
            &[],
            &[],
        );
        assert_eq!(result.snapshot.retained_rows, 10);
        assert_eq!(result.snapshot.considered_rows, 5);
        assert_eq!(result.snapshot.included_rows, 5);
        assert_eq!(result.origins[0].request_count, 5);
        assert_eq!(result.origins[0].endpoints[0].evidence.len(), MAX_EVIDENCE);
        assert!(!result.snapshot.complete);
        assert_eq!(result.snapshot.stopped_by, vec!["max_records"]);
    }

    #[tokio::test]
    async fn service_map_high_cardinality_bounds_and_origin_expansion() {
        let records = (0..MAX_ORIGINS + 1)
            .map(|index| {
                let mut r = record("/");
                r.host = format!("{index}.example.com");
                r
            })
            .collect();
        let store = TransactionStore::from_records(records);
        let session = Uuid::new_v4();
        let result = build(
            session,
            store.service_map_snapshot(session, MAX_RECORDS).await,
            MAX_RECORDS,
            false,
            None,
            &[],
            &[],
        );
        assert_eq!(result.origins.len(), MAX_ORIGINS);
        assert!(!result.snapshot.complete);
        assert!(result.snapshot.stopped_by.contains(&"origins_limit".into()));
        let expanded = build(
            session,
            store.service_map_snapshot(session, MAX_RECORDS).await,
            MAX_RECORDS,
            false,
            Some("https://500.example.com".into()),
            &[],
            &[],
        );
        assert_eq!(expanded.origins.len(), 1);
        assert!(expanded.snapshot.complete);
        let endpoints = map((0..MAX_ENDPOINTS_PER_ORIGIN + 1)
            .map(|i| record(&format!("/item/{i}")))
            .collect())
        .await;
        assert_eq!(
            endpoints.origins[0].endpoints.len(),
            MAX_ENDPOINTS_PER_ORIGIN
        );
        assert_eq!(
            endpoints.origins[0].request_count,
            MAX_ENDPOINTS_PER_ORIGIN + 1
        );
        assert!(endpoints
            .snapshot
            .stopped_by
            .contains(&"endpoints_limit".into()));
    }

    #[tokio::test]
    async fn service_map_projection_byte_budget_bounds_long_paths() {
        let suffix = "x".repeat(1900);
        let store = TransactionStore::from_records(
            (0..5000)
                .map(|i| record(&format!("/{i}/{suffix}")))
                .collect(),
        );
        let session = Uuid::new_v4();
        let start = std::time::Instant::now();
        let snapshot = store.service_map_snapshot(session, MAX_RECORDS).await;
        eprintln!(
            "service-map bounded 5000-row projection: {:?}, {} considered",
            start.elapsed(),
            snapshot.considered_rows
        );
        assert!(snapshot.considered_rows < 5000);
        assert!(snapshot.stopped_by.contains("metadata_bytes"));
        assert!(
            snapshot
                .rows
                .iter()
                .map(|r| serde_json::to_vec(r).unwrap().len())
                .sum::<usize>()
                <= MAX_METADATA_BYTES
        );
    }
    #[tokio::test]
    async fn service_map_missing_body_file_does_not_trigger_body_rehydration() {
        let dir =
            std::env::temp_dir().join(format!("sniper-service-map-metadata-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut row = record("/metadata-only");
        row.request.body_preview.clear();
        row.response.as_mut().unwrap().body_preview.clear();
        row.response.as_mut().unwrap().headers = headers(&[("Server", "Jetty(12.0.1)")]);
        let id = row.id;
        let store = TransactionStore::from_located_records_with_journal(
            vec![row],
            std::collections::HashMap::from([(
                id,
                crate::session::BodyLocator {
                    offset: 999,
                    len: 999,
                },
            )]),
            &std::collections::HashSet::new(),
            dir.join("transactions.journal"),
            0,
        );
        let session = Uuid::new_v4();
        let snapshot = store.service_map_snapshot(session, 10).await;
        assert_eq!(snapshot.rows.len(), 1);
        let evidence = store
            .service_map_evidence(session, &snapshot.rows[0].evidence_id)
            .await;
        assert!(evidence.available);
        let row = evidence.row.unwrap();
        assert_eq!(row.path, "/metadata-only");
        assert_eq!(
            row.technology_observations.as_ref().unwrap()[0]
                .reported_version
                .as_deref(),
            Some("12.0.1")
        );
        assert!(!dir.join("transactions.ndjson").exists());
        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn service_map_considered_times_use_actual_extrema_with_out_of_order_completion() {
        let mut early = record("/early");
        let mut late = record("/late");
        early.started_at = Utc::now() - chrono::Duration::hours(1);
        late.started_at = Utc::now();
        let first = late.started_at;
        let last = early.started_at;
        // Newest capture completed last, but began first.
        let result = map(vec![early, late]).await;
        assert_eq!(result.snapshot.first_retained_started_at, Some(first));
        assert_eq!(result.snapshot.last_retained_started_at, Some(last));
        assert_eq!(result.snapshot.oldest_considered_at, Some(last));
        assert_eq!(result.snapshot.latest_considered_at, Some(first));
    }
    #[tokio::test]
    async fn service_map_connect_is_case_sensitive_and_nonredirect_3xx_has_no_edge() {
        let mut lower = record("/custom");
        lower.method = "connect".into();
        let mut upper = record("/tunnel");
        upper.method = "CONNECT".into();
        let result = map(vec![lower, upper]).await;
        assert_eq!(result.snapshot.non_http_rows, 1);
        assert_eq!(result.origins[0].endpoints[0].method, "connect");
        for status in [304, 305, 306, 309, 399] {
            let mut row = record("/");
            row.status = Some(status);
            row.response.as_mut().unwrap().headers = headers(&[("Location", "/next")]);
            assert!(project_record(&row, "test".into())
                .unwrap()
                .redirect
                .is_none());
        }
        for host in [
            " example.com",
            "example.com\n",
            "example.com\t",
            "example.com/path",
            "example.com?token=secret",
        ] {
            let mut row = record("/");
            row.host = host.into();
            assert!(project_record(&row, "test".into()).is_none());
        }
    }
    #[test]
    fn service_map_websocket_and_mime_checks_obey_header_field_bounds() {
        let mut row = record("/websocket");
        row.status = Some(101);
        row.request.headers = (0..MAX_HEADERS)
            .map(|_| HeaderRecord {
                name: "x-test".into(),
                value: "a".into(),
            })
            .collect();
        row.request.headers.extend(headers(&[
            ("Connection", "upgrade"),
            ("Upgrade", "websocket"),
        ]));
        row.response.as_mut().unwrap().content_type = Some("x".repeat(MAX_HEADER_VALUE_BYTES + 1));
        let projected = project_record(&row, "test".into()).unwrap();
        assert!(!projected.is_websocket);
        assert!(projected.content_type.is_none());
        assert!(projected
            .omitted
            .contains(&"request_header_scan_limit".into()));
        assert!(projected
            .omitted
            .contains(&"unsupported_content_type".into()));
        row.request.headers = headers(&[
            ("Connection", "keep-alive, Upgrade"),
            ("Upgrade", "websocket"),
        ]);
        assert!(project_record(&row, "test".into()).unwrap().is_websocket);
    }
    #[tokio::test]
    async fn service_map_scope_matches_original_expanded_ipv6_and_alias_rows() {
        let mut expanded = record("/expanded");
        expanded.host = "[0:0:0:0:0:0:0:1]:8443".into();
        let mut compressed = record("/compressed");
        compressed.host = "[::1]:8443".into();
        let store = TransactionStore::from_records(vec![expanded, compressed]);
        let session = Uuid::new_v4();
        let include = vec!["0:0:0:0:0:0:0:1".into()];
        let filtered = build(
            session,
            store.service_map_snapshot(session, 10).await,
            10,
            true,
            None,
            &include,
            &[],
        );
        assert_eq!(filtered.origins.len(), 1);
        assert_eq!(filtered.origins[0].origin, "https://[::1]:8443");
        assert_eq!(filtered.origins[0].request_count, 1);
        assert_eq!(filtered.origins[0].endpoints[0].path, "/expanded");
        assert_eq!(filtered.snapshot.excluded_rows, 1);
        let all = build(
            session,
            store.service_map_snapshot(session, 10).await,
            10,
            false,
            None,
            &include,
            &[],
        );
        assert_eq!(all.origins[0].request_count, 2);
        assert!(all.origins[0].in_scope);
        assert!(!serde_json::to_string(&all).unwrap().contains("scope_host"));
    }

    fn technology_record(host: &str, version: usize) -> TransactionRecord {
        let mut row = record("/technology");
        row.host = host.into();
        row.response.as_mut().unwrap().headers =
            headers(&[("Server", &format!("nginx/{version}.1"))]);
        row
    }

    #[tokio::test]
    async fn service_map_catalog_selection_precedes_row_caps_and_keeps_exact_identity() {
        let mut first = record("/catalog-first");
        first.response.as_mut().unwrap().headers = headers(&[(
            "Server",
            &format!(
                "{}nginx/1.2",
                "gunicorn/3 ".repeat(technology::MAX_OBSERVATIONS_PER_ROW)
            ),
        )]);
        let mut second = first.clone();
        second.path = "/catalog-second".into();
        let session = Uuid::new_v4();
        let store = TransactionStore::from_records(vec![first, second]);
        let legacy = store.service_map_snapshot(session, 10).await;
        let explicit_v1 = store
            .service_map_snapshot_for_catalog(session, 10, technology::CatalogVersion::V1)
            .await;
        assert_eq!(
            serde_json::to_vec(&legacy.rows).unwrap(),
            serde_json::to_vec(&explicit_v1.rows).unwrap()
        );
        let v2 = store
            .service_map_snapshot_for_catalog(session, 10, technology::CatalogVersion::V2)
            .await;
        for (old, new) in legacy.rows.iter().zip(&v2.rows) {
            assert_eq!(old.evidence_id, new.evidence_id);
            assert_eq!(old.sequence, new.sequence);
            assert_eq!(old.record_id, new.record_id);
            assert!(old.omitted.is_empty());
            assert_eq!(old.technology_observations.as_ref().unwrap().len(), 1);
            assert_eq!(
                old.technology_observations.as_ref().unwrap()[0].product_id,
                "nginx"
            );
            assert_eq!(
                new.technology_observations.as_ref().unwrap().len(),
                technology::MAX_OBSERVATIONS_PER_ROW
            );
            assert!(new
                .technology_observations
                .as_ref()
                .unwrap()
                .iter()
                .all(|o| o.product_id == "gunicorn"));
            assert_eq!(new.omitted, vec!["technology_observations_limit"]);
            for (catalog, projected) in [
                (technology::CatalogVersion::V1, old),
                (technology::CatalogVersion::V2, new),
            ] {
                let evidence = store
                    .service_map_evidence_for_catalog(
                        session,
                        &projected.evidence_id,
                        false,
                        catalog,
                    )
                    .await;
                assert_eq!(
                    serde_json::to_vec(evidence.row.as_ref().unwrap()).unwrap(),
                    serde_json::to_vec(projected).unwrap()
                );
                assert!(evidence.technology_catalog_version.is_none());
            }
        }
        assert_ne!(legacy.rows[0].evidence_id, legacy.rows[1].evidence_id);
        let result = build(session, v2, 10, false, None, &[], &[]);
        let aggregate = &result.origins[0].technology_observations.as_ref().unwrap()[0];
        assert_eq!(aggregate.row_count, 2);
        assert_eq!(aggregate.evidence.len(), 2);
        assert!(aggregate.is_valid_for_catalog(technology::CatalogVersion::V2));
        assert!(!aggregate.is_valid());
    }

    #[tokio::test]
    async fn service_map_catalog_selection_precedes_origin_and_global_caps() {
        for (rows, cap, marker) in [
            (
                technology::MAX_OBSERVATIONS_PER_ORIGIN,
                technology::MAX_OBSERVATIONS_PER_ORIGIN,
                "technology_observations_per_origin_limit",
            ),
            (
                technology::MAX_OBSERVATIONS,
                technology::MAX_OBSERVATIONS,
                "technology_observations_map_limit",
            ),
        ] {
            let records = (0..rows)
                .map(|index| {
                    let host = if rows == technology::MAX_OBSERVATIONS {
                        format!("{}.example.com", index / 8)
                    } else {
                        "example.com".into()
                    };
                    let mut record = technology_record(&host, index);
                    record.response.as_mut().unwrap().headers =
                        headers(&[("Server", &format!("gunicorn/{index} nginx/{index}"))]);
                    record
                })
                .collect();
            let store = TransactionStore::from_records(records);
            let session = Uuid::new_v4();
            let legacy = build(
                session,
                store.service_map_snapshot(session, MAX_RECORDS).await,
                MAX_RECORDS,
                false,
                None,
                &[],
                &[],
            );
            let v1 = build(
                session,
                store
                    .service_map_snapshot_for_catalog(
                        session,
                        MAX_RECORDS,
                        technology::CatalogVersion::V1,
                    )
                    .await,
                MAX_RECORDS,
                false,
                None,
                &[],
                &[],
            );
            assert_eq!(
                serde_json::to_vec(&legacy.origins).unwrap(),
                serde_json::to_vec(&v1.origins).unwrap()
            );
            assert_eq!(legacy.snapshot.stopped_by, v1.snapshot.stopped_by);
            assert!(!legacy.snapshot.stopped_by.contains(&marker.into()));
            let v2 = build(
                session,
                store
                    .service_map_snapshot_for_catalog(
                        session,
                        MAX_RECORDS,
                        technology::CatalogVersion::V2,
                    )
                    .await,
                MAX_RECORDS,
                false,
                None,
                &[],
                &[],
            );
            let observations: Vec<_> = v2
                .origins
                .iter()
                .flat_map(|origin| origin.technology_observations.as_ref().unwrap())
                .collect();
            assert_eq!(observations.len(), cap);
            assert!(observations
                .iter()
                .any(|observation| observation.product_id == "gunicorn"));
            assert!(v2.snapshot.stopped_by.contains(&marker.into()));
            assert!(!v2.snapshot.stopped_by.contains(&"metadata_bytes".into()));
            assert_eq!(v2.snapshot.included_rows, rows);
        }
    }

    #[tokio::test]
    async fn service_map_catalog_marker_absence_preserves_legacy_wire_shape() {
        let result = map(vec![record("/legacy")]).await;
        let mut value = serde_json::to_value(&result).unwrap();
        assert!(!value
            .as_object()
            .unwrap()
            .contains_key("technology_catalog_version"));
        value["technology_catalog_version"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<ServiceMap>(value).is_err());
        let evidence =
            ServiceMapEvidence::missing(result.session_id, "test".into(), "record_missing");
        let mut value = serde_json::to_value(&evidence).unwrap();
        assert!(!value
            .as_object()
            .unwrap()
            .contains_key("technology_catalog_version"));
        value["technology_catalog_version"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<ServiceMapEvidence>(value).is_err());
    }

    #[tokio::test]
    async fn service_map_technology_aggregates_distinct_rows_without_selecting_a_version() {
        let mut first = record("/a");
        first.started_at = Utc::now() - chrono::Duration::hours(2);
        first.response.as_mut().unwrap().headers = headers(&[
            ("Server", " \t(한글) nginx/1.24.0 nginx/1.24.0"),
            ("SERVER", "nginx/1.24.0"),
            ("X-Powered-By", "PHP/8.3.1"),
        ]);
        let mut second = first.clone();
        second.path = "/b".into();
        second.started_at += chrono::Duration::hours(1);
        second.response.as_mut().unwrap().headers = headers(&[
            ("Server", "nginx/1.24.0 nginx/1.25.3 PHP/8.3.1"),
            ("Server", "nginx/SECRET_VERSION_SENTINEL"),
        ]);
        let session = Uuid::new_v4();
        let store = TransactionStore::from_records(vec![second.clone(), first.clone()]);
        let snapshot = store.service_map_snapshot(session, 10).await;
        let first_row = snapshot.rows.iter().find(|row| row.path == "/a").unwrap();
        let row_observations = first_row.technology_observations.as_ref().unwrap();
        assert_eq!(row_observations.len(), 4);
        assert_eq!(row_observations[2].header_index, 1);
        let exact = store
            .service_map_evidence(session, &first_row.evidence_id)
            .await;
        assert_eq!(
            serde_json::to_value(exact.row.unwrap().technology_observations).unwrap(),
            serde_json::to_value(&first_row.technology_observations).unwrap()
        );
        for row in &snapshot.rows {
            let exact = store.service_map_evidence(session, &row.evidence_id).await;
            assert!(!serde_json::to_string(&exact).unwrap().contains("SENTINEL"));
        }
        let result = build(session, snapshot, 10, false, None, &[], &[]);
        let observations = result.origins[0].technology_observations.as_ref().unwrap();
        assert_eq!(observations.len(), 5);
        assert!(observations.iter().all(TechnologyAggregate::is_valid));
        let repeated = observations
            .iter()
            .find(|o| o.reported_version.as_deref() == Some("1.24.0"))
            .unwrap();
        assert_eq!(repeated.row_count, 2);
        assert_eq!(repeated.evidence.len(), 2);
        assert_ne!(repeated.evidence[0], repeated.evidence[1]);
        assert_eq!(repeated.first_seen, first.started_at);
        assert_eq!(repeated.last_seen, second.started_at);
        assert_eq!(
            observations
                .iter()
                .filter(|o| o.product_id == "php")
                .count(),
            2
        );
        assert_eq!(
            observations
                .iter()
                .filter(|o| o.product_id == "nginx")
                .count(),
            3
        );
        assert!(!serde_json::to_string(&result).unwrap().contains("SENTINEL"));
        // Existing legacy extraction still recognizes only the leading Server product.
        assert_eq!(result.origins[0].technology_clues.len(), 2);
    }

    #[tokio::test]
    async fn service_map_technology_row_limit_preserves_explicit_omissions() {
        let mut row = record("/bounded");
        row.response.as_mut().unwrap().headers = headers(&[("Server", &"nginx/1.2 ".repeat(9))]);
        let session = Uuid::new_v4();
        let store = TransactionStore::from_records(vec![row]);
        let snapshot = store.service_map_snapshot(session, 10).await;
        let projected = &snapshot.rows[0];
        assert_eq!(
            projected.technology_observations.as_ref().unwrap().len(),
            technology::MAX_OBSERVATIONS_PER_ROW
        );
        assert!(!projected.metadata_complete);
        assert!(projected
            .omitted
            .contains(&"technology_observations_limit".into()));
        let evidence = store
            .service_map_evidence(session, &projected.evidence_id)
            .await;
        assert!(evidence
            .row
            .unwrap()
            .omitted
            .contains(&"technology_observations_limit".into()));
        let result = build(session, snapshot, 10, false, None, &[], &[]);
        assert!(!result.snapshot.complete);
        assert!(result
            .snapshot
            .stopped_by
            .contains(&"technology_observations_limit".into()));
        assert_eq!(
            result.origins[0].technology_observations.as_ref().unwrap()[0].row_count,
            1
        );
    }

    #[test]
    fn service_map_technology_ignores_request_headers_and_resident_body_text() {
        let mut record = record("/metadata-only");
        record.request.headers = headers(&[("Server", "nginx/1.2"), ("X-Powered-By", "PHP/8.3")]);
        record.response.as_mut().unwrap().body_preview = "Server: Apache/2.4.62 PHP/8.3.1".into();
        let projected = project_record(&record, "test".into()).unwrap();
        assert!(projected.technology_clues.is_empty());
        assert!(projected.technology_observations.unwrap().is_empty());
    }

    #[tokio::test]
    async fn service_map_technology_origin_cap_keeps_counting_retained_tuples() {
        let mut records: Vec<_> = (0..technology::MAX_OBSERVATIONS_PER_ORIGIN + 3)
            .map(|version| technology_record("example.com", version))
            .collect();
        records.extend((0..4).map(|_| technology_record("example.com", 0)));
        let result = map(records).await;
        let observations = result.origins[0].technology_observations.as_ref().unwrap();
        assert_eq!(observations.len(), technology::MAX_OBSERVATIONS_PER_ORIGIN);
        assert!(result
            .snapshot
            .stopped_by
            .contains(&"technology_observations_per_origin_limit".into()));
        let retained = observations
            .iter()
            .find(|o| o.reported_version.as_deref() == Some("0.1"))
            .unwrap();
        assert_eq!(retained.row_count, 5);
        assert_eq!(retained.evidence.len(), MAX_EVIDENCE);
        assert!(retained.is_valid());
        assert_eq!(
            result.snapshot.included_rows,
            technology::MAX_OBSERVATIONS_PER_ORIGIN + 7
        );
    }

    #[tokio::test]
    async fn service_map_technology_global_cap_keeps_other_metadata_and_retained_counts() {
        let mut records: Vec<_> = (0..technology::MAX_OBSERVATIONS + 3)
            .map(|index| technology_record(&format!("{}.example.com", index / 8), index % 8))
            .collect();
        records.push(technology_record("0.example.com", 0));
        let result = map(records).await;
        assert_eq!(
            result
                .origins
                .iter()
                .map(|o| o.technology_observations.as_ref().unwrap().len())
                .sum::<usize>(),
            technology::MAX_OBSERVATIONS
        );
        assert!(result
            .snapshot
            .stopped_by
            .contains(&"technology_observations_map_limit".into()));
        assert!(!result
            .snapshot
            .stopped_by
            .contains(&"metadata_bytes".into()));
        assert_eq!(
            result.snapshot.included_rows,
            technology::MAX_OBSERVATIONS + 4
        );
        let retained = result
            .origins
            .iter()
            .find(|o| o.host == "0.example.com")
            .unwrap()
            .technology_observations
            .as_ref()
            .unwrap()
            .iter()
            .find(|o| o.reported_version.as_deref() == Some("0.1"))
            .unwrap();
        assert_eq!(retained.row_count, 2);
        assert!(retained.is_valid());
        assert_eq!(result.snapshot.origin_count, 251);
    }

    #[tokio::test]
    async fn service_map_technology_extensions_are_optional_but_present_null_is_invalid() {
        let result = map(vec![record("/old")]).await;
        let mut json = serde_json::to_value(&result).unwrap();
        json["origins"][0]
            .as_object_mut()
            .unwrap()
            .remove("technology_observations");
        for key in [
            "technology_observations_per_row",
            "technology_observations_per_origin",
            "technology_observations",
            "technology_version_bytes",
            "technology_token_candidates_per_row",
        ] {
            json["snapshot"]["limits"]
                .as_object_mut()
                .unwrap()
                .remove(key);
        }
        let old: ServiceMap = serde_json::from_value(json.clone()).unwrap();
        assert!(old.origins[0].technology_observations.is_none());
        assert!(old.snapshot.limits.technology_observations.is_none());
        json["origins"][0]["technology_observations"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<ServiceMap>(json).is_err());
        let row = project_record(&record("/old"), "test".into()).unwrap();
        let mut json = serde_json::to_value(row).unwrap();
        json.as_object_mut()
            .unwrap()
            .remove("technology_observations");
        assert!(serde_json::from_value::<ServiceMapRow>(json.clone())
            .unwrap()
            .technology_observations
            .is_none());
        json["technology_observations"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<ServiceMapRow>(json).is_err());
    }

    #[tokio::test]
    async fn service_map_technology_token_limit_is_explicit_without_truncating_legacy_metadata() {
        let mut row = record("/bounded-tokens");
        row.status = Some(302);
        row.response.as_mut().unwrap().headers = headers(&[
            (
                "Server",
                &"x ".repeat(technology::MAX_TOKEN_CANDIDATES_PER_ROW),
            ),
            ("Server", "nginx/1.2"),
            ("Location", "/next"),
            ("X-Powered-By", "PHP/8.3.1"),
        ]);
        let session = Uuid::new_v4();
        let store = TransactionStore::from_records(vec![row]);
        let snapshot = store.service_map_snapshot(session, 10).await;
        let projected = &snapshot.rows[0];
        assert!(!projected.metadata_complete);
        assert_eq!(projected.omitted, vec!["technology_token_scan_limit"]);
        assert!(projected
            .technology_observations
            .as_ref()
            .unwrap()
            .is_empty());
        assert_eq!(projected.technology_clues.len(), 2);
        assert_eq!(projected.redirect.as_ref().unwrap().target_path, "/next");
        let evidence = store
            .service_map_evidence(session, &projected.evidence_id)
            .await;
        assert_eq!(
            evidence.row.unwrap().omitted,
            vec!["technology_token_scan_limit"]
        );
        let result = build(session, snapshot, 10, false, None, &[], &[]);
        assert!(!result.snapshot.complete);
        assert_eq!(
            result.snapshot.stopped_by,
            vec!["technology_token_scan_limit"]
        );
        assert_eq!(result.snapshot.included_rows, 1);
        assert_eq!(
            result.snapshot.limits.technology_token_candidates_per_row,
            Some(128)
        );
        assert_eq!(result.origins[0].technology_clues.len(), 2);
        assert_eq!(result.origins[0].redirects.len(), 1);

        let mut exact = record("/exact-budget");
        exact.response.as_mut().unwrap().headers = headers(&[
            (
                "Server",
                &"x ".repeat(technology::MAX_TOKEN_CANDIDATES_PER_ROW - 1),
            ),
            ("X-Powered-By", "PHP/8.3.1"),
            ("Server", " \t "),
            ("Location", "/not-a-redirect"),
        ]);
        let result = map(vec![exact]).await;
        assert!(result.snapshot.complete);
        assert!(result.snapshot.stopped_by.is_empty());
        assert_eq!(
            result.origins[0].technology_observations.as_ref().unwrap()[0]
                .reported_version
                .as_deref(),
            Some("8.3.1")
        );
    }

    fn assert_no_synthetic_body_technology(row: &ServiceMapRow) {
        // Opaque evidence tokens can legitimately contain the same numeric text
        // across UUID/sequence delimiters. Check only the declaration fields.
        assert!(row
            .technology_observations
            .as_ref()
            .unwrap()
            .iter()
            .all(|observation| observation.product_id != "jetty"
                && observation.reported_version.as_deref() != Some("99.99")));
    }

    #[test]
    fn service_map_body_technology_check_accepts_opaque_token_collisions() {
        let mut row = record("/token-collision");
        row.sequence = 99;
        row.response.as_mut().unwrap().body_preview = "RESPONSE_BODY_SENTINEL Jetty(99.99)".into();
        row.response.as_mut().unwrap().headers = headers(&[("Server", "nginx/1.26.2")]);
        let ending_99 = Uuid::parse_str("00000000-0000-0000-0000-000000000099").unwrap();
        let starting_99 = Uuid::parse_str("99000000-0000-0000-0000-000000000000").unwrap();
        for (generation, revision) in [(ending_99, Uuid::nil()), (Uuid::nil(), starting_99)] {
            let token = evidence_id(Uuid::nil(), generation, revision, &row);
            assert!(EvidenceKey::parse(&token).is_some());
            assert!(token.contains("99.99"));
            let projected = project_record(&row, token).unwrap();
            let serialized = serde_json::to_string(&projected).unwrap();
            // This is a deterministic counterexample to a whole-row substring check.
            assert!(serialized.contains("99.99"));
            assert!(!serialized.contains("BODY_SENTINEL"));
            assert!(!serialized.contains("body_preview"));
            assert_no_synthetic_body_technology(&projected);
            for product_leak in [false, true] {
                let mut leaked = projected.clone();
                let observation = &mut leaked.technology_observations.as_mut().unwrap()[0];
                if product_leak {
                    observation.product_id = "jetty".into();
                } else {
                    observation.reported_version = Some("99.99".into());
                }
                assert!(
                    std::panic::catch_unwind(|| assert_no_synthetic_body_technology(&leaked))
                        .is_err()
                );
            }
        }
    }

    #[tokio::test]
    async fn service_map_technology_snapshot_scan_work_is_measured_and_bounded() {
        const ROWS: usize = 1_000;
        // Eight 4090-byte values plus their six-byte names use exactly the
        // existing 32-KiB row budget. Unknown one-byte tokens exercise parser
        // work that does not increase the serialized-metadata byte counter.
        let dense_value = "x ".repeat((MAX_HEADER_VALUE_BYTES - 6) / 2);
        let dense_headers = headers(&[("Server", dense_value.as_str()); 8]);
        assert_eq!(
            dense_headers
                .iter()
                .map(|header| header.name.len() + header.value.len())
                .sum::<usize>(),
            MAX_HEADER_BYTES
        );
        let ordinary_headers = headers(&[
            ("Server", "Apache/2.4.62 (Unix) PHP/8.3.1"),
            ("X-Powered-By", "Express/4.21.2"),
        ]);
        // Each iteration owns and drops its store before allocating the next,
        // keeping retained synthetic header data around 32 MiB at peak.
        for (scenario, response_headers, observations_per_row, expected_partial) in [
            ("dense_unknown_tokens", dense_headers, 0, true),
            ("ordinary_explicit_products", ordinary_headers, 3, false),
        ] {
            let header_bytes_per_row = response_headers
                .iter()
                .map(|header| header.name.len() + header.value.len())
                .sum::<usize>();
            let records = (0..ROWS)
                .map(|_| {
                    let mut row = record("/scan-work");
                    row.request.body_preview = "REQUEST_BODY_SENTINEL".into();
                    let response = row.response.as_mut().unwrap();
                    response.body_preview = "RESPONSE_BODY_SENTINEL Jetty(99.99)".into();
                    response.headers = response_headers.clone();
                    row
                })
                .collect();
            // No journal, storage directory, locators, app, or target is involved.
            let store = TransactionStore::from_records(records);
            let session = Uuid::new_v4();
            for catalog in [
                technology::CatalogVersion::V1,
                technology::CatalogVersion::V2,
            ] {
                let started = std::time::Instant::now();
                let snapshot = store
                    .service_map_snapshot_for_catalog(session, ROWS, catalog)
                    .await;
                let elapsed = started.elapsed();
                let projected_bytes = snapshot
                    .rows
                    .iter()
                    .map(|row| {
                        let serialized = serde_json::to_string(row).unwrap();
                        assert!(!serialized.contains("BODY_SENTINEL"));
                        assert!(!serialized.contains("body_preview"));
                        assert_no_synthetic_body_technology(row);
                        assert_eq!(
                            row.technology_observations.as_ref().unwrap().len(),
                            observations_per_row
                        );
                        assert_eq!(row.metadata_complete, !expected_partial);
                        assert_eq!(
                            row.omitted.contains(&"technology_token_scan_limit".into()),
                            expected_partial
                        );
                        serialized.len()
                    })
                    .sum::<usize>();
                eprintln!(
                "service-map header scan catalog={catalog:?} {scenario}: retained_rows={}, considered_rows={}, projected_rows={}, retained_header_bytes={}, projected_bytes={}, snapshot_elapsed={elapsed:?}",
                snapshot.retained_rows,
                snapshot.considered_rows,
                snapshot.rows.len(),
                ROWS * header_bytes_per_row,
                projected_bytes,
            );
                assert_eq!(snapshot.retained_rows, ROWS);
                assert_eq!(snapshot.considered_rows, ROWS);
                assert_eq!(snapshot.rows.len(), ROWS);
                assert_eq!(snapshot.omitted_rows, 0);
                // Row reasons enter aggregate completeness in build(), while the
                // snapshot's own limits still describe the retained row window.
                assert!(snapshot.stopped_by.is_empty());
                assert!(projected_bytes <= MAX_METADATA_BYTES);
                let result = build(session, snapshot, ROWS, false, None, &[], &[]);
                assert_eq!(result.snapshot.complete, !expected_partial);
                assert_eq!(
                    result
                        .snapshot
                        .stopped_by
                        .contains(&"technology_token_scan_limit".into()),
                    expected_partial
                );
                assert_eq!(result.snapshot.included_rows, ROWS);
                assert_eq!(result.origins[0].request_count, ROWS);
                assert!(result.origins[0]
                    .technology_observations
                    .as_ref()
                    .unwrap()
                    .iter()
                    .all(|observation| observation.row_count == ROWS));
            }
        }
    }
}

#[cfg(test)]
#[path = "service_map_bounded_tests.rs"]
mod bounded_tests;
