//! Opt-in, fixed-destination TCP capture. Read chunks are not protocol messages.
//! Interception is opt-in; read ranges are not application messages. No TLS termination.
mod history_io;
use history_io::HistoryDirectory;

use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    net::{Ipv4Addr, Ipv6Addr},
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{watch, Mutex},
    task::{JoinHandle, JoinSet},
};
use uuid::Uuid;

pub const MAX_CONNECTIONS: usize = 256;
pub const MAX_ACTIVE: usize = 32;
pub const MAX_CAPTURE_BYTES: usize = 1024 * 1024;
pub const MAX_CHUNKS: usize = 4096;
// Base64 of a full capture, chunk metadata, and intercept previews, with room.
const MAX_RECORD_FILE_BYTES: u64 = 6 * 1024 * 1024;
/// Saved records a search may read, in bytes of record files.
pub const SEARCH_READ_BUDGET: u64 = 64 * 1024 * 1024;
// Leave room for crash leftovers without allowing an unbounded directory scan.
const MAX_HISTORY_DIRECTORY_ENTRIES: usize = 4 * MAX_CONNECTIONS;
pub const MAX_PENDING_BYTES: usize = 16 * 1024;
const MAX_EVENT_BYTES: usize = 256 * 1024;
const MAX_EVENTS: usize = 1024;
// A target is a validated 253-byte host plus a colon and a five-digit port.
const MAX_TARGET_BYTES: usize = 259;
const MAX_PEER_BYTES: usize = 128;
const MAX_STATUS_BYTES: usize = 16;
const MAX_CHUNK_BASE64_BYTES: usize = 4 * MAX_CAPTURE_BYTES.div_ceil(3);
const MAX_EVENT_BASE64_BYTES: usize = 4 * MAX_PENDING_BYTES.div_ceil(3);

fn bounded_string<'de, D: serde::Deserializer<'de>, const LIMIT: usize>(
    deserializer: D,
) -> Result<String, D::Error> {
    struct Visitor<const LIMIT: usize>;
    impl<'de, const LIMIT: usize> serde::de::Visitor<'de> for Visitor<LIMIT> {
        type Value = String;
        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(formatter, "a string no longer than {LIMIT} bytes")
        }
        fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<String, E> {
            if value.len() > LIMIT {
                return Err(E::custom("TCP history string limit exceeded"));
            }
            Ok(value.to_owned())
        }
        fn visit_string<E: serde::de::Error>(self, value: String) -> Result<String, E> {
            if value.len() > LIMIT {
                return Err(E::custom("TCP history string limit exceeded"));
            }
            Ok(value)
        }
    }
    deserializer.deserialize_string(Visitor::<LIMIT>)
}

fn bounded_optional_string<'de, D: serde::Deserializer<'de>, const LIMIT: usize>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    struct Visitor<const LIMIT: usize>;
    impl<'de, const LIMIT: usize> serde::de::Visitor<'de> for Visitor<LIMIT> {
        type Value = Option<String>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("an optional bounded string")
        }
        fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_some<D: serde::Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
            bounded_string::<D, LIMIT>(d).map(Some)
        }
    }
    deserializer.deserialize_option(Visitor::<LIMIT>)
}

fn bounded_vec<'de, D, T, const LIMIT: usize>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Visitor<T, const LIMIT: usize>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>, const LIMIT: usize> serde::de::Visitor<'de> for Visitor<T, LIMIT> {
        type Value = Vec<T>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(formatter, "no more than {LIMIT} TCP history entries")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> Result<Self::Value, A::Error> {
            let mut entries = Vec::new();
            while entries.len() < LIMIT {
                match seq.next_element()? {
                    Some(entry) => entries.push(entry),
                    None => return Ok(entries),
                }
            }
            if seq.next_element::<serde::de::IgnoredAny>()?.is_some() {
                return Err(serde::de::Error::custom("TCP history entry limit exceeded"));
            }
            Ok(entries)
        }
    }
    deserializer.deserialize_seq(Visitor::<T, LIMIT>(std::marker::PhantomData))
}
/// Shared by one Session listing request, including all inactive sessions.
pub const SUMMARY_READ_BUDGET: u64 = 32 * 1024 * 1024;
const SUMMARY_CACHE_ENTRIES: usize = 4096;
const SUMMARY_DIRECTORY_CACHE_ENTRIES: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq)]
struct SummaryFingerprint {
    bytes: u64,
    modified: std::time::SystemTime,
    created: Option<std::time::SystemTime>,
    #[cfg(unix)]
    identity: (u64, u64, i64, i64),
}
impl SummaryFingerprint {
    fn read(metadata: &std::fs::Metadata) -> Option<Self> {
        if !metadata.is_file() {
            return None;
        }
        Some(Self {
            bytes: metadata.len(),
            modified: metadata.modified().ok()?,
            created: metadata.created().ok(),
            #[cfg(unix)]
            identity: {
                use std::os::unix::fs::MetadataExt;
                (
                    metadata.dev(),
                    metadata.ino(),
                    metadata.ctime(),
                    metadata.ctime_nsec(),
                )
            },
        })
    }
}
#[derive(Default)]
struct SummaryCache {
    clock: u64,
    files: BTreeMap<PathBuf, (SummaryFingerprint, bool, u64)>,
    directories: BTreeMap<PathBuf, (Vec<(PathBuf, SummaryFingerprint)>, usize, u64)>,
}

// write_json replaces the .json extension with .tmp-<UUID> before rename.
// Only its exact canonical UUID spelling is reserved; arbitrary non-JSON files
// still indicate a history problem. Callers must also reject non-regular files.
fn is_history_temporary_path(path: &std::path::Path) -> bool {
    let canonical_uuid =
        |value: &str| Uuid::parse_str(value).is_ok_and(|id| id.to_string() == value);
    path.file_stem()
        .and_then(|value| value.to_str())
        .is_some_and(canonical_uuid)
        && path
            .extension()
            .and_then(|value| value.to_str())
            .and_then(|value| value.strip_prefix("tmp-"))
            .is_some_and(canonical_uuid)
}

/// Count record envelopes without allocating previews. None is unknown, not empty.
/// Completed counts have a separate bounded cache so file-cache churn does not
/// immediately make an already summarized directory unknown again.
/// Payload semantics remain the full loader's responsibility when a session opens.
pub fn stored_connection_count(directory: &std::path::Path, budget: &mut u64) -> Option<usize> {
    static CACHE: std::sync::OnceLock<std::sync::Mutex<SummaryCache>> = std::sync::OnceLock::new();
    let mut cache = CACHE.get_or_init(Default::default).lock().ok()?;
    stored_connection_count_cached(directory, budget, &mut cache, SUMMARY_CACHE_ENTRIES)
}

fn stored_connection_count_cached(
    directory: &std::path::Path,
    budget: &mut u64,
    cache: &mut SummaryCache,
    file_capacity: usize,
) -> Option<usize> {
    #[derive(Deserialize)]
    struct Header {
        id: Uuid,
        started_at: DateTime<Utc>,
        #[serde(deserialize_with = "bounded_string::<_, MAX_STATUS_BYTES>")]
        status: String,
        #[serde(
            default,
            deserialize_with = "bounded_optional_string::<_, MAX_PEER_BYTES>"
        )]
        peer: Option<String>,
        #[serde(
            default,
            deserialize_with = "bounded_optional_string::<_, MAX_TARGET_BYTES>"
        )]
        target: Option<String>,
    }
    let root = match HistoryDirectory::open(directory) {
        Ok(root) => root,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Some(0),
        Err(_) => return None,
    };
    let mut entries = Vec::new();
    for (index, entry) in root
        .entries()
        .ok()?
        .take(MAX_HISTORY_DIRECTORY_ENTRIES + 1)
        .enumerate()
    {
        if index == MAX_HISTORY_DIRECTORY_ENTRIES {
            return None;
        }
        let path = entry.ok()?.path();
        if is_history_temporary_path(&path) {
            if !root.is_regular_entry(path.file_name()?).ok()? {
                return None;
            }
            continue;
        }
        let file = root.open_file(path.file_name()?).ok()?;
        let fingerprint = SummaryFingerprint::read(&file.metadata().ok()?)?;
        if entries.len() == MAX_CONNECTIONS
            || path.extension().and_then(|value| value.to_str()) != Some("json")
            || fingerprint.bytes > MAX_RECORD_FILE_BYTES
        {
            return None;
        }
        entries.push((path, fingerprint));
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    cache.clock = cache.clock.saturating_add(1);
    let clock = cache.clock;
    // On platforms without change-time/file identity, do not reuse content
    // validation solely from size/mtime: replacing a file could preserve both.
    #[cfg(unix)]
    if let Some((signature, count, touched)) = cache.directories.get_mut(directory) {
        if *signature == entries {
            *touched = clock;
            root.check_current().ok()?;
            return Some(*count);
        }
    }
    cache.directories.remove(directory);
    let mut complete = true;
    for (path, fingerprint) in &entries {
        #[cfg(unix)]
        if let Some((saved, valid, touched)) = cache.files.get_mut(path) {
            if saved == fingerprint {
                *touched = clock;
                if !*valid {
                    return None;
                }
                continue;
            }
        }
        if fingerprint.bytes > *budget {
            complete = false;
            continue;
        }
        *budget -= fingerprint.bytes;
        let file = root.open_file(path.file_name()?).ok()?;
        if SummaryFingerprint::read(&file.metadata().ok()?)?.ne(fingerprint) {
            return None;
        }
        // IgnoredAny streams base64 strings without materializing TcpChunks.
        // Limit to stat size so a concurrently growing file cannot exceed budget.
        let reader = std::io::Read::take(file, fingerprint.bytes);
        let header: Result<Header, _> = serde_json::from_reader(std::io::BufReader::new(reader));
        let valid = header.is_ok_and(|header| {
            let _ = (header.started_at, header.peer, header.target);
            path.file_stem().and_then(|value| value.to_str())
                == Some(header.id.to_string().as_str())
                && [
                    "connecting",
                    "open",
                    "closed",
                    "failed",
                    "stopped",
                    "interrupted",
                ]
                .contains(&header.status.as_str())
        });
        if SummaryFingerprint::read(&root.open_file(path.file_name()?).ok()?.metadata().ok()?)?
            .ne(fingerprint)
        {
            return None;
        }
        if cache.files.len() >= file_capacity && !cache.files.contains_key(path) {
            if let Some(oldest) = cache
                .files
                .iter()
                .min_by_key(|(_, entry)| entry.2)
                .map(|(path, _)| path.clone())
            {
                cache.files.remove(&oldest);
            }
        }
        cache
            .files
            .insert(path.clone(), (fingerprint.clone(), valid, clock));
        if !valid {
            return None;
        }
    }
    if !complete {
        return None;
    }
    if cache.directories.len() >= SUMMARY_DIRECTORY_CACHE_ENTRIES {
        if let Some(oldest) = cache
            .directories
            .iter()
            .min_by_key(|(_, entry)| entry.2)
            .map(|(path, _)| path.clone())
        {
            cache.directories.remove(&oldest);
        }
    }
    root.check_current().ok()?;
    let count = entries.len();
    cache
        .directories
        .insert(directory.to_path_buf(), (entries, count, clock));
    Some(count)
}

fn event_schema_version() -> u8 {
    1
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDirection {
    Both,
    ClientToServer,
    ServerToClient,
}
#[derive(Clone, Debug, Serialize)]
pub struct InterceptPolicy {
    pub enabled: bool,
    pub direction: PolicyDirection,
    pub revision: u64,
    /// All unresolved ranges, including approved ranges still forwarding.
    pub pending_count: usize,
    pub paused_count: usize,
    pub forwarding_count: usize,
    /// Only reads that match are held. A match across two reads is not found:
    /// reads are not messages.
    pub filter: Option<InterceptFilter>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyUpdate {
    pub enabled: bool,
    pub direction: PolicyDirection,
    pub expected_revision: u64,
    #[serde(default)]
    pub filter: Option<InterceptFilter>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InterceptFilter {
    pub kind: FilterKind,
    pub value: String,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FilterKind {
    Text,
    Hex,
    Regex,
}
pub enum Matcher {
    Bytes(Vec<u8>),
    Pattern(regex::bytes::Regex),
}
impl Matcher {
    pub fn compile(filter: &InterceptFilter) -> Result<Self, InterceptError> {
        let bad = |message: &str| InterceptError::BadRequest(message.into());
        if filter.value.is_empty() || filter.value.len() > 1024 {
            return Err(bad("A pattern is 1 to 1024 characters."));
        }
        Ok(match filter.kind {
            FilterKind::Text => Self::Bytes(filter.value.as_bytes().to_vec()),
            FilterKind::Hex => {
                let compact: Vec<u8> = filter
                    .value
                    .bytes()
                    .filter(|byte| !byte.is_ascii_whitespace())
                    .collect();
                if compact.len() % 2 != 0 || !compact.iter().all(u8::is_ascii_hexdigit) {
                    return Err(bad("Enter whole hex byte pairs."));
                }
                Self::Bytes(
                    compact
                        .chunks(2)
                        .map(|pair| {
                            u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap()
                        })
                        .collect(),
                )
            }
            FilterKind::Regex => Self::Pattern(
                regex::bytes::RegexBuilder::new(&filter.value)
                    .size_limit(1 << 20)
                    .build()
                    .map_err(|_| bad("The pattern is not a valid regular expression."))?,
            ),
        })
    }
    fn matches(&self, bytes: &[u8]) -> bool {
        match self {
            Self::Bytes(needle) => bytes.windows(needle.len()).any(|window| window == needle),
            Self::Pattern(pattern) => pattern.is_match(bytes),
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionAction {
    Forward,
    Drop,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionRequest {
    pub action: DecisionAction,
    pub replacement_base64: Option<String>,
    pub expected_revision: u64,
}
#[derive(Clone, Debug, Serialize)]
pub struct DecisionReceipt {
    pub pending_id: Uuid,
    pub state: String,
}
#[derive(Debug)]
pub enum InterceptError {
    BadRequest(String),
    Conflict(String),
    NotFound(String),
    TooLarge(String),
}
impl std::fmt::Display for InterceptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadRequest(s) | Self::Conflict(s) | Self::NotFound(s) | Self::TooLarge(s) => {
                f.write_str(s)
            }
        }
    }
}
impl std::error::Error for InterceptError {}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InterceptEvent {
    pub pending_id: Uuid,
    pub direction: Direction,
    pub sequence: u64,
    pub revision: u64,
    pub received_at: DateTime<Utc>,
    pub decided_at: Option<DateTime<Utc>>,
    pub ended_at: Option<DateTime<Utc>>,
    pub original_offset: u64,
    pub destination_offset: u64,
    pub original_length: usize,
    #[serde(
        default,
        deserialize_with = "bounded_optional_string::<_, MAX_EVENT_BASE64_BYTES>"
    )]
    pub original_base64: Option<String>,
    pub selected_length: usize,
    pub edited: bool,
    #[serde(
        default,
        deserialize_with = "bounded_optional_string::<_, MAX_EVENT_BASE64_BYTES>"
    )]
    pub selected_base64: Option<String>,
    pub written_bytes: usize,
    #[serde(deserialize_with = "bounded_string::<_, MAX_STATUS_BYTES>")]
    pub state: String,
    pub preview_truncated: bool,
}
#[derive(Clone, Debug, Serialize)]
pub struct PendingResponse {
    pub connection_id: Uuid,
    pub items: Vec<InterceptEvent>,
}
struct SubmittedDecision {
    request: DecisionRequest,
    selected: Option<Vec<u8>>,
    ack: tokio::sync::oneshot::Sender<Result<DecisionReceipt, InterceptError>>,
}
struct PendingRange {
    connection_id: Uuid,
    event: InterceptEvent,
    original: Vec<u8>,
    selected: Option<Arc<[u8]>>,
    sender: tokio::sync::mpsc::Sender<SubmittedDecision>,
}
struct InterceptRuntime {
    policy: InterceptPolicy,
    matcher: Option<Matcher>,
    pending: BTreeMap<Uuid, PendingRange>,
    connections: BTreeMap<Uuid, watch::Sender<bool>>,
}
impl InterceptRuntime {
    fn policy_snapshot(&self) -> InterceptPolicy {
        let mut policy = self.policy.clone();
        policy.pending_count = self.pending.len();
        policy.paused_count = self
            .pending
            .values()
            .filter(|p| p.event.state == "pending")
            .count();
        policy.forwarding_count = self
            .pending
            .values()
            .filter(|p| p.event.state == "forwarding")
            .count();
        policy
    }
}

impl Default for InterceptRuntime {
    fn default() -> Self {
        Self {
            policy: InterceptPolicy {
                enabled: false,
                direction: PolicyDirection::Both,
                revision: 0,
                pending_count: 0,
                paused_count: 0,
                forwarding_count: 0,
                filter: None,
            },
            matcher: None,
            pending: BTreeMap::new(),
            connections: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TcpSettings {
    pub local_port: u16,
    pub target_host: String,
    pub target_port: u16,
    /// Left out when off, so a plain listener reads the same to an older Sniper.
    #[serde(default, skip_serializing_if = "TlsMode::is_off")]
    pub tls: TlsMode,
    /// Other devices may connect, from the addresses in `allowed_clients`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub remote: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_clients: Vec<String>,
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// An address or network: `192.0.2.7`, `192.0.2.0/24`, `2001:db8::/32`.
fn parse_network(entry: &str) -> Option<(std::net::IpAddr, u8)> {
    let entry = entry.trim();
    let (address, prefix) = match entry.split_once('/') {
        Some((address, prefix)) => (address, Some(prefix.parse::<u8>().ok()?)),
        None => (entry, None),
    };
    let ip = address.parse::<std::net::IpAddr>().ok()?.to_canonical();
    let bits = if ip.is_ipv4() { 32 } else { 128 };
    let prefix = prefix.unwrap_or(bits);
    (prefix <= bits).then_some((ip, prefix))
}

fn in_network(ip: std::net::IpAddr, network: std::net::IpAddr, prefix: u8) -> bool {
    use std::net::IpAddr::{V4, V6};
    match (ip, network) {
        (V4(ip), V4(network)) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
            u32::from(ip) & mask == u32::from(network) & mask
        }
        (V6(ip), V6(network)) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
            u128::from(ip) & mask == u128::from(network) & mask
        }
        _ => false,
    }
}

/// This machine, or a listed device. IPv4 arrives v4-mapped on a dual-stack socket.
fn client_allowed(peer: std::net::IpAddr, allowed: &[String]) -> bool {
    let peer = peer.to_canonical();
    peer.is_loopback()
        || allowed
            .iter()
            .filter_map(|entry| parse_network(entry))
            .any(|(network, prefix)| in_network(peer, network, prefix))
}

/// Whether any of `addresses` is one of Sniper's own guarded listeners.
fn reaches_guarded(addresses: &[std::net::SocketAddr], guarded: &[std::net::SocketAddr]) -> bool {
    addresses.iter().any(|address| {
        guarded.iter().any(|listener| {
            address.port() == listener.port()
                && crate::proxy::ip_belongs_to_this_machine(
                    address.ip().to_canonical(),
                    listener.ip(),
                )
        })
    })
}

/// Every interface, IPv6 and IPv4 on one socket.
fn bind_every_interface(port: u16) -> std::io::Result<TcpListener> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    socket.set_only_v6(false)?;
    #[cfg(unix)]
    socket.set_reuse_address(true)?;
    socket.bind(&std::net::SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)).into())?;
    socket.listen(1024)?;
    socket.set_nonblocking(true)?;
    TcpListener::from_std(socket.into())
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TlsMode {
    /// Bytes are relayed as they are.
    #[default]
    Off,
    /// A client that starts TLS is answered with a certificate from Sniper's CA
    /// and the target is reached over TLS; both sides are captured in plain
    /// text. A client that does not start TLS, or a server that speaks first,
    /// is relayed as it is.
    Decrypt,
    /// The client speaks plain text and Sniper adds TLS towards the target.
    Upstream,
}

impl TlsMode {
    fn is_off(&self) -> bool {
        *self == Self::Off
    }
}

pub const MAX_LISTENERS: usize = 16;
pub const UNKNOWN_LISTENER: &str = "unknown TCP listener";

/// A listener the session keeps. One that is on starts again when its session
/// is opened, as the proxy listener does.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TcpListenerConfig {
    pub id: Uuid,
    pub enabled: bool,
    pub settings: TcpSettings,
}

/// What adding or changing a listener takes.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TcpListenerInput {
    pub enabled: bool,
    pub settings: TcpSettings,
}

/// Where a recorded connection came from.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TcpSource {
    /// A client of one of the session's listeners.
    #[default]
    Listener,
    /// Sent by TCP Replay.
    Replay,
    #[serde(other)]
    Unknown,
}

impl TcpSource {
    fn is_listener(&self) -> bool {
        *self == Self::Listener
    }
}

pub const MAX_REPLAY_MESSAGES: usize = 64;
/// However much the target keeps talking, a replay ends after this.
const REPLAY_LIMIT: Duration = Duration::from_secs(120);

/// `POST /api/tcp/replay`: messages to send, one at a time, to a target.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayRequest {
    pub target_host: String,
    pub target_port: u16,
    #[serde(default)]
    pub tls: bool,
    /// Each message as standard base64.
    pub messages: Vec<String>,
    /// How long the target may stay silent before the next message goes.
    #[serde(default = "default_replay_wait")]
    pub wait_ms: u64,
    #[serde(default)]
    pub from: Option<Uuid>,
}

fn default_replay_wait() -> u64 {
    1000
}

pub enum ListenerChange {
    Add(TcpListenerInput),
    Update(Uuid, TcpListenerInput),
    Remove(Uuid),
    /// `POST /api/tcp/start`: turns on the listener on this port, or adds one.
    Start(TcpSettings),
    /// `POST /api/tcp/stop`: turns every listener off.
    StopAll,
}

impl ListenerChange {
    pub fn starts(&self) -> bool {
        match self {
            Self::Add(input) | Self::Update(_, input) => input.enabled,
            Self::Start(_) => true,
            Self::Remove(_) | Self::StopAll => false,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct TcpListenerStatus {
    #[serde(flatten)]
    pub config: TcpListenerConfig,
    pub running: bool,
    /// Clients refused because they are not on the listener's list.
    pub refused: u64,
    /// Why a listener that is on is not running, such as a port in use.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}
impl TcpSettings {
    fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.local_port != 0 && self.target_port != 0,
            "ports must be 1–65535"
        );
        anyhow::ensure!(
            !self.target_host.is_empty()
                && self.target_host.len() <= 253
                && !self
                    .target_host
                    .chars()
                    .any(|c| c.is_whitespace() || c.is_control() || "/?#@".contains(c)),
            "invalid target host"
        );
        self.normalized_host()?;
        if self.remote {
            anyhow::ensure!(
                !self.allowed_clients.is_empty(),
                "Name the devices that may connect: IP addresses or networks such as 192.0.2.0/24."
            );
            anyhow::ensure!(
                self.allowed_clients.len() <= 32
                    && self
                        .allowed_clients
                        .iter()
                        .all(|entry| entry.len() <= 64 && parse_network(entry).is_some()),
                "Each device is an IP address or a network such as 192.0.2.0/24, at most 32 of them."
            );
        }
        Ok(())
    }
    fn normalized_host(&self) -> anyhow::Result<String> {
        let host = self.target_host.as_str();
        if host.contains([':', '[', ']']) {
            let address = host
                .strip_prefix('[')
                .and_then(|s| s.strip_suffix(']'))
                .unwrap_or(host);
            let ip = address.parse::<Ipv6Addr>().map_err(|_| {
                anyhow::anyhow!(
                    "Enter a hostname or IP address without a port; use Target port separately."
                )
            })?;
            return Ok(ip.to_string());
        }
        Ok(host.to_owned())
    }
    fn target_label(&self) -> String {
        if self.target_host.contains(':') {
            format!("[{}]:{}", self.target_host, self.target_port)
        } else {
            format!("{}:{}", self.target_host, self.target_port)
        }
    }
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    ClientToServer,
    ServerToClient,
}
fn direction_index(direction: Direction) -> usize {
    match direction {
        Direction::ClientToServer => 0,
        Direction::ServerToClient => 1,
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TcpChunk {
    pub sequence: usize,
    pub at: DateTime<Utc>,
    pub direction: Direction,
    pub offset: u64,
    #[serde(deserialize_with = "bounded_string::<_, MAX_CHUNK_BASE64_BYTES>")]
    pub data_base64: String,
}
/// Persist codes only: OS errors can contain private hostnames or resolver details.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TcpFailure {
    ResolutionTimeout,
    ResolutionFailed,
    ConnectTimeout,
    ConnectionRefused,
    ConnectFailed,
    SelfTarget,
    RelayFailed,
    StorageFailed,
    ProxyFailed,
    TlsFailed,
    /// A client on another device aimed at Sniper's own UI, proxy or a browser
    /// it drives, which trust connections from this machine.
    GuardedTarget,
    #[serde(other)]
    Unknown,
}
async fn connection_stage<T>(
    future: impl std::future::Future<Output = std::io::Result<T>>,
    budget: Duration,
    resolving: bool,
) -> Result<T, TcpFailure> {
    match tokio::time::timeout(budget, future).await {
        Err(_) => Err(if resolving {
            TcpFailure::ResolutionTimeout
        } else {
            TcpFailure::ConnectTimeout
        }),
        Ok(Err(error)) => Err(if error.kind() == std::io::ErrorKind::TimedOut {
            if resolving {
                TcpFailure::ResolutionTimeout
            } else {
                TcpFailure::ConnectTimeout
            }
        } else if resolving {
            TcpFailure::ResolutionFailed
        } else if error.kind() == std::io::ErrorKind::ConnectionRefused {
            TcpFailure::ConnectionRefused
        } else {
            TcpFailure::ConnectFailed
        }),
        Ok(Ok(value)) => Ok(value),
    }
}
async fn connection_outcome(
    future: impl std::future::Future<Output = Result<(), TcpFailure>>,
    stop: &mut watch::Receiver<bool>,
    closed: &mut watch::Receiver<bool>,
) -> (&'static str, Option<TcpFailure>) {
    tokio::select! {
        biased;
        _ = wait_stop(stop) => ("stopped", None),
        _ = wait_stop(closed) => ("stopped", None),
        result = future => match result {
            Ok(()) => ("closed", None),
            Err(failure) => ("failed", Some(failure)),
        },
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TcpConnection {
    pub id: Uuid,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    #[serde(deserialize_with = "bounded_string::<_, MAX_PEER_BYTES>")]
    pub peer: String,
    #[serde(deserialize_with = "bounded_string::<_, MAX_TARGET_BYTES>")]
    pub target: String,
    /// The listener's port; 0 in records saved before there could be several.
    #[serde(default)]
    pub local_port: u16,
    /// Opened through the session's upstream proxy.
    #[serde(default)]
    pub via_proxy: bool,
    /// The client's TLS was decrypted with a certificate from Sniper's CA.
    #[serde(default)]
    pub client_tls: bool,
    /// The target was reached over TLS.
    #[serde(default)]
    pub server_tls: bool,
    #[serde(default, skip_serializing_if = "TcpSource::is_listener")]
    pub source: TcpSource,
    /// The connection a replay was made from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replayed_from: Option<Uuid>,
    #[serde(deserialize_with = "bounded_string::<_, MAX_STATUS_BYTES>")]
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure: Option<TcpFailure>,
    pub client_bytes: u64,
    pub server_bytes: u64,
    pub captured_bytes: usize,
    pub capture_truncated: bool,
    /// True only after a terminal record was atomically persisted.
    pub durable: bool,
    #[serde(deserialize_with = "bounded_vec::<_, _, MAX_CHUNKS>")]
    pub chunks: Vec<TcpChunk>,
    #[serde(default)]
    pub client_received_bytes: u64,
    #[serde(default)]
    pub server_received_bytes: u64,
    #[serde(default, deserialize_with = "bounded_vec::<_, _, MAX_EVENTS>")]
    pub intercept_events: Vec<InterceptEvent>,
    #[serde(default)]
    pub intercept_captured_bytes: usize,
    #[serde(default)]
    pub intercept_truncated: bool,
    #[serde(default)]
    pub intercept_event_count: u64,
    #[serde(default = "event_schema_version")]
    pub intercept_schema_version: u8,
    #[serde(default)]
    pub pending_count: usize,
    #[serde(default, deserialize_with = "bounded_vec::<_, _, 2>")]
    pub pending_directions: Vec<Direction>,
}
impl TcpConnection {
    fn release_durable_payload(&mut self) {
        // Live, interrupted and failed-to-persist captures may exist only here.
        // Release capacity as well as contents, and never write this summary to disk.
        if self.durable && self.ended_at.is_some() {
            self.chunks = Vec::new();
            self.intercept_events = Vec::new();
        }
    }
}
/// Validate one record at a time; payloads never remain in the session cache.
fn read_stored_connection(path: &std::path::Path) -> anyhow::Result<TcpConnection> {
    let directory = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("missing history directory"))?;
    let root = HistoryDirectory::open(directory)?;
    read_stored_connection_in(&root, path)
}

fn read_stored_connection_in(
    root: &HistoryDirectory,
    path: &std::path::Path,
) -> anyhow::Result<TcpConnection> {
    let name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("missing history filename"))?;
    let file = root.open_file(name)?;
    let fingerprint = SummaryFingerprint::read(&file.metadata()?)
        .ok_or_else(|| anyhow::anyhow!("unexpected history entry"))?;
    anyhow::ensure!(
        fingerprint.bytes <= MAX_RECORD_FILE_BYTES,
        "history record too large"
    );
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(
        &mut std::io::Read::take(file, MAX_RECORD_FILE_BYTES + 1),
        &mut bytes,
    )?;
    anyhow::ensure!(
        bytes.len() as u64 <= MAX_RECORD_FILE_BYTES,
        "history record too large"
    );
    anyhow::ensure!(
        SummaryFingerprint::read(&root.open_file(name)?.metadata()?).as_ref() == Some(&fingerprint),
        "history record changed while reading"
    );
    root.check_current()?;
    let mut record: TcpConnection = serde_json::from_slice(&bytes)?;
    anyhow::ensure!(
        path.file_stem().and_then(|s| s.to_str()) == Some(record.id.to_string().as_str()),
        "history id mismatch"
    );
    anyhow::ensure!(
        [
            "connecting",
            "open",
            "closed",
            "failed",
            "stopped",
            "interrupted"
        ]
        .contains(&record.status.as_str()),
        "invalid history status"
    );
    let terminal = ["closed", "failed", "stopped"].contains(&record.status.as_str());
    anyhow::ensure!(
        terminal == record.ended_at.is_some()
            && (!record.durable || terminal)
            && (record.failure.is_none() || record.status == "failed"),
        "inconsistent history lifecycle"
    );
    anyhow::ensure!(
        !record.peer.is_empty()
            && !record.target.is_empty()
            && !record
                .peer
                .chars()
                .chain(record.target.chars())
                .any(|c| c.is_whitespace() || c.is_control())
            && record.pending_count <= 2
            && record.pending_count == record.pending_directions.len()
            && (record.pending_directions.len() < 2
                || record.pending_directions[0] != record.pending_directions[1]),
        "invalid history metadata"
    );
    anyhow::ensure!(
        record.chunks.len() <= MAX_CHUNKS && record.captured_bytes <= MAX_CAPTURE_BYTES,
        "history limits exceeded"
    );
    let mut total = 0;
    let mut captured = [0u64; 2];
    for (sequence, chunk) in record.chunks.iter().enumerate() {
        anyhow::ensure!(
            chunk.data_base64.len() <= 4 * MAX_CAPTURE_BYTES.div_ceil(3),
            "oversized chunk"
        );
        let length = STANDARD.decode(&chunk.data_base64)?.len();
        let direction = direction_index(chunk.direction);
        anyhow::ensure!(
            length != 0 && chunk.sequence == sequence && chunk.offset == captured[direction],
            "invalid history chunk sequence or offset"
        );
        captured[direction] = captured[direction]
            .checked_add(length as u64)
            .ok_or_else(|| anyhow::anyhow!("history offset overflow"))?;
        total += length;
        anyhow::ensure!(total <= MAX_CAPTURE_BYTES, "oversized capture");
    }
    anyhow::ensure!(
        total == record.captured_bytes,
        "history byte count mismatch"
    );
    for (captured, forwarded) in captured
        .into_iter()
        .zip([record.client_bytes, record.server_bytes])
    {
        anyhow::ensure!(
            captured <= forwarded && (record.capture_truncated || captured == forwarded),
            "history forwarded byte count mismatch"
        );
    }
    anyhow::ensure!(
        record.intercept_events.len() <= MAX_EVENTS
            && record.intercept_captured_bytes <= MAX_EVENT_BYTES,
        "intercept history limits exceeded"
    );
    anyhow::ensure!(
        record.intercept_schema_version == 1
            && record.intercept_event_count >= record.intercept_events.len() as u64
            && (record.intercept_truncated
                || record.intercept_event_count == record.intercept_events.len() as u64)
            && u128::from(record.intercept_event_count)
                <= u128::from(record.client_received_bytes)
                    + u128::from(record.server_received_bytes),
        "unsupported or corrupt intercept schema"
    );
    let mut event_bytes = 0;
    let mut sequences = std::collections::BTreeSet::new();
    let mut pending_ids = std::collections::BTreeSet::new();
    for event in &record.intercept_events {
        let direction = direction_index(event.direction);
        let received = [record.client_received_bytes, record.server_received_bytes][direction];
        let forwarded = [record.client_bytes, record.server_bytes][direction];
        anyhow::ensure!(
            event.sequence < record.intercept_event_count
                && sequences.insert(event.sequence)
                && pending_ids.insert(event.pending_id)
                && event
                    .original_offset
                    .checked_add(event.original_length as u64)
                    .is_some_and(|end| end <= received)
                && event
                    .destination_offset
                    .checked_add(event.written_bytes as u64)
                    .is_some_and(|end| end <= forwarded),
            "invalid intercept sequence or offset"
        );
        anyhow::ensure!(
            event.ended_at.is_some()
                && event.revision == if event.decided_at.is_some() { 2 } else { 1 }
                && (!["forwarded", "dropped"].contains(&event.state.as_str())
                    || event.decided_at.is_some()),
            "invalid intercept lifecycle"
        );
        anyhow::ensure!(
            event.original_length > 0
                && event.original_length <= MAX_PENDING_BYTES
                && event.selected_length <= MAX_PENDING_BYTES
                && event.written_bytes <= event.selected_length,
            "invalid intercept lengths"
        );
        anyhow::ensure!(
            ["forwarded", "dropped", "cancelled", "failed"].contains(&event.state.as_str()),
            "invalid terminal intercept outcome"
        );
        anyhow::ensure!(
            event.state != "forwarded" || event.written_bytes == event.selected_length,
            "incomplete forwarded event"
        );
        anyhow::ensure!(
            event.state != "dropped" || (event.written_bytes == 0 && event.selected_length == 0),
            "invalid dropped event"
        );
        anyhow::ensure!(
            (event.edited || event.selected_base64.is_none())
                && (event.edited
                    || event.state == "dropped"
                    || event.selected_length == event.original_length),
            "invalid selected intercept range"
        );
        anyhow::ensure!(
            !event.edited || event.preview_truncated || event.selected_base64.is_some(),
            "missing edited preview"
        );
        for (encoded, length) in [
            (&event.original_base64, event.original_length),
            (&event.selected_base64, event.selected_length),
        ] {
            if let Some(encoded) = encoded {
                anyhow::ensure!(
                    encoded.len() <= 4 * MAX_PENDING_BYTES.div_ceil(3),
                    "oversized intercept field"
                );
                let decoded = STANDARD.decode(encoded)?;
                anyhow::ensure!(decoded.len() == length, "intercept byte count mismatch");
                event_bytes += decoded.len();
                anyhow::ensure!(
                    event_bytes <= MAX_EVENT_BYTES,
                    "oversized intercept history"
                );
            }
        }
        anyhow::ensure!(
            event.preview_truncated || event.original_base64.is_some(),
            "missing original preview"
        );
    }
    let mut ordered: Vec<_> = record.intercept_events.iter().collect();
    ordered.sort_by_key(|event| event.sequence);
    let mut original_ends = [0u64; 2];
    let mut destination_ends = [0u64; 2];
    for event in ordered {
        let direction = direction_index(event.direction);
        anyhow::ensure!(
            event.original_offset >= original_ends[direction]
                && event.destination_offset >= destination_ends[direction],
            "overlapping intercept ranges"
        );
        // Both additions were checked above before retaining any metadata.
        original_ends[direction] = event.original_offset + event.original_length as u64;
        destination_ends[direction] = event.destination_offset + event.written_bytes as u64;
    }
    anyhow::ensure!(
        event_bytes == record.intercept_captured_bytes,
        "intercept capture count mismatch"
    );
    record.pending_count = 0;
    record.pending_directions.clear();
    if record.ended_at.is_none() {
        record.status = "interrupted".into();
        record.failure = None;
        record.intercept_truncated = true;
        record.capture_truncated = true;
        record.durable = false;
    }
    Ok(record)
}

#[derive(Clone, Debug, Serialize)]
pub struct TcpStatus {
    /// Whether any listener is running.
    pub enabled: bool,
    pub listeners: Vec<TcpListenerStatus>,
    pub history_count: usize,
    pub history_limit: usize,
    pub active_count: usize,
    pub active_limit: usize,
    pub load_error: bool,
    pub persistence_error: bool,
    /// Connections relayed but not recorded because the history was full,
    /// since it was last cleared.
    pub unrecorded_count: u64,
}
/// Captures remain owned in memory until an explicit retry saves every record.
#[derive(Debug)]
pub struct TcpPersistenceError {
    pub pending_records: usize,
}
impl std::fmt::Display for TcpPersistenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TCP capture stopped, but {} connection record(s) are not saved. Keep Sniper open, restore storage, then retry saving.", self.pending_records)
    }
}
impl std::error::Error for TcpPersistenceError {}

#[derive(Default)]
struct History {
    records: BTreeMap<Uuid, TcpConnection>,
    load_error: bool,
    persistence_error: bool,
}
struct Running {
    refused: Arc<AtomicU64>,
    stop: watch::Sender<bool>,
    task: JoinHandle<()>,
}
/// What a listener does with a connection it accepted.
enum Admission {
    Refused,
    Unrecorded,
    Recorded(Box<TcpConnection>, watch::Receiver<bool>),
}
pub struct TcpCapture {
    directory: PathBuf,
    history: Arc<std::sync::Mutex<History>>,
    /// The session's listeners, in the order they were added.
    listeners: std::sync::Mutex<Vec<TcpListenerConfig>>,
    /// Running listeners by id. Starting and stopping happen under this lock.
    running: Mutex<BTreeMap<Uuid, Running>>,
    errors: std::sync::Mutex<BTreeMap<Uuid, String>>,
    active_count: AtomicUsize,
    unrecorded: AtomicU64,
    /// The session's settings, for its upstream proxy; absent in unit tests.
    runtime: std::sync::OnceLock<Arc<crate::runtime::RuntimeSettings>>,
    /// Sniper's CA, for listeners that decrypt TLS.
    certificates: std::sync::OnceLock<Arc<crate::certificate::CertificateAuthority>>,
    /// Sniper's UI and proxy listeners, which a remote client must not reach.
    own_addresses: std::sync::Mutex<Vec<std::net::SocketAddr>>,
    intercept: std::sync::Mutex<InterceptRuntime>,
}
impl TcpCapture {
    pub fn policy(&self) -> InterceptPolicy {
        let runtime = self.intercept.lock().unwrap();
        runtime.policy_snapshot()
    }
    pub fn set_policy(&self, update: PolicyUpdate) -> Result<InterceptPolicy, InterceptError> {
        let mut runtime = self.intercept.lock().unwrap();
        if runtime.policy.revision != update.expected_revision {
            return Err(InterceptError::Conflict("intercept policy changed".into()));
        }
        let revision = runtime
            .policy
            .revision
            .checked_add(1)
            .ok_or_else(|| InterceptError::Conflict("policy revision exhausted".into()))?;
        let matcher = update.filter.as_ref().map(Matcher::compile).transpose()?;
        runtime.policy = InterceptPolicy {
            enabled: update.enabled,
            direction: update.direction,
            revision,
            pending_count: 0,
            paused_count: 0,
            forwarding_count: 0,
            filter: update.filter,
        };
        runtime.matcher = matcher;
        Ok(runtime.policy_snapshot())
    }
    /// Turning intercept off lets go of what it held, as HTTP intercept does.
    pub async fn update_policy(
        &self,
        update: PolicyUpdate,
    ) -> Result<InterceptPolicy, InterceptError> {
        let off = !update.enabled;
        self.set_policy(update)?;
        if off {
            self.release_all(DecisionAction::Forward).await;
        }
        Ok(self.policy())
    }
    /// Forwards unchanged, or drops, every read held in this session.
    pub async fn release_all(&self, action: DecisionAction) -> usize {
        let held: Vec<(Uuid, Uuid, u64)> = self
            .intercept
            .lock()
            .unwrap()
            .pending
            .iter()
            .filter(|(_, range)| range.event.state == "pending")
            .map(|(id, range)| (range.connection_id, *id, range.event.revision))
            .collect();
        let mut released = 0;
        for (connection, pending, expected_revision) in held {
            let request = DecisionRequest {
                action,
                replacement_base64: None,
                expected_revision,
            };
            // One that ended or was decided meanwhile is not counted.
            if self.decide(connection, pending, request).await.is_ok() {
                released += 1;
            }
        }
        released
    }
    pub fn pending(&self, id: Uuid) -> Result<PendingResponse, InterceptError> {
        let runtime = self.intercept.lock().unwrap();
        if !self.history.lock().unwrap().records.contains_key(&id) {
            return Err(InterceptError::NotFound("unknown connection".into()));
        }
        let mut items: Vec<_> = runtime
            .pending
            .values()
            .filter(|p| p.connection_id == id)
            .map(|p| {
                let mut event = p.event.clone();
                event.original_base64 = Some(STANDARD.encode(&p.original));
                event.selected_base64 = p.selected.as_ref().map(|bytes| STANDARD.encode(bytes));
                event
            })
            .collect();
        items.sort_by_key(|p| p.sequence);
        Ok(PendingResponse {
            connection_id: id,
            items,
        })
    }
    pub fn close(&self, id: Uuid) -> Result<(), InterceptError> {
        let runtime = self.intercept.lock().unwrap();
        match runtime.connections.get(&id) {
            Some(stop) => {
                let _ = stop.send(true);
                Ok(())
            }
            None => {
                if self.history.lock().unwrap().records.contains_key(&id) {
                    Err(InterceptError::Conflict("connection is closed".into()))
                } else {
                    Err(InterceptError::NotFound("unknown connection".into()))
                }
            }
        }
    }
    pub async fn decide(
        &self,
        id: Uuid,
        pending_id: Uuid,
        request: DecisionRequest,
    ) -> Result<DecisionReceipt, InterceptError> {
        let selected = match (&request.action, &request.replacement_base64) {
            (DecisionAction::Drop, Some(_)) => {
                return Err(InterceptError::BadRequest(
                    "Drop cannot include replacement".into(),
                ))
            }
            (DecisionAction::Forward, Some(encoded)) => {
                if encoded.len() > MAX_PENDING_BYTES.div_ceil(3) * 4 {
                    return Err(InterceptError::TooLarge(
                        "replacement exceeds 16 KiB".into(),
                    ));
                }
                let bytes = STANDARD
                    .decode(encoded)
                    .map_err(|_| InterceptError::BadRequest("invalid standard base64".into()))?;
                if bytes.is_empty() {
                    return Err(InterceptError::BadRequest(
                        "use Drop for an empty replacement".into(),
                    ));
                }
                if bytes.len() > MAX_PENDING_BYTES {
                    return Err(InterceptError::TooLarge(
                        "replacement exceeds 16 KiB".into(),
                    ));
                }
                Some(bytes)
            }
            _ => None,
        };
        let (ack, receiver) = tokio::sync::oneshot::channel();
        {
            let runtime = self.intercept.lock().unwrap();
            if !self.history.lock().unwrap().records.contains_key(&id) {
                return Err(InterceptError::NotFound("unknown connection".into()));
            }
            let pending = runtime
                .pending
                .get(&pending_id)
                .filter(|p| p.connection_id == id)
                .ok_or_else(|| InterceptError::Conflict("range no longer pending".into()))?;
            if pending.event.state != "pending"
                || pending.event.revision != request.expected_revision
            {
                return Err(InterceptError::Conflict("range changed".into()));
            }
            pending
                .sender
                .try_send(SubmittedDecision {
                    request,
                    selected,
                    ack,
                })
                .map_err(|_| {
                    InterceptError::Conflict("decision busy or connection closed".into())
                })?;
        }
        receiver
            .await
            .map_err(|_| InterceptError::Conflict("connection closed before acceptance".into()))?
    }
    fn admit(
        &self,
        id: Uuid,
        direction: Direction,
        bytes: &[u8],
    ) -> Option<(Uuid, tokio::sync::mpsc::Receiver<SubmittedDecision>)> {
        // This lock is the policy/read admission linearization point. Off does not
        // mutate already-admitted ranges. Never hold it across an await.
        let mut runtime = self.intercept.lock().unwrap();
        let mut history = self.history.lock().unwrap();
        let record = history.records.get_mut(&id)?;
        let received = match direction {
            Direction::ClientToServer => &mut record.client_received_bytes,
            Direction::ServerToClient => &mut record.server_received_bytes,
        };
        let original_offset = *received;
        *received += bytes.len() as u64;
        if !runtime.policy.enabled
            || !matches!(
                (runtime.policy.direction, direction),
                (PolicyDirection::Both, _)
                    | (PolicyDirection::ClientToServer, Direction::ClientToServer)
                    | (PolicyDirection::ServerToClient, Direction::ServerToClient)
            )
            || runtime
                .matcher
                .as_ref()
                .is_some_and(|matcher| !matcher.matches(bytes))
        {
            return None;
        }
        let pending_id = Uuid::new_v4();
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        let sequence = record.intercept_event_count;
        record.intercept_event_count += 1;
        let event = InterceptEvent {
            pending_id,
            direction,
            sequence,
            revision: 0,
            received_at: Utc::now(),
            decided_at: None,
            ended_at: None,
            original_offset,
            destination_offset: match direction {
                Direction::ClientToServer => record.client_bytes,
                Direction::ServerToClient => record.server_bytes,
            },
            original_length: bytes.len(),
            original_base64: None,
            selected_length: bytes.len(),
            edited: false,
            selected_base64: None,
            written_bytes: 0,
            state: "pending".into(),
            preview_truncated: false,
        };
        runtime.pending.insert(
            pending_id,
            PendingRange {
                connection_id: id,
                event,
                original: bytes.to_vec(),
                selected: None,
                sender,
            },
        );
        Some((pending_id, receiver))
    }
    fn end_range(&self, pending_id: Uuid, state: &str) {
        let pending = self.intercept.lock().unwrap().pending.remove(&pending_id);
        let Some(mut pending) = pending else {
            return;
        };
        pending.event.state = state.into();
        pending.event.ended_at = Some(Utc::now());
        pending.event.revision += 1;
        let mut history = self.history.lock().unwrap();
        let Some(record) = history.records.get_mut(&pending.connection_id) else {
            return;
        };
        if record.intercept_events.len() >= MAX_EVENTS {
            record.intercept_truncated = true;
            return;
        }
        let size =
            pending.original.len() + pending.selected.as_ref().map_or(0, |bytes| bytes.len());
        if size > MAX_EVENT_BYTES - record.intercept_captured_bytes {
            pending.event.original_base64 = None;
            pending.event.selected_base64 = None;
            pending.event.preview_truncated = true;
            record.intercept_truncated = true;
        } else {
            pending.event.original_base64 = Some(STANDARD.encode(&pending.original));
            pending.event.selected_base64 = pending
                .selected
                .as_ref()
                .map(|bytes| STANDARD.encode(bytes));
            record.intercept_captured_bytes += size;
        }
        record.intercept_events.push(pending.event);
    }

    /// Called during ordinary session loading, not from a proxy runtime task.
    pub fn load(directory: PathBuf) -> Self {
        let mut history = History::default();
        match HistoryDirectory::open(&directory) {
            Ok(root) => {
                if let Ok(entries) = root.entries() {
                    for (index, entry) in
                        entries.take(MAX_HISTORY_DIRECTORY_ENTRIES + 1).enumerate()
                    {
                        if index == MAX_HISTORY_DIRECTORY_ENTRIES {
                            history.load_error = true;
                            break;
                        }
                        let result = (|| -> anyhow::Result<Option<TcpConnection>> {
                            let entry = entry?;
                            let path = entry.path();
                            if is_history_temporary_path(&path) {
                                anyhow::ensure!(
                                    root.is_regular_entry(&entry.file_name())?,
                                    "unexpected history entry"
                                );
                                // A crash before rename never published this version. Keep
                                // the file untouched and trust only the durable .json record.
                                return Ok(None);
                            }
                            anyhow::ensure!(
                                path.extension().and_then(|s| s.to_str()) == Some("json"),
                                "unexpected history file"
                            );
                            read_stored_connection_in(&root, &path).map(Some)
                        })();
                        match result {
                            Ok(Some(mut record)) if history.records.len() < MAX_CONNECTIONS => {
                                record.release_durable_payload();
                                history.records.insert(record.id, record);
                            }
                            Ok(None) => {}
                            _ => {
                                history.load_error = true;
                            }
                        }
                    }
                } else {
                    history.load_error = true;
                }
                if root.check_current().is_err() {
                    history.load_error = true;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {
                history.load_error = true;
            }
        }
        Self {
            directory,
            history: Arc::new(std::sync::Mutex::new(history)),
            listeners: std::sync::Mutex::new(Vec::new()),
            running: Mutex::new(BTreeMap::new()),
            errors: std::sync::Mutex::new(BTreeMap::new()),
            active_count: AtomicUsize::new(0),
            unrecorded: AtomicU64::new(0),
            runtime: std::sync::OnceLock::new(),
            certificates: std::sync::OnceLock::new(),
            own_addresses: std::sync::Mutex::new(Vec::new()),
            intercept: std::sync::Mutex::new(InterceptRuntime::default()),
        }
    }
    pub async fn status(&self) -> TcpStatus {
        let running = self.running.lock().await;
        let errors = self.errors.lock().unwrap().clone();
        let listeners: Vec<_> = self
            .listener_configs()
            .into_iter()
            .map(|config| {
                let alive = running
                    .get(&config.id)
                    .is_some_and(|worker| !worker.task.is_finished());
                TcpListenerStatus {
                    refused: running
                        .get(&config.id)
                        .map_or(0, |worker| worker.refused.load(Ordering::Relaxed)),
                    running: alive,
                    error: (!alive && config.enabled)
                        .then(|| errors.get(&config.id).cloned())
                        .flatten(),
                    config,
                }
            })
            .collect();
        let live = running
            .values()
            .filter(|worker| !worker.task.is_finished())
            .count();
        let history = self.history.lock().unwrap();
        TcpStatus {
            enabled: live > 0,
            listeners,
            history_count: history.records.len(),
            history_limit: MAX_CONNECTIONS,
            active_count: self.active_count.load(Ordering::Relaxed),
            // Each running listener admits its own MAX_ACTIVE.
            active_limit: MAX_ACTIVE * live.max(1),
            load_error: history.load_error,
            persistence_error: history.persistence_error,
            unrecorded_count: self.unrecorded.load(Ordering::Relaxed),
        }
    }
    #[cfg(test)]
    async fn records(&self) -> Vec<TcpConnection> {
        let ids: Vec<_> = self
            .history
            .lock()
            .unwrap()
            .records
            .keys()
            .copied()
            .collect();
        let mut records = Vec::new();
        for id in ids {
            if let Some(record) = self.detail(id).await.expect("read saved TCP test record") {
                records.push(record);
            }
        }
        records.sort_by_key(|r| std::cmp::Reverse(r.started_at));
        records
    }
    pub fn connection_count(&self) -> Option<usize> {
        let history = self.history.lock().unwrap();
        (!history.load_error).then_some(history.records.len())
    }

    pub async fn summaries(&self) -> Vec<TcpConnection> {
        let runtime = self.intercept.lock().unwrap();
        let history = self.history.lock().unwrap();
        let mut records: Vec<_> = history
            .records
            .values()
            .map(|r| TcpConnection {
                id: r.id,
                started_at: r.started_at,
                ended_at: r.ended_at,
                peer: r.peer.clone(),
                target: r.target.clone(),
                local_port: r.local_port,
                via_proxy: r.via_proxy,
                client_tls: r.client_tls,
                server_tls: r.server_tls,
                source: r.source,
                replayed_from: r.replayed_from,
                status: r.status.clone(),
                failure: r.failure,
                client_bytes: r.client_bytes,
                server_bytes: r.server_bytes,
                captured_bytes: r.captured_bytes,
                capture_truncated: r.capture_truncated,
                durable: r.durable,
                chunks: vec![],
                client_received_bytes: r.client_received_bytes,
                server_received_bytes: r.server_received_bytes,
                intercept_events: vec![],
                intercept_captured_bytes: r.intercept_captured_bytes,
                intercept_truncated: r.intercept_truncated,
                intercept_event_count: r.intercept_event_count,
                intercept_schema_version: r.intercept_schema_version,
                pending_count: runtime
                    .pending
                    .values()
                    .filter(|p| p.connection_id == r.id)
                    .count(),
                pending_directions: runtime
                    .pending
                    .values()
                    .filter(|p| p.connection_id == r.id)
                    .map(|p| p.event.direction)
                    .collect(),
            })
            .collect();
        records.sort_by_key(|r| std::cmp::Reverse(r.started_at));
        records
    }
    pub async fn detail(&self, id: Uuid) -> anyhow::Result<Option<TcpConnection>> {
        let record = {
            let runtime = self.intercept.lock().unwrap();
            let history = self.history.lock().unwrap();
            let Some(mut record) = history.records.get(&id).cloned() else {
                return Ok(None);
            };
            record.pending_directions = runtime
                .pending
                .values()
                .filter(|p| p.connection_id == id)
                .map(|p| p.event.direction)
                .collect();
            record.pending_count = record.pending_directions.len();
            record
        };
        if !record.durable || record.ended_at.is_none() {
            return Ok(Some(record));
        }
        let path = self.directory.join(format!("{id}.json"));
        // No retained payload cache: inactive summaries and repeated detail reads
        // cannot accumulate captures across the shared SessionContext caches.
        // Do not hold either runtime lock while waiting for filesystem work.
        let result = tokio::task::spawn_blocking(move || {
            let mut loaded = read_stored_connection(&path)?;
            let chunks = std::mem::take(&mut loaded.chunks);
            let events = std::mem::take(&mut loaded.intercept_events);
            anyhow::ensure!(
                serde_json::to_value(&loaded)? == serde_json::to_value(&record)?,
                "stored TCP record changed"
            );
            loaded.chunks = chunks;
            loaded.intercept_events = events;
            Ok(loaded)
        })
        .await;
        match result {
            Ok(Ok(record)) => Ok(Some(record)),
            _ => {
                self.history.lock().unwrap().load_error = true;
                anyhow::bail!("Saved TCP detail could not be read. History requires recovery.")
            }
        }
    }
    pub async fn apply(self: &Arc<Self>, change: ListenerChange) -> anyhow::Result<()> {
        match change {
            ListenerChange::Add(input) => self.add_listener(input).await.map(drop),
            ListenerChange::Update(id, input) => self.update_listener(id, input).await,
            ListenerChange::Remove(id) => self.remove_listener(id).await,
            ListenerChange::Start(settings) => {
                let port = settings.local_port;
                let input = TcpListenerInput {
                    enabled: true,
                    settings,
                };
                match self
                    .listener_configs()
                    .into_iter()
                    .find(|listener| listener.settings.local_port == port)
                {
                    Some(listener) => self.update_listener(listener.id, input).await,
                    None => self.add_listener(input).await.map(drop),
                }
            }
            ListenerChange::StopAll => {
                for listener in self.listeners.lock().unwrap().iter_mut() {
                    listener.enabled = false;
                }
                Ok(self.stop().await?)
            }
        }
    }
    /// Removes every ended, saved record from memory and disk. Live records and
    /// ones still waiting to be saved stay.
    pub async fn clear(&self) -> anyhow::Result<usize> {
        let removed: Vec<Uuid> = {
            let mut history = self.history.lock().unwrap();
            let ids: Vec<_> = history
                .records
                .values()
                .filter(|record| record.ended_at.is_some() && record.durable)
                .map(|record| record.id)
                .collect();
            for id in &ids {
                history.records.remove(id);
            }
            ids
        };
        self.unrecorded.store(0, Ordering::Relaxed);
        let directory = self.directory.clone();
        let names: Vec<String> = removed.iter().map(|id| format!("{id}.json")).collect();
        let deleted = tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            let root = match HistoryDirectory::open(&directory) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                root => root?,
            };
            for name in names {
                match root.remove_file(std::ffi::OsStr::new(&name)) {
                    Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                        return Err(error)
                    }
                    _ => {}
                }
            }
            Ok(())
        })
        .await;
        if !matches!(deleted, Ok(Ok(()))) {
            // Files left behind would come back at the next load.
            self.history.lock().unwrap().load_error = true;
            anyhow::bail!("Some TCP records could not be deleted. History requires recovery.");
        }
        Ok(removed.len())
    }
    pub fn use_runtime(&self, runtime: Arc<crate::runtime::RuntimeSettings>) {
        let _ = self.runtime.set(runtime);
    }
    pub fn use_own_addresses(&self, addresses: Vec<std::net::SocketAddr>) {
        *self.own_addresses.lock().unwrap() = addresses;
    }
    /// What `client` may not be relayed to: nothing for this machine.
    fn guarded_for(&self, client: &TcpStream) -> Vec<std::net::SocketAddr> {
        match client.peer_addr() {
            Ok(peer) if peer.ip().to_canonical().is_loopback() => Vec::new(),
            _ => self.guarded(),
        }
    }
    /// What a client on another device may not be relayed to.
    fn guarded(&self) -> Vec<std::net::SocketAddr> {
        let mut guarded = self.own_addresses.lock().unwrap().clone();
        guarded.extend(
            crate::browser::driver_ports()
                .into_iter()
                .map(|port| std::net::SocketAddr::from((Ipv4Addr::LOCALHOST, port))),
        );
        guarded
    }
    pub fn use_certificates(&self, certificates: Arc<crate::certificate::CertificateAuthority>) {
        let _ = self.certificates.set(certificates);
    }
    /// Whether the target's certificate goes unchecked, as for HTTP.
    async fn upstream_insecure(&self) -> bool {
        match self.runtime.get() {
            Some(runtime) => runtime.upstream_insecure().await,
            None => true,
        }
    }
    async fn upstream_proxy(&self) -> Option<crate::upstream_proxy::UpstreamProxy> {
        match self.runtime.get() {
            Some(runtime) => Some(runtime.upstream_proxy().await),
            None => None,
        }
    }
    /// The records whose bytes in either direction match, even across reads,
    /// and whether the search stopped early: saved records are read from disk
    /// within `SEARCH_READ_BUDGET`.
    pub async fn search(&self, matcher: &Matcher) -> (Vec<Uuid>, bool) {
        let mut records: Vec<_> = self
            .history
            .lock()
            .unwrap()
            .records
            .values()
            .map(|record| (record.started_at, record.id))
            .collect();
        records.sort_by(|a, b| b.cmp(a));
        let (mut found, mut budget) = (Vec::new(), SEARCH_READ_BUDGET);
        for (_, id) in records {
            let size = tokio::fs::metadata(self.directory.join(format!("{id}.json")))
                .await
                .map_or(0, |metadata| metadata.len());
            if size > budget {
                return (found, true);
            }
            budget -= size;
            let Ok(Some(record)) = self.detail(id).await else {
                continue;
            };
            if [Direction::ClientToServer, Direction::ServerToClient]
                .into_iter()
                .any(|direction| matcher.matches(&stream_of(&record, direction)))
            {
                found.push(id);
            }
        }
        (found, false)
    }
    /// One direction's captured bytes, joined in the order they were read.
    pub async fn raw(&self, id: Uuid, direction: Direction) -> anyhow::Result<Option<Vec<u8>>> {
        Ok(self
            .detail(id)
            .await?
            .map(|record| stream_of(&record, direction)))
    }
    /// Restores the listeners a session saved, without starting them.
    pub fn restore_listeners(&self, listeners: Vec<TcpListenerConfig>) {
        *self.listeners.lock().unwrap() = listeners;
    }
    pub fn listener_configs(&self) -> Vec<TcpListenerConfig> {
        self.listeners.lock().unwrap().clone()
    }
    /// Starts every listener that is on and not running. One that cannot start
    /// keeps its reason for the status and leaves the others running.
    pub async fn start_saved(self: &Arc<Self>) {
        for listener in self.listener_configs() {
            if !listener.enabled || self.running.lock().await.contains_key(&listener.id) {
                continue;
            }
            if let Err(error) = self.start_listener(listener.id, listener.settings).await {
                self.errors
                    .lock()
                    .unwrap()
                    .insert(listener.id, error.to_string());
            }
        }
    }
    /// A listener that is on is started first, and kept only if it starts.
    pub async fn add_listener(self: &Arc<Self>, input: TcpListenerInput) -> anyhow::Result<Uuid> {
        let settings = self.checked_settings(None, input.settings)?;
        anyhow::ensure!(
            self.listeners.lock().unwrap().len() < MAX_LISTENERS,
            "A session keeps at most {MAX_LISTENERS} TCP listeners."
        );
        let id = Uuid::new_v4();
        if input.enabled {
            self.start_listener(id, settings.clone()).await?;
        }
        self.listeners.lock().unwrap().push(TcpListenerConfig {
            id,
            enabled: input.enabled,
            settings,
        });
        Ok(id)
    }
    /// A running listener is restarted with the new settings; if they cannot
    /// start, the old ones are put back and the change is not kept.
    pub async fn update_listener(
        self: &Arc<Self>,
        id: Uuid,
        input: TcpListenerInput,
    ) -> anyhow::Result<()> {
        let settings = self.checked_settings(Some(id), input.settings)?;
        let old = self
            .listener_configs()
            .into_iter()
            .find(|listener| listener.id == id)
            .ok_or_else(|| anyhow::anyhow!(UNKNOWN_LISTENER))?;
        let was_running = self.running.lock().await.contains_key(&id);
        if was_running {
            self.stop_listener(id).await?;
        }
        if input.enabled {
            if let Err(error) = self.start_listener(id, settings.clone()).await {
                if was_running {
                    let _ = self.start_listener(id, old.settings).await;
                }
                return Err(error);
            }
        }
        if let Some(listener) = self
            .listeners
            .lock()
            .unwrap()
            .iter_mut()
            .find(|listener| listener.id == id)
        {
            listener.enabled = input.enabled;
            listener.settings = settings;
        }
        self.errors.lock().unwrap().remove(&id);
        Ok(())
    }
    pub async fn remove_listener(&self, id: Uuid) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.listeners
                .lock()
                .unwrap()
                .iter()
                .any(|listener| listener.id == id),
            UNKNOWN_LISTENER
        );
        let stopped = self.stop_listener(id).await;
        self.listeners
            .lock()
            .unwrap()
            .retain(|listener| listener.id != id);
        self.errors.lock().unwrap().remove(&id);
        Ok(stopped?)
    }
    /// Valid settings with a normalized host, on a port no other listener of
    /// this session uses.
    fn checked_settings(
        &self,
        id: Option<Uuid>,
        mut settings: TcpSettings,
    ) -> anyhow::Result<TcpSettings> {
        settings.validate()?;
        settings.target_host = settings.normalized_host()?;
        anyhow::ensure!(
            !self.listeners.lock().unwrap().iter().any(|listener| {
                Some(listener.id) != id && listener.settings.local_port == settings.local_port
            }),
            "Another listener already uses local port {}.",
            settings.local_port
        );
        Ok(settings)
    }
    #[cfg(test)]
    pub async fn start(self: &Arc<Self>, settings: TcpSettings) -> anyhow::Result<()> {
        self.start_listener(Uuid::new_v4(), settings).await
    }
    async fn start_listener(
        self: &Arc<Self>,
        id: Uuid,
        mut settings: TcpSettings,
    ) -> anyhow::Result<()> {
        settings.validate()?;
        settings.target_host = settings.normalized_host()?;
        let mut running = self.running.lock().await;
        // A listener can exit on accept failure without an explicit stop. Reap
        // only completed owners, under the same lock used for start/stop, so
        // concurrent starts cannot overlap or detach an in-flight shutdown.
        running.retain(|_, worker| !worker.task.is_finished());
        anyhow::ensure!(
            !running.contains_key(&id),
            "stop this TCP listener before starting it again"
        );
        {
            let history = self.history.lock().unwrap();
            anyhow::ensure!(
                !history.load_error && !history.persistence_error,
                "TCP history requires recovery before capture can start"
            );
        }
        if let Err(error) = HistoryDirectory::open(&self.directory) {
            if error.kind() != std::io::ErrorKind::NotFound {
                self.history.lock().unwrap().load_error = true;
                anyhow::bail!("TCP history requires recovery before capture can start");
            }
        }
        let bound = if settings.remote {
            bind_every_interface(settings.local_port)
        } else {
            TcpListener::bind((Ipv4Addr::LOCALHOST, settings.local_port)).await
        };
        let listener = bound.map_err(|error| {
            if error.kind() == std::io::ErrorKind::AddrInUse {
                anyhow::anyhow!("Local port {} is already in use. Choose another Local port or stop the listener using it.", settings.local_port)
            } else {
                anyhow::anyhow!("Could not bind local port {}. Check the port and local permissions.", settings.local_port)
            }
        })?;
        let (stop, receiver) = watch::channel(false);
        let capture = self.clone();
        let refused = Arc::new(AtomicU64::new(0));
        let counted = refused.clone();
        let task = tokio::spawn(async move {
            capture.serve(listener, settings, counted, receiver).await;
        });
        running.insert(
            id,
            Running {
                refused,
                stop,
                task,
            },
        );
        self.errors.lock().unwrap().remove(&id);
        Ok(())
    }
    /// Stops admission on every listener, cancels both directions, and waits for
    /// final persistence. No listener is turned off: a session switch or
    /// shutdown stops them, and they start again with the session.
    pub async fn stop(&self) -> Result<(), TcpPersistenceError> {
        let mut running = self.running.lock().await;
        for worker in running.values() {
            let _ = worker.stop.send(true);
        }
        for worker in running.values_mut() {
            // Preserve ownership if this caller is cancelled while joining. A
            // subsequent stop/session switch must still await the same worker.
            let _ = (&mut worker.task).await;
        }
        running.clear();
        // Keep start/stop serialized through the retry. Terminal records are
        // immutable, so cancellation can only cause the same bytes to be saved
        // again, never an older snapshot to overwrite a newer one.
        self.retry_terminal_records().await
    }
    async fn stop_listener(&self, id: Uuid) -> Result<(), TcpPersistenceError> {
        let mut running = self.running.lock().await;
        if let Some(worker) = running.get_mut(&id) {
            let _ = worker.stop.send(true);
            let _ = (&mut worker.task).await;
        }
        running.remove(&id);
        // Keep start/stop serialized through the retry. Terminal records are
        // immutable, so cancellation can only cause the same bytes to be saved
        // again, never an older snapshot to overwrite a newer one.
        self.retry_terminal_records().await
    }
    async fn retry_terminal_records(&self) -> Result<(), TcpPersistenceError> {
        let ids: Vec<_> = self
            .history
            .lock()
            .unwrap()
            .records
            .values()
            .filter(|record| record.ended_at.is_some() && !record.durable)
            .map(|record| record.id)
            .collect();
        // Clone one payload at a time rather than doubling a full history's
        // memory while retrying a storage outage.
        for id in ids {
            let mut record = self.history.lock().unwrap().records[&id].clone();
            record.durable = true;
            if self.persist(&record).await {
                if let Some(saved) = self.history.lock().unwrap().records.get_mut(&record.id) {
                    saved.durable = true;
                    saved.release_durable_payload();
                }
            }
        }
        let mut history = self.history.lock().unwrap();
        let pending_records = history
            .records
            .values()
            .filter(|record| record.ended_at.is_some() && !record.durable)
            .count();
        history.persistence_error = pending_records != 0;
        if pending_records == 0 {
            Ok(())
        } else {
            Err(TcpPersistenceError { pending_records })
        }
    }
    async fn persist(&self, record: &TcpConnection) -> bool {
        let directory = self.directory.clone();
        let record = record.clone();
        let result = tokio::task::spawn_blocking(move || {
            let root = HistoryDirectory::create(&directory)?;
            root.write_json(
                std::ffi::OsStr::new(&format!("{}.json", record.id)),
                &record,
            )
        })
        .await;
        if matches!(result, Ok(Ok(()))) {
            true
        } else {
            self.history.lock().unwrap().persistence_error = true;
            false
        }
    }
    async fn serve(
        self: Arc<Self>,
        listener: TcpListener,
        settings: TcpSettings,
        refused: Arc<AtomicU64>,
        mut stop: watch::Receiver<bool>,
    ) {
        let mut tasks = JoinSet::new();
        let (children_stop, children_receiver) = watch::channel(false);
        // Occupied admission slots of every listener, including tasks finishing
        // persistence; each listener admits at most MAX_ACTIVE of its own.
        loop {
            tokio::select! {
                biased;
                _ = stop.changed() => break,
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {
                    self.active_count.fetch_sub(1, Ordering::Relaxed);
                },
                accepted = listener.accept(), if tasks.len() < MAX_ACTIVE => {
                    let Ok((client, peer)) = accepted else { break; };
                    // IPv4 on a dual-stack socket arrives v4-mapped; record it as IPv4.
                    let peer = std::net::SocketAddr::new(peer.ip().to_canonical(), peer.port());
                    if settings.remote && !client_allowed(peer.ip(), &settings.allowed_clients) {
                        refused.fetch_add(1, Ordering::Relaxed);
                        drop(client);
                        continue;
                    }
                    // The locks end with this block, before anything awaits.
                    let admitted = {
                        let mut runtime = self.intercept.lock().unwrap();
                        let mut history = self.history.lock().unwrap();
                        if history.persistence_error || history.load_error {
                            Admission::Refused
                        } else if history.records.len() >= MAX_CONNECTIONS {
                            // A full history must not break the app under test:
                            // relay on, record nothing, and count it until cleared.
                            Admission::Unrecorded
                        } else {
                            let record = self.new_record(Uuid::new_v4(), peer.to_string(), &settings);
                            let (close, closed) = watch::channel(false);
                            runtime.connections.insert(record.id, close);
                            history.records.insert(record.id, record.clone());
                            Admission::Recorded(Box::new(record), closed)
                        }
                    };
                    let settings = settings.clone();
                    let stop = children_receiver.clone();
                    match admitted {
                        Admission::Refused => { drop(client); continue; }
                        Admission::Unrecorded => {
                            self.unrecorded.fetch_add(1, Ordering::Relaxed);
                            let proxy = self.upstream_proxy().await;
                            let guarded = self.guarded_for(&client);
                            tasks.spawn(relay_unrecorded(client, settings, proxy, guarded, stop));
                        }
                        Admission::Recorded(record, closed) => {
                            let capture = self.clone();
                            tasks.spawn(async move { capture.connection(client, *record, settings, stop, closed).await; });
                        }
                    }
                    self.active_count.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        drop(listener);
        let _ = children_stop.send(true);
        // Dropping the sender is also cancellation; no detached relay tasks remain.
        while tasks.join_next().await.is_some() {
            self.active_count.fetch_sub(1, Ordering::Relaxed);
        }
    }
    async fn connection(
        self: Arc<Self>,
        client: TcpStream,
        record: TcpConnection,
        settings: TcpSettings,
        mut stop: watch::Receiver<bool>,
        mut closed: watch::Receiver<bool>,
    ) {
        let id = record.id;
        // Persist admission before forwarding: a crash leaves an explicit interrupted record.
        if !self.persist(&record).await {
            self.finish(id, "failed", Some(TcpFailure::StorageFailed))
                .await;
            return;
        }
        let result = connection_outcome(
            async {
                let local = client.local_addr().map_err(|_| TcpFailure::ConnectFailed)?;
                let proxy = self.upstream_proxy().await;
                let guarded = self.guarded_for(&client);
                let (upstream, via_proxy) =
                    open_upstream(&settings, local, proxy.as_ref(), &guarded).await?;
                let (client, upstream, client_tls, server_tls) =
                    self.secure(&settings, client, upstream).await?;
                if let Some(r) = self.history.lock().unwrap().records.get_mut(&id) {
                    r.status = "open".into();
                    r.via_proxy = via_proxy;
                    r.client_tls = client_tls;
                    r.server_tls = server_tls;
                }
                let (client_read, client_write) = tokio::io::split(client);
                let (server_read, server_write) = tokio::io::split(upstream);
                tokio::try_join!(
                    self.pump(id, Direction::ClientToServer, client_read, server_write),
                    self.pump(id, Direction::ServerToClient, server_read, client_write)
                )
                .map_err(|_| TcpFailure::RelayFailed)?;
                Ok::<(), TcpFailure>(())
            },
            &mut stop,
            &mut closed,
        )
        .await;
        self.finish(id, result.0, result.1).await;
    }
    /// Sends a request's messages to its target over a new connection, one at a
    /// time, and records the exchange like a listener's: after each message the
    /// replies are read until `wait_ms` passes without any, or the target closes.
    pub async fn replay(&self, request: ReplayRequest) -> Result<TcpConnection, InterceptError> {
        let bad = |message: &str| InterceptError::BadRequest(message.into());
        if request.messages.is_empty() || request.messages.len() > MAX_REPLAY_MESSAGES {
            return Err(bad("A replay sends 1 to 64 messages."));
        }
        if !(50..=30_000).contains(&request.wait_ms) {
            return Err(bad("The wait is 50 to 30000 ms."));
        }
        let messages = request
            .messages
            .iter()
            .map(|message| STANDARD.decode(message))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| bad("Each message is standard base64."))?;
        if messages.iter().any(Vec::is_empty) {
            return Err(bad("A message cannot be empty."));
        }
        if messages.iter().map(Vec::len).sum::<usize>() > MAX_CAPTURE_BYTES {
            return Err(InterceptError::TooLarge(
                "A replay sends at most what one connection records.".into(),
            ));
        }
        let mut settings = TcpSettings {
            // Validation wants a port; a replay has no listener.
            local_port: 1,
            target_host: request.target_host,
            target_port: request.target_port,
            tls: if request.tls {
                TlsMode::Upstream
            } else {
                TlsMode::Off
            },
            ..Default::default()
        };
        settings
            .validate()
            .map_err(|error| bad(&error.to_string()))?;
        settings.target_host = settings
            .normalized_host()
            .map_err(|error| bad(&error.to_string()))?;
        settings.local_port = 0;
        let id = Uuid::new_v4();
        let mut record = self.new_record(id, "replay".into(), &settings);
        record.source = TcpSource::Replay;
        record.replayed_from = request.from;
        let closed = {
            let mut runtime = self.intercept.lock().unwrap();
            let mut history = self.history.lock().unwrap();
            if history.load_error || history.persistence_error {
                return Err(InterceptError::Conflict(
                    "TCP history requires recovery before a replay.".into(),
                ));
            }
            if history.records.len() >= MAX_CONNECTIONS {
                return Err(InterceptError::Conflict(
                    "TCP history is full. Clear it to replay.".into(),
                ));
            }
            let (close, closed) = watch::channel(false);
            runtime.connections.insert(id, close);
            history.records.insert(id, record.clone());
            closed
        };
        if !self.persist(&record).await {
            self.finish(id, "failed", Some(TcpFailure::StorageFailed))
                .await;
        } else {
            // A replay is stopped by closing it, not by a listener.
            let (_running, mut stop) = watch::channel(false);
            let mut closed = closed;
            let wait = Duration::from_millis(request.wait_ms);
            let result = connection_outcome(
                async {
                    let proxy = self.upstream_proxy().await;
                    let unspecified = std::net::SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0));
                    let (upstream, via_proxy) =
                        open_upstream(&settings, unspecified, proxy.as_ref(), &[]).await?;
                    let stream: Box<dyn Io> = if request.tls {
                        let insecure = self.upstream_insecure().await;
                        Box::new(connect_tls(upstream, &settings.target_host, insecure).await?)
                    } else {
                        Box::new(upstream)
                    };
                    if let Some(r) = self.history.lock().unwrap().records.get_mut(&id) {
                        r.status = "open".into();
                        r.via_proxy = via_proxy;
                        r.server_tls = request.tls;
                    }
                    tokio::time::timeout(REPLAY_LIMIT, self.exchange(id, stream, messages, wait))
                        .await
                        .unwrap_or(Ok(()))
                },
                &mut stop,
                &mut closed,
            )
            .await;
            self.finish(id, result.0, result.1).await;
        }
        self.detail(id)
            .await
            .ok()
            .flatten()
            .ok_or_else(|| InterceptError::Conflict("The replay record could not be read.".into()))
    }
    async fn exchange(
        &self,
        id: Uuid,
        mut stream: Box<dyn Io>,
        messages: Vec<Vec<u8>>,
        wait: Duration,
    ) -> Result<(), TcpFailure> {
        let mut buffer = vec![0u8; 16 * 1024];
        for message in messages {
            stream
                .write_all(&message)
                .await
                .map_err(|_| TcpFailure::RelayFailed)?;
            self.capture(id, Direction::ClientToServer, &message);
            loop {
                match tokio::time::timeout(wait, stream.read(&mut buffer)).await {
                    // Silence: the target has said what it will for now.
                    Err(_) => break,
                    Ok(Ok(0)) => return Ok(()),
                    Ok(Ok(read)) => self.capture(id, Direction::ServerToClient, &buffer[..read]),
                    Ok(Err(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
                        return Ok(())
                    }
                    Ok(Err(_)) => return Err(TcpFailure::RelayFailed),
                }
            }
        }
        let _ = stream.shutdown().await;
        Ok(())
    }
    fn new_record(&self, id: Uuid, peer: String, settings: &TcpSettings) -> TcpConnection {
        TcpConnection {
            id,
            started_at: Utc::now(),
            ended_at: None,
            peer,
            target: settings.target_label(),
            local_port: settings.local_port,
            via_proxy: false,
            client_tls: false,
            server_tls: false,
            source: TcpSource::Listener,
            replayed_from: None,
            status: "connecting".into(),
            failure: None,
            client_bytes: 0,
            server_bytes: 0,
            captured_bytes: 0,
            capture_truncated: false,
            durable: false,
            chunks: vec![],
            client_received_bytes: 0,
            server_received_bytes: 0,
            intercept_events: vec![],
            intercept_captured_bytes: 0,
            intercept_truncated: false,
            intercept_event_count: 0,
            intercept_schema_version: 1,
            pending_count: 0,
            pending_directions: vec![],
        }
    }
    /// Applies the listener's TLS mode to an opened connection pair, and says
    /// which side ended up in TLS.
    async fn secure(
        &self,
        settings: &TcpSettings,
        client: TcpStream,
        upstream: TcpStream,
    ) -> Result<(Box<dyn Io>, Box<dyn Io>, bool, bool), TcpFailure> {
        let insecure = self.upstream_insecure().await;
        match settings.tls {
            TlsMode::Off => Ok((Box::new(client), Box::new(upstream), false, false)),
            TlsMode::Upstream => {
                let server = connect_tls(upstream, &settings.target_host, insecure).await?;
                Ok((Box::new(client), Box::new(server), false, true))
            }
            TlsMode::Decrypt => {
                if !client_starts_tls(&client, &upstream).await {
                    return Ok((Box::new(client), Box::new(upstream), false, false));
                }
                let certificates = self.certificates.get().ok_or(TcpFailure::TlsFailed)?;
                let start = tokio_rustls::LazyConfigAcceptor::new(
                    rustls::server::Acceptor::default(),
                    client,
                )
                .await
                .map_err(|_| TcpFailure::TlsFailed)?;
                // The name the client asked for, or the target's, names both ends.
                let name = start
                    .client_hello()
                    .server_name()
                    .map(str::to_owned)
                    .unwrap_or_else(|| settings.target_host.clone());
                let server = connect_tls(upstream, &name, insecure).await?;
                let config = certificates
                    .server_config_for_host(&name)
                    .map_err(|_| TcpFailure::TlsFailed)?;
                let client = start
                    .into_stream(config)
                    .await
                    .map_err(|_| TcpFailure::TlsFailed)?;
                Ok((Box::new(client), Box::new(server), true, true))
            }
        }
    }
    async fn finish(&self, id: Uuid, status: &str, failure: Option<TcpFailure>) {
        let tickets: Vec<_> = {
            let mut runtime = self.intercept.lock().unwrap();
            runtime.connections.remove(&id);
            runtime
                .pending
                .iter()
                .filter(|(_, p)| p.connection_id == id)
                .map(|(k, _)| *k)
                .collect()
        };
        for ticket in tickets {
            self.end_range(
                ticket,
                if status == "failed" {
                    "failed"
                } else {
                    "cancelled"
                },
            );
        }
        let Ok(Some(complete_record)) = self.detail(id).await else {
            return;
        };
        let record = {
            let mut history = self.history.lock().unwrap();
            let Some(record) = history.records.get_mut(&id) else {
                return;
            };
            *record = complete_record;
            record.status = status.into();
            record.failure = if status == "failed" { failure } else { None };
            record.ended_at = Some(Utc::now());
            record.durable = false;
            let mut durable_record = record.clone();
            durable_record.durable = true;
            durable_record
        };
        let persisted = self.persist(&record).await;
        if let Some(record) = self.history.lock().unwrap().records.get_mut(&id) {
            record.durable = persisted;
            record.release_durable_payload();
        }
    }
    async fn pump<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
        &self,
        id: Uuid,
        direction: Direction,
        mut reader: R,
        mut writer: W,
    ) -> std::io::Result<()> {
        let mut buffer = [0u8; 16 * 1024];
        loop {
            let count = match reader.read(&mut buffer).await {
                // A TLS peer that closes without close_notify, as many clients
                // do, has ended its side all the same. Plain TCP never says this.
                Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => 0,
                read => read?,
            };
            if count == 0 {
                writer.shutdown().await?;
                return Ok(());
            }
            let admitted = self.admit(id, direction, &buffer[..count]);
            let mut selected: Option<Arc<[u8]>> = None;
            let mut ticket = None;
            if let Some((pending_id, mut decisions)) = admitted {
                ticket = Some(pending_id);
                let Some(decision) = decisions.recv().await else {
                    return Err(std::io::ErrorKind::ConnectionAborted.into());
                };
                let receipt = {
                    let mut runtime = self.intercept.lock().unwrap();
                    let pending = runtime
                        .pending
                        .get_mut(&pending_id)
                        .expect("owner retains admitted range");
                    pending.event.decided_at = Some(Utc::now());
                    pending.event.revision += 1;
                    match decision.request.action {
                        DecisionAction::Drop => {
                            pending.event.state = "dropped".into();
                            pending.event.selected_length = 0;
                        }
                        DecisionAction::Forward => {
                            pending.event.state = "forwarding".into();
                            pending.selected = decision.selected.map(Arc::from);
                            pending.event.edited = pending.selected.is_some();
                            if let Some(bytes) = &pending.selected {
                                pending.event.selected_length = bytes.len();
                            }
                            selected = pending.selected.clone();
                        }
                    }
                    DecisionReceipt {
                        pending_id,
                        state: pending.event.state.clone(),
                    }
                };
                let _ = decision.ack.send(Ok(receipt));
                if matches!(decision.request.action, DecisionAction::Drop) {
                    self.end_range(pending_id, "dropped");
                    continue;
                }
            }
            let bytes = selected.as_deref().unwrap_or(&buffer[..count]);
            let mut offset = 0;
            while offset < bytes.len() {
                let written = writer.write(&bytes[offset..]).await?;
                if written == 0 {
                    return Err(std::io::ErrorKind::WriteZero.into());
                }
                self.capture(id, direction, &bytes[offset..offset + written]);
                if let Some(ticket) = ticket {
                    if let Some(p) = self.intercept.lock().unwrap().pending.get_mut(&ticket) {
                        p.event.written_bytes += written;
                    }
                }
                offset += written;
            }
            if let Some(ticket) = ticket {
                self.end_range(ticket, "forwarded");
            }
        }
    }
    fn capture(&self, id: Uuid, direction: Direction, bytes: &[u8]) {
        let mut history = self.history.lock().unwrap();
        let Some(record) = history.records.get_mut(&id) else {
            return;
        };
        let offset = match direction {
            Direction::ClientToServer => {
                let n = record.client_bytes;
                record.client_bytes += bytes.len() as u64;
                n
            }
            Direction::ServerToClient => {
                let n = record.server_bytes;
                record.server_bytes += bytes.len() as u64;
                n
            }
        };
        let kept = if record.chunks.len() < MAX_CHUNKS {
            bytes.len().min(MAX_CAPTURE_BYTES - record.captured_bytes)
        } else {
            0
        };
        if kept != bytes.len() {
            record.capture_truncated = true;
        }
        if kept > 0 {
            record.chunks.push(TcpChunk {
                sequence: record.chunks.len(),
                at: Utc::now(),
                direction,
                offset,
                data_base64: STANDARD.encode(&bytes[..kept]),
            });
            record.captured_bytes += kept;
        }
    }
}
fn stream_of(record: &TcpConnection, direction: Direction) -> Vec<u8> {
    let mut chunks: Vec<_> = record
        .chunks
        .iter()
        .filter(|chunk| chunk.direction == direction)
        .collect();
    chunks.sort_by_key(|chunk| chunk.sequence);
    chunks
        .into_iter()
        .flat_map(|chunk| STANDARD.decode(&chunk.data_base64).unwrap_or_default())
        .collect()
}

/// A relayed stream, plain or in TLS.
trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

/// Whether the client's first bytes are a TLS handshake record (16 03 0x). A
/// server that speaks first, as SMTP or MySQL do, decides it: not TLS.
async fn client_starts_tls(client: &TcpStream, upstream: &TcpStream) -> bool {
    let first = async {
        let mut head = [0u8; 3];
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            let read = client.peek(&mut head).await.unwrap_or(0);
            if read == 0 || head[0] != 0x16 {
                return false;
            }
            if read >= 3 {
                return head[1] == 0x03 && head[2] <= 0x04;
            }
            // The rest of the record header is still on its way.
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    tokio::select! {
        biased;
        starts = first => starts,
        _ = upstream.readable() => false,
    }
}

/// TLS towards the target, named by SNI where the name is a host name.
async fn connect_tls(
    upstream: TcpStream,
    name: &str,
    insecure: bool,
) -> Result<tokio_rustls26::client::TlsStream<TcpStream>, TcpFailure> {
    let name = rustls23::pki_types::ServerName::try_from(name.trim_matches(['[', ']']).to_owned())
        .map_err(|_| TcpFailure::TlsFailed)?;
    tokio_rustls26::TlsConnector::from(crate::ws_tls::client_config(insecure))
        .connect(name, upstream)
        .await
        .map_err(|_| TcpFailure::TlsFailed)
}

/// Whether a target goes through the upstream proxy: only while it is on, and
/// never for a bypassed host or this machine, which a proxy elsewhere cannot
/// reach.
fn routes_through(proxy: &crate::upstream_proxy::UpstreamProxy, host: &str) -> bool {
    let local = host.eq_ignore_ascii_case("localhost")
        || host
            .trim_matches(['[', ']'])
            .parse::<std::net::IpAddr>()
            .is_ok_and(is_loopback);
    proxy.enabled && !local && !proxy.bypasses(host)
}

/// Opens the connection to a listener's target, through the upstream proxy when
/// it applies, and says whether it did. A direct connection that comes back to
/// the listener is refused: it would recursively fill the connection budget.
async fn open_upstream(
    settings: &TcpSettings,
    listener: std::net::SocketAddr,
    proxy: Option<&crate::upstream_proxy::UpstreamProxy>,
    guarded: &[std::net::SocketAddr],
) -> Result<(TcpStream, bool), TcpFailure> {
    if let Some(proxy) = proxy.filter(|proxy| routes_through(proxy, &settings.target_host)) {
        // The proxy's own errors can name hosts; only the code is kept.
        return proxy
            .connect(&settings.target_host, settings.target_port)
            .await
            .map(|stream| (stream, true))
            .map_err(|_| TcpFailure::ProxyFailed);
    }
    let addresses: Vec<_> = connection_stage(
        tokio::net::lookup_host((settings.target_host.as_str(), settings.target_port)),
        Duration::from_secs(10),
        true,
    )
    .await?
    .collect();
    if addresses.is_empty() {
        return Err(TcpFailure::ResolutionFailed);
    }
    if addresses
        .iter()
        .any(|a| is_loopback(a.ip()) && a.port() == settings.local_port)
    {
        return Err(TcpFailure::SelfTarget);
    }
    if reaches_guarded(&addresses, guarded) {
        return Err(TcpFailure::GuardedTarget);
    }
    let upstream = connection_stage(
        TcpStream::connect(addresses.as_slice()),
        Duration::from_secs(10),
        false,
    )
    .await?;
    if upstream
        .peer_addr()
        .map_err(|_| TcpFailure::ConnectFailed)?
        == listener
    {
        return Err(TcpFailure::SelfTarget);
    }
    Ok((upstream, false))
}

/// A connection past the history cap: relayed as it is, not recorded or held.
async fn relay_unrecorded(
    mut client: TcpStream,
    settings: TcpSettings,
    proxy: Option<crate::upstream_proxy::UpstreamProxy>,
    guarded: Vec<std::net::SocketAddr>,
    mut stop: watch::Receiver<bool>,
) {
    let relay = async {
        let local = client.local_addr().ok()?;
        let (mut upstream, _) = open_upstream(&settings, local, proxy.as_ref(), &guarded)
            .await
            .ok()?;
        tokio::io::copy_bidirectional(&mut client, &mut upstream)
            .await
            .ok()
    };
    tokio::select! {
        _ = wait_stop(&mut stop) => {}
        _ = relay => {}
    }
}

fn is_loopback(ip: std::net::IpAddr) -> bool {
    ip.is_loopback()
        || match ip {
            std::net::IpAddr::V6(ip) => ip.to_ipv4().map(|ip| ip.is_loopback()).unwrap_or(false),
            std::net::IpAddr::V4(_) => false,
        }
}
async fn wait_stop(receiver: &mut watch::Receiver<bool>) {
    if *receiver.borrow() {
        return;
    }
    let _ = receiver.changed().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    fn stored_connection_count(directory: &std::path::Path) -> Option<usize> {
        let mut budget = SUMMARY_READ_BUDGET;
        super::stored_connection_count(directory, &mut budget)
    }
    fn temporary() -> Arc<TcpCapture> {
        Arc::new(TcpCapture::load(
            std::env::temp_dir().join(format!("sniper-tcp-{}", Uuid::new_v4())),
        ))
    }
    fn record() -> TcpConnection {
        TcpConnection {
            id: Uuid::new_v4(),
            started_at: Utc::now(),
            ended_at: None,
            peer: "127.0.0.1:1".into(),
            target: "127.0.0.1:2".into(),
            local_port: 0,
            via_proxy: false,
            client_tls: false,
            server_tls: false,
            source: TcpSource::Listener,
            replayed_from: None,
            status: "open".into(),
            failure: None,
            client_bytes: 0,
            server_bytes: 0,
            captured_bytes: 0,
            capture_truncated: false,
            durable: false,
            chunks: vec![],
            client_received_bytes: 0,
            server_received_bytes: 0,
            intercept_events: vec![],
            intercept_captured_bytes: 0,
            intercept_truncated: false,
            intercept_event_count: 0,
            intercept_schema_version: 1,
            pending_count: 0,
            pending_directions: vec![],
        }
    }
    fn resident_preview_bytes(capture: &TcpCapture) -> usize {
        capture
            .history
            .lock()
            .unwrap()
            .records
            .values()
            .map(|record| {
                record
                    .chunks
                    .iter()
                    .map(|chunk| chunk.data_base64.len())
                    .sum::<usize>()
                    + record
                        .intercept_events
                        .iter()
                        .map(|event| {
                            event.original_base64.as_ref().map_or(0, String::len)
                                + event.selected_base64.as_ref().map_or(0, String::len)
                        })
                        .sum::<usize>()
            })
            .sum()
    }

    #[test]
    fn atomic_write_temp_names_require_two_canonical_uuids() {
        let id = Uuid::new_v4();
        let suffix = Uuid::parse_str("01234567-89ab-4cde-8f01-23456789abcd").unwrap();
        assert!(is_history_temporary_path(std::path::Path::new(&format!(
            "{id}.tmp-{suffix}"
        ))));
        for name in [
            format!("{id}.json"),
            format!("{id}.json.tmp-{suffix}"),
            format!("{id}.tmp-invalid"),
            format!("invalid.tmp-{suffix}"),
            format!("{id}.tmp-{suffix}.json"),
            format!("{}.tmp-{suffix}", id.simple()),
            format!("{id}.tmp-{}", suffix.simple()),
            format!("{id}.tmp-{}", suffix.to_string().to_uppercase()),
        ] {
            assert!(
                !is_history_temporary_path(std::path::Path::new(&name)),
                "{name}"
            );
        }
    }

    #[tokio::test]
    async fn orphan_atomic_writes_preserve_durable_history_and_allow_start() {
        let capture = temporary();
        let initial = record();
        let id = initial.id;
        capture.history.lock().unwrap().records.insert(id, initial);
        capture.capture(id, Direction::ClientToServer, &[0, 255, 13, 10]);
        capture.finish(id, "closed", None).await;
        let path = capture.directory.join(format!("{id}.json"));
        let durable = std::fs::read(&path).unwrap();
        let temp = path.with_extension(format!("tmp-{}", Uuid::new_v4()));
        std::fs::write(&temp, b"{unfinished").unwrap();
        let unpublished = record();
        let unpublished_path =
            capture
                .directory
                .join(format!("{}.tmp-{}", unpublished.id, Uuid::new_v4()));
        let unpublished_bytes = serde_json::to_vec(&unpublished).unwrap();
        std::fs::write(&unpublished_path, &unpublished_bytes).unwrap();
        let loaded = Arc::new(TcpCapture::load(capture.directory.clone()));
        assert!(!loaded.status().await.load_error);
        assert_eq!(loaded.connection_count(), Some(1));
        assert_eq!(stored_connection_count(&capture.directory), Some(1));
        assert!(loaded.detail(unpublished.id).await.unwrap().is_none());
        assert_eq!(
            serde_json::to_value(loaded.detail(id).await.unwrap().unwrap()).unwrap(),
            serde_json::to_value(capture.detail(id).await.unwrap().unwrap()).unwrap()
        );
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let local_port = listener.local_addr().unwrap().port();
        drop(listener);
        loaded
            .start(TcpSettings {
                local_port,
                target_host: "127.0.0.1".into(),
                target_port: 9,
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(loaded.status().await.enabled);
        loaded.stop().await.unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), durable);
        assert_eq!(std::fs::read(&temp).unwrap(), b"{unfinished");
        assert_eq!(std::fs::read(&unpublished_path).unwrap(), unpublished_bytes);
        std::fs::remove_dir_all(&capture.directory).unwrap();
    }

    #[tokio::test]
    async fn terminal_atomic_write_orphan_cannot_promote_admission_snapshot() {
        let capture = temporary();
        let admission = record();
        let id = admission.id;
        let path = capture.directory.join(format!("{id}.json"));
        crate::session::write_json(&path, &admission).unwrap();
        let admission_bytes = std::fs::read(&path).unwrap();
        capture
            .history
            .lock()
            .unwrap()
            .records
            .insert(id, admission);
        capture.capture(id, Direction::ClientToServer, b"unpublished terminal bytes");
        let mut terminal = capture.detail(id).await.unwrap().unwrap();
        terminal.ended_at = Some(Utc::now());
        terminal.status = "closed".into();
        terminal.durable = true;
        let temp = path.with_extension(format!("tmp-{}", Uuid::new_v4()));
        let terminal_bytes = serde_json::to_vec(&terminal).unwrap();
        std::fs::write(&temp, &terminal_bytes).unwrap();
        let loaded = TcpCapture::load(capture.directory.clone());
        assert!(!loaded.status().await.load_error);
        assert_eq!(loaded.connection_count(), Some(1));
        assert_eq!(stored_connection_count(&capture.directory), Some(1));
        let recovered = loaded.detail(id).await.unwrap().unwrap();
        assert_eq!(recovered.status, "interrupted");
        assert!(recovered.ended_at.is_none());
        assert!(!recovered.durable);
        assert!(recovered.capture_truncated);
        assert!(recovered.intercept_truncated);
        assert_eq!(recovered.client_bytes, 0);
        assert_eq!(recovered.captured_bytes, 0);
        assert!(recovered.chunks.is_empty());
        assert_eq!(std::fs::read(&path).unwrap(), admission_bytes);
        assert_eq!(std::fs::read(&temp).unwrap(), terminal_bytes);
        std::fs::remove_dir_all(&capture.directory).unwrap();
    }

    #[tokio::test]
    async fn orphan_atomic_writes_do_not_hide_corrupt_records() {
        let capture = temporary();
        let valid = record();
        let id = valid.id;
        crate::session::write_json(&capture.directory.join(format!("{id}.json")), &valid).unwrap();
        let corrupt = record();
        let path = capture.directory.join(format!("{}.json", corrupt.id));
        std::fs::write(&path, b"broken durable record").unwrap();
        let temp = path.with_extension(format!("tmp-{}", Uuid::new_v4()));
        std::fs::write(&temp, serde_json::to_vec(&corrupt).unwrap()).unwrap();
        let loaded = Arc::new(TcpCapture::load(capture.directory.clone()));
        assert!(loaded.status().await.load_error);
        assert!(loaded.detail(id).await.unwrap().is_some());
        assert!(loaded.detail(corrupt.id).await.unwrap().is_none());
        assert_eq!(loaded.connection_count(), None);
        assert_eq!(stored_connection_count(&capture.directory), None);
        assert!(loaded
            .start(TcpSettings {
                local_port: 12345,
                target_host: "127.0.0.1".into(),
                target_port: 9,
                ..Default::default()
            })
            .await
            .unwrap_err()
            .to_string()
            .contains("requires recovery"));
        assert_eq!(std::fs::read(&path).unwrap(), b"broken durable record");
        std::fs::remove_dir_all(&capture.directory).unwrap();
    }

    #[tokio::test]
    async fn unexpected_history_files_and_temp_directories_still_fail_closed() {
        for name in [
            "unrelated.txt".to_string(),
            format!("{}.tmp-invalid", Uuid::new_v4()),
            format!("invalid.tmp-{}", Uuid::new_v4()),
            format!("{}.json.tmp-{}", Uuid::new_v4(), Uuid::new_v4()),
        ] {
            let capture = temporary();
            std::fs::create_dir_all(&capture.directory).unwrap();
            std::fs::write(capture.directory.join(name), b"unpublished").unwrap();
            assert!(
                TcpCapture::load(capture.directory.clone())
                    .status()
                    .await
                    .load_error
            );
            assert_eq!(stored_connection_count(&capture.directory), None);
            std::fs::remove_dir_all(&capture.directory).unwrap();
        }
        let capture = temporary();
        let temp = capture
            .directory
            .join(format!("{}.tmp-{}", Uuid::new_v4(), Uuid::new_v4()));
        std::fs::create_dir_all(temp).unwrap();
        assert!(
            TcpCapture::load(capture.directory.clone())
                .status()
                .await
                .load_error
        );
        assert_eq!(stored_connection_count(&capture.directory), None);
        std::fs::remove_dir_all(&capture.directory).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn orphan_atomic_write_symlinks_still_fail_closed() {
        let capture = temporary();
        std::fs::create_dir_all(&capture.directory).unwrap();
        let temp = capture
            .directory
            .join(format!("{}.tmp-{}", Uuid::new_v4(), Uuid::new_v4()));
        std::os::unix::fs::symlink("missing-target", &temp).unwrap();
        assert!(
            TcpCapture::load(capture.directory.clone())
                .status()
                .await
                .load_error
        );
        assert_eq!(stored_connection_count(&capture.directory), None);
        assert!(std::fs::symlink_metadata(temp).unwrap().is_symlink());
        std::fs::remove_dir_all(&capture.directory).unwrap();
    }

    #[tokio::test]
    async fn orphan_atomic_writes_do_not_consume_record_capacity() {
        let capture = temporary();
        for _ in 0..MAX_CONNECTIONS {
            let record = record();
            let path = capture.directory.join(format!("{}.json", record.id));
            crate::session::write_json(&path, &record).unwrap();
            std::fs::write(
                path.with_extension(format!("tmp-{}", Uuid::new_v4())),
                b"partial",
            )
            .unwrap();
        }
        let loaded = TcpCapture::load(capture.directory.clone());
        assert!(!loaded.status().await.load_error);
        assert_eq!(loaded.connection_count(), Some(MAX_CONNECTIONS));
        assert_eq!(
            stored_connection_count(&capture.directory),
            Some(MAX_CONNECTIONS)
        );
        let extra = record();
        crate::session::write_json(
            &capture.directory.join(format!("{}.json", extra.id)),
            &extra,
        )
        .unwrap();
        assert!(
            TcpCapture::load(capture.directory.clone())
                .status()
                .await
                .load_error
        );
        assert_eq!(stored_connection_count(&capture.directory), None);
        assert_eq!(
            std::fs::read_dir(&capture.directory).unwrap().count(),
            2 * MAX_CONNECTIONS + 1
        );
        std::fs::remove_dir_all(&capture.directory).unwrap();
    }

    #[tokio::test]
    async fn orphan_atomic_write_directory_scans_remain_bounded() {
        let capture = temporary();
        std::fs::create_dir_all(&capture.directory).unwrap();
        for _ in 0..MAX_HISTORY_DIRECTORY_ENTRIES {
            let temp = capture
                .directory
                .join(format!("{}.tmp-{}", Uuid::new_v4(), Uuid::new_v4()));
            std::fs::write(temp, b"partial").unwrap();
        }
        assert_eq!(
            TcpCapture::load(capture.directory.clone()).connection_count(),
            Some(0)
        );
        assert_eq!(stored_connection_count(&capture.directory), Some(0));
        let temp = capture
            .directory
            .join(format!("{}.tmp-{}", Uuid::new_v4(), Uuid::new_v4()));
        std::fs::write(temp, b"partial").unwrap();
        assert!(
            TcpCapture::load(capture.directory.clone())
                .status()
                .await
                .load_error
        );
        assert_eq!(stored_connection_count(&capture.directory), None);
        assert_eq!(
            std::fs::read_dir(&capture.directory).unwrap().count(),
            MAX_HISTORY_DIRECTORY_ENTRIES + 1
        );
        std::fs::remove_dir_all(&capture.directory).unwrap();
    }

    #[tokio::test]
    async fn retry_success_releases_complete_payload_and_keeps_detail_readable() {
        let (capture, id) = setup_intercept();
        capture.capture(id, Direction::ClientToServer, &[0, 255, 128, 13, 10]);
        let (ticket, _receiver) = capture
            .admit(id, Direction::ServerToClient, &[255, 0, 254])
            .unwrap();
        capture.end_range(ticket, "cancelled");
        std::fs::write(&capture.directory, b"storage unavailable").unwrap();
        capture.finish(id, "stopped", None).await;
        assert!(capture.stop().await.is_err());
        let before = capture.detail(id).await.unwrap().unwrap();
        assert!(!before.durable);
        assert!(!before.chunks.is_empty());
        assert!(!before.intercept_events.is_empty());
        assert!(resident_preview_bytes(&capture) > 0);
        std::fs::remove_file(&capture.directory).unwrap();
        capture.stop().await.unwrap();
        assert_eq!(resident_preview_bytes(&capture), 0);
        let actual = capture.detail(id).await.unwrap().unwrap();
        let mut expected = before;
        expected.durable = true;
        assert_eq!(
            serde_json::to_value(&actual).unwrap(),
            serde_json::to_value(&expected).unwrap()
        );
        assert!(!capture.status().await.load_error);
        assert!(!capture.status().await.persistence_error);
        let reloaded = TcpCapture::load(capture.directory.clone());
        assert_eq!(resident_preview_bytes(&reloaded), 0);
        assert_eq!(
            serde_json::to_value(reloaded.detail(id).await.unwrap().unwrap()).unwrap(),
            serde_json::to_value(expected).unwrap()
        );
        std::fs::remove_dir_all(&capture.directory).unwrap();
    }
    #[tokio::test]
    async fn durable_payloads_are_released_and_detail_reads_do_not_retain_them() {
        let mut sessions = Vec::new();
        for _ in 0..3 {
            let capture = temporary();
            let mut expected = Vec::new();
            for _ in 0..4 {
                let record = record();
                let id = record.id;
                capture.history.lock().unwrap().records.insert(id, record);
                capture.capture(id, Direction::ClientToServer, &vec![255; MAX_CAPTURE_BYTES]);
                assert!(resident_preview_bytes(&capture) >= MAX_CAPTURE_BYTES);
                capture.finish(id, "closed", None).await;
                assert_eq!(resident_preview_bytes(&capture), 0);
                let detail = capture.detail(id).await.unwrap().unwrap();
                assert_eq!(
                    STANDARD.decode(&detail.chunks[0].data_base64).unwrap(),
                    vec![255; MAX_CAPTURE_BYTES]
                );
                let path = capture.directory.join(format!("{id}.json"));
                let disk = std::fs::read(&path).unwrap();
                assert_eq!(
                    serde_json::to_value(&detail).unwrap(),
                    serde_json::from_slice::<serde_json::Value>(&disk).unwrap()
                );
                expected.push((id, disk));
            }
            let reloaded = TcpCapture::load(capture.directory.clone());
            assert_eq!(resident_preview_bytes(&reloaded), 0);
            assert_eq!(reloaded.connection_count(), Some(4));
            for (id, original_disk) in expected {
                for _ in 0..3 {
                    let detail = reloaded.detail(id).await.unwrap().unwrap();
                    assert_eq!(
                        serde_json::to_value(&detail).unwrap(),
                        serde_json::from_slice::<serde_json::Value>(&original_disk).unwrap()
                    );
                    assert_eq!(resident_preview_bytes(&reloaded), 0);
                }
                assert_eq!(
                    std::fs::read(capture.directory.join(format!("{id}.json"))).unwrap(),
                    original_disk
                );
            }
            sessions.push((capture, reloaded));
        }
        assert_eq!(
            sessions
                .iter()
                .map(|(a, b)| resident_preview_bytes(a) + resident_preview_bytes(b))
                .sum::<usize>(),
            0
        );
        for (capture, _) in sessions {
            std::fs::remove_dir_all(&capture.directory).unwrap();
        }
    }

    #[tokio::test]
    async fn failed_persistence_pins_payload_until_success_and_never_saves_a_summary() {
        let capture = temporary();
        let record = record();
        let id = record.id;
        capture.history.lock().unwrap().records.insert(id, record);
        capture.capture(id, Direction::ServerToClient, &[0, 255, 128, 13, 10]);
        std::fs::write(&capture.directory, b"storage unavailable").unwrap();
        capture.finish(id, "closed", None).await;
        let failed = capture.detail(id).await.unwrap().unwrap();
        assert!(!failed.durable);
        assert!(failed.ended_at.is_some());
        assert_eq!(
            resident_preview_bytes(&capture),
            failed.chunks[0].data_base64.len()
        );
        assert_eq!(
            STANDARD.decode(&failed.chunks[0].data_base64).unwrap(),
            [0, 255, 128, 13, 10]
        );
        std::fs::remove_file(&capture.directory).unwrap();
        capture.finish(id, "closed", None).await;
        assert_eq!(resident_preview_bytes(&capture), 0);
        // Finalizing an already durable record must hydrate, never overwrite it
        // with the metadata-only in-memory representation.
        capture.finish(id, "stopped", None).await;
        let reloaded = TcpCapture::load(capture.directory.clone());
        let recovered = reloaded.detail(id).await.unwrap().unwrap();
        assert!(recovered.durable);
        assert_eq!(
            recovered.chunks[0].data_base64,
            failed.chunks[0].data_base64
        );
        std::fs::remove_dir_all(&capture.directory).unwrap();
    }

    #[tokio::test]
    async fn active_interrupted_and_nondurable_records_keep_payloads_resident() {
        let capture = temporary();
        let mut record = record();
        let id = record.id;
        capture
            .history
            .lock()
            .unwrap()
            .records
            .insert(id, record.clone());
        capture.capture(id, Direction::ClientToServer, &[0, 255, 127]);
        record = capture.detail(id).await.unwrap().unwrap();
        assert_eq!(resident_preview_bytes(&capture), 4);
        assert!(capture.persist(&record).await);
        let interrupted = TcpCapture::load(capture.directory.clone());
        let restored = interrupted.detail(id).await.unwrap().unwrap();
        assert_eq!(restored.status, "interrupted");
        assert_eq!(resident_preview_bytes(&interrupted), 4);
        assert_eq!(restored.chunks[0].data_base64, record.chunks[0].data_base64);
        record.ended_at = Some(Utc::now());
        record.status = "closed".into();
        assert!(!record.durable);
        assert!(capture.persist(&record).await);
        let nondurable = TcpCapture::load(capture.directory.clone());
        assert_eq!(resident_preview_bytes(&nondurable), 4);
        assert_eq!(
            nondurable.detail(id).await.unwrap().unwrap().chunks[0].data_base64,
            record.chunks[0].data_base64
        );
        std::fs::remove_dir_all(&capture.directory).unwrap();
    }

    #[tokio::test]
    async fn unreadable_or_changed_saved_details_fail_explicitly_without_losing_summaries() {
        for fault in ["missing", "corrupt", "oversized", "changed"] {
            let capture = temporary();
            let record = record();
            let id = record.id;
            capture.history.lock().unwrap().records.insert(id, record);
            capture.capture(id, Direction::ClientToServer, &[0, 255]);
            capture.finish(id, "closed", None).await;
            let path = capture.directory.join(format!("{id}.json"));
            match fault {
                "missing" => std::fs::remove_file(&path).unwrap(),
                "corrupt" => std::fs::write(&path, b"not json").unwrap(),
                "oversized" => std::fs::OpenOptions::new()
                    .write(true)
                    .open(&path)
                    .unwrap()
                    .set_len(MAX_RECORD_FILE_BYTES + 1)
                    .unwrap(),
                "changed" => {
                    let mut saved = read_stored_connection(&path).unwrap();
                    saved.status = "stopped".into();
                    crate::session::write_json(&path, &saved).unwrap();
                }
                _ => unreachable!(),
            }
            assert!(capture.detail(id).await.is_err(), "{fault}");
            assert!(capture.status().await.load_error, "{fault}");
            assert_eq!(capture.summaries().await.len(), 1);
            assert_eq!(capture.summaries().await[0].captured_bytes, 2);
            assert_eq!(resident_preview_bytes(&capture), 0);
            assert!(capture.detail(Uuid::new_v4()).await.unwrap().is_none());
            std::fs::remove_dir_all(&capture.directory).unwrap();
        }
    }

    #[tokio::test]
    async fn tcp_failed_terminal_save_retries_without_a_listener_and_survives_reload() {
        let capture = temporary();
        let initial = record();
        let id = initial.id;
        assert!(capture.persist(&initial).await);
        capture.history.lock().unwrap().records.insert(id, initial);
        capture.capture(id, Direction::ClientToServer, &[0, 255, 42]);
        let held = capture.directory.with_extension("held");
        std::fs::rename(&capture.directory, &held).unwrap();
        std::fs::write(&capture.directory, b"storage unavailable").unwrap();
        capture.finish(id, "stopped", None).await;
        for _ in 0..2 {
            assert_eq!(capture.stop().await.unwrap_err().pending_records, 1);
            assert!(capture.status().await.persistence_error);
            assert!(!capture.detail(id).await.unwrap().unwrap().durable);
        }
        let failed = capture.detail(id).await.unwrap().unwrap();
        assert_eq!(failed.client_bytes, 3);
        assert_eq!(failed.chunks[0].data_base64, "AP8q");
        std::fs::remove_file(&capture.directory).unwrap();
        std::fs::rename(&held, &capture.directory).unwrap();
        capture.stop().await.unwrap();
        assert!(!capture.status().await.persistence_error);
        let saved = capture.detail(id).await.unwrap().unwrap();
        assert!(saved.durable);
        assert_eq!(saved.ended_at, failed.ended_at);
        assert_eq!(saved.chunks[0].data_base64, failed.chunks[0].data_base64);
        let loaded = TcpCapture::load(capture.directory.clone());
        assert_eq!(
            serde_json::to_value(loaded.detail(id).await.unwrap().unwrap()).unwrap(),
            serde_json::to_value(saved).unwrap()
        );
        capture.stop().await.unwrap();
        std::fs::remove_dir_all(&capture.directory).unwrap();
    }

    #[tokio::test]
    async fn tcp_retry_attempts_every_record_and_clears_error_only_after_all_save() {
        let capture = temporary();
        let mut ids = vec![];
        std::fs::write(&capture.directory, b"storage unavailable").unwrap();
        for _ in 0..3 {
            let initial = record();
            let id = initial.id;
            ids.push(id);
            capture.history.lock().unwrap().records.insert(id, initial);
            capture.capture(id, Direction::ServerToClient, b"retained");
            capture.finish(id, "stopped", None).await;
        }
        std::fs::remove_file(&capture.directory).unwrap();
        std::fs::create_dir(&capture.directory).unwrap();
        let blocked = capture.directory.join(format!("{}.json", ids[0]));
        std::fs::create_dir(&blocked).unwrap();
        assert_eq!(capture.stop().await.unwrap_err().pending_records, 1);
        assert!(capture.status().await.persistence_error);
        for id in &ids[1..] {
            assert!(capture.detail(*id).await.unwrap().unwrap().durable);
        }
        std::fs::remove_dir(&blocked).unwrap();
        capture.stop().await.unwrap();
        assert!(!capture.status().await.persistence_error);
        let loaded = TcpCapture::load(capture.directory.clone());
        assert!(loaded
            .records()
            .await
            .iter()
            .all(|record| record.durable && record.server_bytes == 8));
        assert_eq!(loaded.records().await.len(), 3);
        std::fs::remove_dir_all(&capture.directory).unwrap();
    }

    #[tokio::test]
    async fn tcp_retry_does_not_claim_crash_interrupted_records_are_complete() {
        let capture = temporary();
        let initial = record();
        let id = initial.id;
        assert!(capture.persist(&initial).await);
        let loaded = TcpCapture::load(capture.directory.clone());
        loaded.stop().await.unwrap();
        let interrupted = loaded.detail(id).await.unwrap().unwrap();
        assert_eq!(interrupted.status, "interrupted");
        assert!(!interrupted.durable);
        assert!(interrupted.ended_at.is_none());
        std::fs::remove_dir_all(&capture.directory).unwrap();
    }

    #[tokio::test]
    async fn loopback_self_target_and_storage_failure_do_not_forward() {
        for storage_failure in [false, true] {
            let capture = temporary();
            if storage_failure {
                std::fs::write(&capture.directory, b"not a directory").unwrap();
            }
            let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let address = listener.local_addr().unwrap();
            let settings = TcpSettings {
                local_port: address.port(),
                target_host: "127.0.0.1".into(),
                target_port: if storage_failure {
                    upstream.local_addr().unwrap().port()
                } else {
                    address.port()
                },
                ..Default::default()
            };
            let (stop, rx) = watch::channel(false);
            let copy = capture.clone();
            let relay = tokio::spawn(async move {
                copy.serve(listener, settings, Default::default(), rx).await
            });
            let mut client = TcpStream::connect(address).await.unwrap();
            let mut bytes = vec![];
            let _ = tokio::time::timeout(Duration::from_secs(3), client.read_to_end(&mut bytes))
                .await
                .unwrap();
            stop.send(true).unwrap();
            relay.await.unwrap();
            let rows = capture.records().await;
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].status, "failed");
            assert_eq!(
                rows[0].failure,
                Some(if storage_failure {
                    TcpFailure::StorageFailed
                } else {
                    TcpFailure::SelfTarget
                })
            );
            assert_eq!(rows[0].client_bytes, 0);
            assert_eq!(rows[0].durable, !storage_failure);
            assert_eq!(capture.status().await.persistence_error, storage_failure);
            assert!(
                tokio::time::timeout(Duration::from_millis(10), upstream.accept())
                    .await
                    .is_err()
            );
        }
    }
    #[test]
    fn failure_codes_are_optional_and_forward_compatible() {
        let mut json = serde_json::to_value(record()).unwrap();
        assert!(json.get("failure").is_none());
        assert_eq!(
            serde_json::from_value::<TcpConnection>(json.clone())
                .unwrap()
                .failure,
            None
        );
        json["failure"] = serde_json::json!("future_private_error");
        let future = serde_json::from_value::<TcpConnection>(json).unwrap();
        assert_eq!(future.failure, Some(TcpFailure::Unknown));
        assert!(!serde_json::to_string(&future)
            .unwrap()
            .contains("future_private_error"));
    }
    #[tokio::test]
    async fn simulated_stage_failures_are_safe_and_cancellable() {
        use std::io::{Error, ErrorKind};
        for (resolving, kind, expected) in [
            (true, ErrorKind::Other, TcpFailure::ResolutionFailed),
            (true, ErrorKind::TimedOut, TcpFailure::ResolutionTimeout),
            (false, ErrorKind::TimedOut, TcpFailure::ConnectTimeout),
            (
                false,
                ErrorKind::ConnectionRefused,
                TcpFailure::ConnectionRefused,
            ),
            (false, ErrorKind::Other, TcpFailure::ConnectFailed),
        ] {
            let future = async { Err::<(), _>(Error::new(kind, "secret-host-and-token")) };
            assert_eq!(
                connection_stage(future, Duration::from_secs(1), resolving).await,
                Err(expected)
            );
        }
        for (resolving, expected) in [
            (true, TcpFailure::ResolutionTimeout),
            (false, TcpFailure::ConnectTimeout),
        ] {
            assert_eq!(
                connection_stage(
                    std::future::pending::<std::io::Result<()>>(),
                    Duration::ZERO,
                    resolving
                )
                .await,
                Err(expected)
            );
            for explicit_close in [false, true] {
                let (sender, mut stop) = watch::channel(false);
                let (closer, mut closed) = watch::channel(false);
                let (began, started) = tokio::sync::oneshot::channel();
                let ended = Arc::new(std::sync::atomic::AtomicBool::new(false));
                struct DropFlag(Arc<std::sync::atomic::AtomicBool>);
                impl Drop for DropFlag {
                    fn drop(&mut self) {
                        self.0.store(true, std::sync::atomic::Ordering::SeqCst);
                    }
                }
                let guard = DropFlag(ended.clone());
                let task = tokio::spawn(async move {
                    connection_outcome(
                        async move {
                            let _guard = guard;
                            let _ = began.send(());
                            connection_stage(
                                std::future::pending::<std::io::Result<()>>(),
                                Duration::from_secs(10),
                                resolving,
                            )
                            .await
                        },
                        &mut stop,
                        &mut closed,
                    )
                    .await
                });
                started.await.unwrap();
                if explicit_close {
                    closer.send(true).unwrap();
                } else {
                    sender.send(true).unwrap();
                }
                assert_eq!(
                    tokio::time::timeout(Duration::from_secs(1), task)
                        .await
                        .unwrap()
                        .unwrap(),
                    ("stopped", None)
                );
                assert!(ended.load(std::sync::atomic::Ordering::SeqCst));
            }
        }
    }
    #[tokio::test]
    async fn failure_survives_summary_disk_reload_and_stop_clears_it() {
        let capture = temporary();
        let record = record();
        let id = record.id;
        capture.history.lock().unwrap().records.insert(id, record);
        capture
            .finish(id, "failed", Some(TcpFailure::ConnectionRefused))
            .await;
        assert_eq!(
            capture.summaries().await[0].failure,
            Some(TcpFailure::ConnectionRefused)
        );
        let loaded = TcpCapture::load(capture.directory.clone());
        assert_eq!(
            loaded.records().await[0].failure,
            Some(TcpFailure::ConnectionRefused)
        );
        assert!(loaded.records().await[0].durable);
        capture
            .finish(id, "stopped", Some(TcpFailure::RelayFailed))
            .await;
        assert_eq!(capture.detail(id).await.unwrap().unwrap().failure, None);
        assert_eq!(
            TcpCapture::load(capture.directory.clone()).records().await[0].failure,
            None
        );
    }
    #[cfg(unix)]
    #[test]
    fn completed_directory_counts_survive_file_cache_churn() {
        let mut cache = SummaryCache::default();
        let mut directories = Vec::new();
        let mut largest = 0;
        for _ in 0..5 {
            let capture = temporary();
            std::fs::create_dir_all(&capture.directory).unwrap();
            for _ in 0..3 {
                let record = record();
                let path = capture.directory.join(format!("{}.json", record.id));
                crate::session::write_json(&path, &record).unwrap();
                largest = largest.max(std::fs::metadata(path).unwrap().len());
            }
            directories.push(capture.directory.clone());
        }
        // More files than the file cache and less budget than all sessions.
        // Completed directories must not compete with partially scanned files.
        let mut counts = Vec::new();
        for _ in 0..15 {
            let mut budget = largest * 2;
            counts = directories
                .iter()
                .map(|directory| {
                    stored_connection_count_cached(directory, &mut budget, &mut cache, 4)
                })
                .collect();
        }
        assert_eq!(counts, vec![Some(3); 5]);
        let mut budget = 0;
        for directory in &directories {
            assert_eq!(
                stored_connection_count_cached(directory, &mut budget, &mut cache, 4),
                Some(3)
            );
        }
        assert!(cache.files.len() <= 4);
        for directory in directories {
            std::fs::remove_dir_all(directory).unwrap();
        }
    }

    #[cfg(unix)]
    #[test]
    fn replacing_same_size_and_mtime_invalidates_cached_count() {
        let capture = temporary();
        std::fs::create_dir_all(&capture.directory).unwrap();
        let record = record();
        let path = capture.directory.join(format!("{}.json", record.id));
        crate::session::write_json(&path, &record).unwrap();
        assert_eq!(stored_connection_count(&capture.directory), Some(1));
        let original = std::fs::read_to_string(&path).unwrap();
        let modified = std::fs::metadata(&path).unwrap().modified().unwrap();
        let replacement = capture.directory.with_extension("replacement");
        let corrupt = original.replace("\"open\"", "\"oops\"");
        assert_ne!(corrupt, original);
        assert_eq!(corrupt.len(), original.len());
        std::fs::write(&replacement, corrupt).unwrap();
        std::fs::File::options()
            .write(true)
            .open(&replacement)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(modified))
            .unwrap();
        std::fs::rename(&replacement, &path).unwrap();
        assert_eq!(stored_connection_count(&capture.directory), None);
        std::fs::remove_dir_all(&capture.directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn stored_count_budget_resumes_and_cache_invalidates_after_change() {
        let capture = temporary();
        std::fs::create_dir_all(&capture.directory).unwrap();
        let mut total = 0;
        for _ in 0..3 {
            let record = record();
            let path = capture.directory.join(format!("{}.json", record.id));
            crate::session::write_json(&path, &record).unwrap();
            total += std::fs::metadata(path).unwrap().len();
        }
        assert_eq!(
            super::stored_connection_count(&capture.directory, &mut 0),
            None
        );
        assert_eq!(
            super::stored_connection_count(&capture.directory, &mut (total / 2)),
            None
        );
        assert_eq!(
            super::stored_connection_count(&capture.directory, &mut total),
            Some(3)
        );
        assert_eq!(
            super::stored_connection_count(&capture.directory, &mut 0),
            Some(3)
        );
        let path = std::fs::read_dir(&capture.directory)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        std::fs::write(&path, "corrupt").unwrap();
        assert_eq!(stored_connection_count(&capture.directory), None);
        std::fs::remove_dir_all(&capture.directory).unwrap();
    }

    #[test]
    fn stored_counts_stream_headers_and_do_not_change_history() {
        let capture = temporary();
        assert_eq!(stored_connection_count(&capture.directory), Some(0));
        std::fs::create_dir_all(&capture.directory).unwrap();
        let record = record();
        let path = capture.directory.join(format!("{}.json", record.id));
        crate::session::write_json(&path, &record).unwrap();
        let before = std::fs::read(&path).unwrap();
        assert_eq!(stored_connection_count(&capture.directory), Some(1));
        assert_eq!(std::fs::read(&path).unwrap(), before);
        // A preview can be skipped without constructing any TcpChunk values.
        let mut json = serde_json::to_value(&record).unwrap();
        json["chunks"] = serde_json::json!([{"data_base64": "A".repeat(350_000)}]);
        crate::session::write_json(&path, &json).unwrap();
        assert_eq!(stored_connection_count(&capture.directory), Some(1));
        std::fs::remove_dir_all(&capture.directory).unwrap();
    }

    #[test]
    fn stored_count_reports_unknown_for_corruption_or_oversize() {
        let capture = temporary();
        std::fs::create_dir_all(&capture.directory).unwrap();
        let record = record();
        let path = capture.directory.join(format!("{}.json", record.id));
        for content in [
            "not json".to_string(),
            "{}".to_string(),
            serde_json::json!({"id": Uuid::new_v4(), "started_at": Utc::now(), "status": "open"})
                .to_string(),
        ] {
            std::fs::write(&path, content).unwrap();
            assert_eq!(stored_connection_count(&capture.directory), None);
        }
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(MAX_RECORD_FILE_BYTES + 1).unwrap();
        assert_eq!(stored_connection_count(&capture.directory), None);
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert_eq!(stored_connection_count(&capture.directory), None);
        std::fs::remove_dir_all(&capture.directory).unwrap();
    }

    #[test]
    fn stored_count_limits_directory_work_and_preserves_records() {
        let capture = temporary();
        std::fs::create_dir_all(&capture.directory).unwrap();
        for _ in 0..MAX_CONNECTIONS {
            let record = record();
            crate::session::write_json(
                &capture.directory.join(format!("{}.json", record.id)),
                &record,
            )
            .unwrap();
        }
        assert_eq!(
            stored_connection_count(&capture.directory),
            Some(MAX_CONNECTIONS)
        );
        let record = record();
        crate::session::write_json(
            &capture.directory.join(format!("{}.json", record.id)),
            &record,
        )
        .unwrap();
        assert_eq!(stored_connection_count(&capture.directory), None);
        assert_eq!(
            std::fs::read_dir(&capture.directory).unwrap().count(),
            MAX_CONNECTIONS + 1
        );
        std::fs::remove_dir_all(&capture.directory).unwrap();
    }

    #[test]
    fn live_count_includes_open_records_and_marks_failed_load_unknown() {
        let capture = temporary();
        assert_eq!(capture.connection_count(), Some(0));
        let record = record();
        capture
            .history
            .lock()
            .unwrap()
            .records
            .insert(record.id, record);
        assert_eq!(capture.connection_count(), Some(1));
        capture.history.lock().unwrap().load_error = true;
        assert_eq!(capture.connection_count(), None);
    }

    #[tokio::test]
    async fn capture_caps_preserve_total_offsets_and_binary() {
        let capture = temporary();
        let record = record();
        let id = record.id;
        capture.history.lock().unwrap().records.insert(id, record);
        capture.capture(id, Direction::ClientToServer, &[0, 255, 13, 10]);
        capture.capture(id, Direction::ClientToServer, &vec![7; MAX_CAPTURE_BYTES]);
        capture.capture(id, Direction::ServerToClient, &[8, 9]);
        let records = capture.records().await;
        let record = &records[0];
        assert_eq!(record.client_bytes, MAX_CAPTURE_BYTES as u64 + 4);
        assert_eq!(record.server_bytes, 2);
        assert_eq!(record.captured_bytes, MAX_CAPTURE_BYTES);
        assert!(record.capture_truncated);
        assert_eq!(
            STANDARD.decode(&record.chunks[0].data_base64).unwrap(),
            [0, 255, 13, 10]
        );
        assert_eq!(record.chunks[1].offset, 4);
    }
    #[tokio::test]
    async fn pump_preserves_half_close_and_large_binary_stream() {
        let capture = temporary();
        let record = record();
        let id = record.id;
        capture.history.lock().unwrap().records.insert(id, record);
        // Small duplex buffers force partial writes and backpressure.
        let (mut sender, input) = tokio::io::duplex(31);
        let (output, mut receiver) = tokio::io::duplex(17);
        let copy = capture.clone();
        let pump = tokio::spawn(async move {
            copy.pump(id, Direction::ClientToServer, input, output)
                .await
                .unwrap();
        });
        let payload: Vec<u8> = (0..500_000).map(|n| (n % 256) as u8).collect();
        let expected = payload.clone();
        let sending = tokio::spawn(async move {
            for part in payload.chunks(73) {
                sender.write_all(part).await.unwrap();
            }
            sender.shutdown().await.unwrap();
        });
        let mut received = vec![];
        receiver.read_to_end(&mut received).await.unwrap();
        sending.await.unwrap();
        pump.await.unwrap();
        assert_eq!(received, expected);
        assert_eq!(capture.records().await[0].client_bytes, 500_000);
    }
    #[tokio::test]
    async fn terminal_history_survives_reload_and_live_history_is_interrupted() {
        let capture = temporary();
        let record = record();
        let id = record.id;
        capture
            .history
            .lock()
            .unwrap()
            .records
            .insert(id, record.clone());
        assert!(capture.persist(&record).await);
        let reload = TcpCapture::load(capture.directory.clone());
        assert_eq!(reload.records().await[0].status, "interrupted");
        assert!(reload.records().await[0].capture_truncated);
        // Recovery must not invent a shutdown timestamp (or a live duration).
        assert!(reload.records().await[0].ended_at.is_none());
        capture.capture(id, Direction::ServerToClient, &[0, 128]);
        capture.finish(id, "closed", None).await;
        let reload = TcpCapture::load(capture.directory.clone());
        let records = reload.records().await;
        assert_eq!(records[0].status, "closed");
        assert!(records[0].durable);
        assert_eq!(
            STANDARD.decode(&records[0].chunks[0].data_base64).unwrap(),
            [0, 128]
        );
        std::fs::remove_dir_all(&capture.directory).unwrap();
    }
    #[tokio::test]
    async fn full_history_never_evicts_existing_records() {
        let capture = temporary();
        for _ in 0..MAX_CONNECTIONS {
            let record = record();
            capture
                .history
                .lock()
                .unwrap()
                .records
                .insert(record.id, record);
        }
        // A full history still starts: it relays without recording.
        capture.start(loopback(free_port(), 1)).await.unwrap();
        assert_eq!(capture.records().await.len(), MAX_CONNECTIONS);
        capture.stop().await.unwrap();
    }
    #[tokio::test]
    async fn stopped_receiver_is_immediately_observed() {
        let (sender, mut receiver) = watch::channel(false);
        sender.send(true).unwrap();
        tokio::time::timeout(Duration::from_millis(100), wait_stop(&mut receiver))
            .await
            .unwrap();
    }
    #[tokio::test]
    async fn loopback_relay_keeps_response_after_client_half_close() {
        let capture = temporary();
        let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let target_port = upstream.local_addr().unwrap().port();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let settings = TcpSettings {
            local_port: address.port(),
            target_host: "127.0.0.1".into(),
            target_port,
            ..Default::default()
        };
        let (stop, receiver) = watch::channel(false);
        let copy = capture.clone();
        let relay = tokio::spawn(async move {
            copy.serve(listener, settings, Default::default(), receiver)
                .await;
        });
        let server = tokio::spawn(async move {
            let (mut socket, _) = upstream.accept().await.unwrap();
            let mut request = vec![];
            socket.read_to_end(&mut request).await.unwrap();
            assert_eq!(request, [0, 255, 13, 10]);
            tokio::task::yield_now().await;
            socket.write_all(&[128, 0, 9]).await.unwrap();
            socket.shutdown().await.unwrap();
        });
        let mut client = TcpStream::connect(address).await.unwrap();
        client.write_all(&[0, 255]).await.unwrap();
        client.write_all(&[13, 10]).await.unwrap();
        client.shutdown().await.unwrap();
        let mut response = vec![];
        tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response, [128, 0, 9]);
        server.await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if capture
                    .records()
                    .await
                    .iter()
                    .any(|r| r.status == "closed" && r.durable)
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        stop.send(true).unwrap();
        relay.await.unwrap();
        let records = capture.records().await;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].client_bytes, 4);
        assert_eq!(records[0].server_bytes, 3);
        std::fs::remove_dir_all(&capture.directory).unwrap();
    }
    #[test]
    fn mapped_loopback_is_rejected_as_a_self_target() {
        for ip in ["127.0.0.1", "::1", "::ffff:127.0.0.1"] {
            assert!(is_loopback(ip.parse().unwrap()));
        }
        assert!(!is_loopback("192.0.2.1".parse().unwrap()));
    }
    #[tokio::test]
    async fn cancelled_stop_retains_the_join_owner() {
        let capture = temporary();
        let id = Uuid::new_v4();
        let (release, blocked) = tokio::sync::oneshot::channel::<()>();
        let (stop, _receiver) = watch::channel(false);
        let task = tokio::spawn(async move {
            let _ = blocked.await;
        });
        capture.running.lock().await.insert(
            id,
            Running {
                refused: Default::default(),
                stop,
                task,
            },
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(20), capture.stop())
                .await
                .is_err()
        );
        assert!(capture.running.lock().await.contains_key(&id));
        release.send(()).unwrap();
        capture.stop().await.unwrap();
        assert!(capture.running.lock().await.is_empty());
    }
    #[tokio::test]
    async fn completed_listener_can_restart_but_concurrent_starts_cannot_overlap() {
        let capture = temporary();
        let id = Uuid::new_v4();
        let probe = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let settings = TcpSettings {
            local_port: port,
            target_host: "127.0.0.1".into(),
            target_port: 1,
            ..Default::default()
        };
        let (stop, _receiver) = watch::channel(false);
        // Model the completed owner left behind when serve exits on accept failure.
        let task = tokio::spawn(async {});
        tokio::time::timeout(Duration::from_secs(5), async {
            while !task.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        capture.running.lock().await.insert(
            id,
            Running {
                refused: Default::default(),
                stop,
                task,
            },
        );
        assert!(!capture.status().await.enabled);
        let (first, second) = tokio::join!(
            capture.start_listener(id, settings.clone()),
            capture.start_listener(id, settings)
        );
        assert_ne!(first.is_ok(), second.is_ok());
        assert!(capture.status().await.enabled);
        capture.stop().await.unwrap();
        assert!(capture.running.lock().await.is_empty());
    }
    #[tokio::test]
    async fn start_does_not_reap_an_unfinished_worker_after_cancelled_stop() {
        let capture = temporary();
        let id = Uuid::new_v4();
        let settings = TcpSettings {
            local_port: 19999,
            target_host: "127.0.0.1".into(),
            target_port: 19998,
            ..Default::default()
        };
        let (release, blocked) = tokio::sync::oneshot::channel::<()>();
        let (stop, _receiver) = watch::channel(false);
        let task = tokio::spawn(async move {
            let _ = blocked.await;
        });
        capture.running.lock().await.insert(
            id,
            Running {
                refused: Default::default(),
                stop,
                task,
            },
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(20), capture.stop())
                .await
                .is_err()
        );
        assert!(capture.start_listener(id, settings).await.is_err());
        assert!(capture.running.lock().await.contains_key(&id));
        release.send(()).unwrap();
        capture.stop().await.unwrap();
        assert!(capture.running.lock().await.is_empty());
    }
    #[test]
    fn listener_host_syntax_and_labels() {
        for host in ["::1", "[::1]", "[0:0:0:0:0:0:0:1]"] {
            let mut settings = TcpSettings {
                local_port: 9000,
                target_host: host.into(),
                target_port: 9100,
                ..Default::default()
            };
            settings.validate().unwrap();
            settings.target_host = settings.normalized_host().unwrap();
            assert_eq!(settings.target_host, "::1");
            assert_eq!(settings.target_label(), "[::1]:9100");
        }
        for host in [
            "localhost:1234",
            "127.0.0.1:80",
            "[::1]:80",
            "[localhost]",
            "[::1",
            "::1]",
            "[[::1]]",
            "fe80::1%eth0",
        ] {
            let settings = TcpSettings {
                local_port: 9000,
                target_host: host.into(),
                target_port: 9100,
                ..Default::default()
            };
            assert!(settings.validate().is_err(), "{host}");
        }
    }
    #[tokio::test]
    async fn active_admission_status_counts_slots_and_queues_extra_connection() {
        let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let target_port = upstream.local_addr().unwrap().port();
        let probe = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let local_port = probe.local_addr().unwrap().port();
        drop(probe);
        let capture = temporary();
        enable(&capture);
        assert_eq!(capture.status().await.active_count, 0);
        capture
            .start(TcpSettings {
                local_port,
                target_host: "127.0.0.1".into(),
                target_port,
                ..Default::default()
            })
            .await
            .unwrap();
        let mut clients = vec![];
        let mut servers = vec![];
        for _ in 0..MAX_ACTIVE {
            let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, local_port))
                .await
                .unwrap();
            client.write_all(b"held").await.unwrap();
            clients.push(client);
            servers.push(
                tokio::time::timeout(Duration::from_secs(3), upstream.accept())
                    .await
                    .unwrap()
                    .unwrap()
                    .0,
            );
        }
        tokio::time::timeout(Duration::from_secs(3), async {
            while capture.policy().paused_count != MAX_ACTIVE {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let status = capture.status().await;
        assert_eq!(
            (status.active_count, status.active_limit),
            (MAX_ACTIVE, MAX_ACTIVE)
        );
        let mut extra = TcpStream::connect((Ipv4Addr::LOCALHOST, local_port))
            .await
            .unwrap();
        extra.write_all(b"queued").await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(30), upstream.accept())
                .await
                .is_err()
        );
        assert_eq!(capture.records().await.len(), MAX_ACTIVE);
        let first = capture.records().await[0].id;
        capture.close(first).unwrap();
        servers.push(
            tokio::time::timeout(Duration::from_secs(3), upstream.accept())
                .await
                .unwrap()
                .unwrap()
                .0,
        );
        tokio::time::timeout(Duration::from_secs(3), async {
            while capture.records().await.len() != MAX_ACTIVE + 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(capture.status().await.active_count, MAX_ACTIVE);
        capture.stop().await.unwrap();
        assert_eq!(capture.status().await.active_count, 0);
        assert_eq!(capture.policy().pending_count, 0);
        assert!(capture.records().await.iter().all(|r| r.client_bytes == 0));
        // Reloaded/session-local runtime starts with no occupied slots or policy state.
        let loaded = TcpCapture::load(capture.directory.clone());
        assert_eq!(loaded.status().await.active_count, 0);
        assert_eq!(loaded.policy().forwarding_count, 0);
    }
    #[tokio::test]
    async fn occupied_listener_port_is_actionable_and_does_not_start() {
        let occupied = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let local_port = occupied.local_addr().unwrap().port();
        let capture = temporary();
        let error = capture
            .start(TcpSettings {
                local_port,
                target_host: "127.0.0.1".into(),
                target_port: 1,
                ..Default::default()
            })
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), format!("Local port {local_port} is already in use. Choose another Local port or stop the listener using it."));
        assert!(capture.running.lock().await.is_empty());
    }
    #[tokio::test]
    async fn bracketed_ipv6_start_relays_actual_loopback_bytes() {
        let upstream = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).await.unwrap();
        let target_port = upstream.local_addr().unwrap().port();
        let probe = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let local_port = probe.local_addr().unwrap().port();
        drop(probe);
        let capture = temporary();
        capture
            .add_listener(TcpListenerInput {
                enabled: true,
                settings: TcpSettings {
                    local_port,
                    target_host: "[::1]".into(),
                    target_port,
                    ..Default::default()
                },
            })
            .await
            .unwrap();
        assert_eq!(capture.listener_configs()[0].settings.target_host, "::1");
        let server = tokio::spawn(async move {
            let (mut socket, _) = upstream.accept().await.unwrap();
            let mut bytes = [0; 3];
            socket.read_exact(&mut bytes).await.unwrap();
            socket.write_all(&bytes).await.unwrap();
        });
        let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, local_port))
            .await
            .unwrap();
        client.write_all(&[0, 255, 42]).await.unwrap();
        let mut bytes = [0; 3];
        tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(bytes, [0, 255, 42]);
        server.await.unwrap();
        capture.stop().await.unwrap();
        assert_eq!(
            capture.records().await[0].target,
            format!("[::1]:{target_port}")
        );
    }
    #[test]
    fn rejects_invalid_ports_and_hosts() {
        assert!(TcpSettings {
            local_port: 0,
            target_host: "127.0.0.1".into(),
            target_port: 12,
            ..Default::default()
        }
        .validate()
        .is_err());
        assert!(TcpSettings {
            local_port: 12,
            target_host: "http://example.com".into(),
            target_port: 12,
            ..Default::default()
        }
        .validate()
        .is_err());
    }
    fn enable(capture: &TcpCapture) {
        capture
            .set_policy(PolicyUpdate {
                enabled: true,
                direction: PolicyDirection::Both,
                expected_revision: 0,
                filter: None,
            })
            .unwrap();
    }
    async fn wait_pending(capture: &TcpCapture, id: Uuid, n: usize) -> Vec<InterceptEvent> {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let items = capture.pending(id).unwrap().items;
                if items.len() == n {
                    return items;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap()
    }
    async fn wait_written(capture: &TcpCapture, id: Uuid, n: usize) {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if capture
                    .pending(id)
                    .unwrap()
                    .items
                    .first()
                    .map(|p| p.written_bytes)
                    == Some(n)
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
    fn setup_intercept() -> (Arc<TcpCapture>, Uuid) {
        let capture = temporary();
        let record = record();
        let id = record.id;
        capture.history.lock().unwrap().records.insert(id, record);
        enable(&capture);
        (capture, id)
    }
    #[tokio::test]
    async fn intercept_holds_binary_and_forwards_edited_bytes_only_once() {
        let (capture, id) = setup_intercept();
        let (mut client, input) = tokio::io::duplex(128);
        let (output, mut server) = tokio::io::duplex(128);
        let copy = capture.clone();
        let pump = tokio::spawn(async move {
            copy.pump(id, Direction::ClientToServer, input, output)
                .await
        });
        client.write_all(&[0, 255, 13, 10, 128]).await.unwrap();
        let item = wait_pending(&capture, id, 1).await.remove(0);
        assert_eq!(
            STANDARD.decode(item.original_base64.unwrap()).unwrap(),
            [0, 255, 13, 10, 128]
        );
        let mut byte = [0];
        assert!(
            tokio::time::timeout(Duration::from_millis(20), server.read(&mut byte))
                .await
                .is_err()
        );
        assert_eq!(capture.detail(id).await.unwrap().unwrap().client_bytes, 0);
        let edited = [254, 0, 10, 13, 1];
        let result = capture
            .decide(
                id,
                item.pending_id,
                DecisionRequest {
                    action: DecisionAction::Forward,
                    replacement_base64: Some(STANDARD.encode(edited)),
                    expected_revision: 0,
                },
            )
            .await
            .unwrap();
        assert_eq!(result.state, "forwarding");
        let duplicate = capture
            .decide(
                id,
                item.pending_id,
                DecisionRequest {
                    action: DecisionAction::Forward,
                    replacement_base64: None,
                    expected_revision: 0,
                },
            )
            .await;
        assert!(matches!(duplicate, Err(InterceptError::Conflict(_))));
        client.shutdown().await.unwrap();
        let mut bytes = vec![];
        server.read_to_end(&mut bytes).await.unwrap();
        pump.await.unwrap().unwrap();
        assert_eq!(bytes, edited);
        assert!(resident_preview_bytes(&capture) > 0);
        capture.finish(id, "closed", None).await;
        assert_eq!(resident_preview_bytes(&capture), 0);
        let record = capture.detail(id).await.unwrap().unwrap();
        assert_eq!(record.client_received_bytes, 5);
        assert_eq!(record.client_bytes, 5);
        assert_eq!(record.intercept_events[0].state, "forwarded");
        assert_eq!(record.intercept_events[0].written_bytes, 5);
        let loaded = TcpCapture::load(capture.directory.clone());
        let saved = loaded.detail(id).await.unwrap().unwrap();
        assert_eq!(resident_preview_bytes(&loaded), 0);
        assert_eq!(
            serde_json::to_value(&saved).unwrap(),
            serde_json::to_value(&record).unwrap()
        );
        assert!(!loaded.status().await.load_error);
        assert_eq!(
            saved.intercept_events[0].selected_base64,
            Some(STANDARD.encode(edited))
        );
        assert!(!loaded.policy().enabled);
    }
    #[tokio::test]
    async fn intercept_off_does_not_release_pending_and_drop_allows_next_read() {
        let (capture, id) = setup_intercept();
        let (mut client, input) = tokio::io::duplex(128);
        let (output, mut server) = tokio::io::duplex(128);
        let copy = capture.clone();
        let pump = tokio::spawn(async move {
            copy.pump(id, Direction::ClientToServer, input, output)
                .await
        });
        client.write_all(b"drop").await.unwrap();
        let item = wait_pending(&capture, id, 1).await.remove(0);
        capture
            .set_policy(PolicyUpdate {
                enabled: false,
                direction: PolicyDirection::Both,
                expected_revision: 1,
                filter: None,
            })
            .unwrap();
        assert_eq!(capture.policy().pending_count, 1);
        assert_eq!(capture.policy().paused_count, 1);
        assert_eq!(capture.policy().forwarding_count, 0);
        let mut byte = [0];
        assert!(
            tokio::time::timeout(Duration::from_millis(20), server.read(&mut byte))
                .await
                .is_err()
        );
        capture
            .decide(
                id,
                item.pending_id,
                DecisionRequest {
                    action: DecisionAction::Drop,
                    replacement_base64: None,
                    expected_revision: 0,
                },
            )
            .await
            .unwrap();
        client.write_all(b"next").await.unwrap();
        client.shutdown().await.unwrap();
        let mut bytes = vec![];
        server.read_to_end(&mut bytes).await.unwrap();
        pump.await.unwrap().unwrap();
        assert_eq!(bytes, b"next");
        let record = capture.detail(id).await.unwrap().unwrap();
        assert_eq!(record.client_received_bytes, 8);
        assert_eq!(record.client_bytes, 4);
        assert_eq!(record.intercept_events[0].state, "dropped");
        assert_eq!(record.intercept_events[0].written_bytes, 0);
    }
    #[tokio::test]
    async fn intercepted_partial_write_cancellation_keeps_exact_prefix_and_original() {
        let (capture, id) = setup_intercept();
        let (mut client, input) = tokio::io::duplex(128);
        let (output, _server) = tokio::io::duplex(3);
        let copy = capture.clone();
        let pump = tokio::spawn(async move {
            copy.pump(id, Direction::ClientToServer, input, output)
                .await
        });
        client.write_all(b"original").await.unwrap();
        let item = wait_pending(&capture, id, 1).await.remove(0);
        capture
            .decide(
                id,
                item.pending_id,
                DecisionRequest {
                    action: DecisionAction::Forward,
                    replacement_base64: Some(STANDARD.encode(b"replacement")),
                    expected_revision: 0,
                },
            )
            .await
            .unwrap();
        wait_written(&capture, id, 3).await;
        let policy = capture
            .set_policy(PolicyUpdate {
                enabled: false,
                direction: PolicyDirection::Both,
                expected_revision: 1,
                filter: None,
            })
            .unwrap();
        assert_eq!(
            (
                policy.pending_count,
                policy.paused_count,
                policy.forwarding_count
            ),
            (1, 0, 1)
        );
        assert_eq!(capture.policy().forwarding_count, 1);
        pump.abort();
        let _ = pump.await;
        capture.finish(id, "stopped", None).await;
        let record = capture.detail(id).await.unwrap().unwrap();
        assert_eq!(record.client_bytes, 3);
        assert_eq!(
            STANDARD.decode(&record.chunks[0].data_base64).unwrap(),
            b"rep"
        );
        let event = &record.intercept_events[0];
        assert_eq!(event.state, "cancelled");
        assert_eq!(event.written_bytes, 3);
        assert_eq!(event.selected_length, 11);
        assert_eq!(event.original_base64, Some(STANDARD.encode(b"original")));
        assert_eq!(capture.policy().pending_count, 0);
    }
    #[tokio::test]
    async fn dropped_decision_response_does_not_undo_owner_acceptance() {
        let (capture, id) = setup_intercept();
        let (mut client, input) = tokio::io::duplex(128);
        let (output, mut server) = tokio::io::duplex(128);
        let copy = capture.clone();
        let pump = tokio::spawn(async move {
            copy.pump(id, Direction::ClientToServer, input, output)
                .await
        });
        client.write_all(b"once").await.unwrap();
        let item = wait_pending(&capture, id, 1).await.remove(0);
        // Submit exactly like an HTTP handler then drop its response receiver.
        let (ack, receiver) = tokio::sync::oneshot::channel();
        capture.intercept.lock().unwrap().pending[&item.pending_id]
            .sender
            .try_send(SubmittedDecision {
                request: DecisionRequest {
                    action: DecisionAction::Forward,
                    replacement_base64: None,
                    expected_revision: 0,
                },
                selected: None,
                ack,
            })
            .unwrap();
        drop(receiver);
        client.shutdown().await.unwrap();
        let mut bytes = vec![];
        server.read_to_end(&mut bytes).await.unwrap();
        pump.await.unwrap().unwrap();
        assert_eq!(bytes, b"once");
        assert_eq!(
            capture
                .detail(id)
                .await
                .unwrap()
                .unwrap()
                .intercept_events
                .len(),
            1
        );
    }
    #[tokio::test]
    async fn intercept_validates_revisions_and_replacement_before_queueing() {
        let (capture, id) = setup_intercept();
        let (ticket, _rx) = capture
            .admit(id, Direction::ClientToServer, b"test")
            .unwrap();
        assert!(capture
            .set_policy(PolicyUpdate {
                enabled: false,
                direction: PolicyDirection::Both,
                expected_revision: 0,
                filter: None,
            })
            .is_err());
        for (action, replacement, revision) in [
            (DecisionAction::Forward, Some("".into()), 0),
            (DecisionAction::Forward, Some("@@".into()), 0),
            (DecisionAction::Drop, Some("dA==".into()), 0),
            (DecisionAction::Forward, None, 1),
            (
                DecisionAction::Forward,
                Some(STANDARD.encode(vec![0; MAX_PENDING_BYTES + 1])),
                0,
            ),
        ] {
            assert!(capture
                .decide(
                    id,
                    ticket,
                    DecisionRequest {
                        action,
                        replacement_base64: replacement,
                        expected_revision: revision
                    }
                )
                .await
                .is_err());
        }
        assert_eq!(capture.pending(id).unwrap().items[0].state, "pending");
    }
    #[tokio::test]
    async fn intercept_history_cap_and_corrupt_load_fail_closed() {
        let (capture, id) = setup_intercept();
        for _ in 0..MAX_EVENTS + 2 {
            let (ticket, _rx) = capture
                .admit(id, Direction::ClientToServer, &vec![1; MAX_PENDING_BYTES])
                .unwrap();
            capture.end_range(ticket, "cancelled");
        }
        capture.finish(id, "closed", None).await;
        let record = capture.detail(id).await.unwrap().unwrap();
        assert_eq!(record.intercept_events.len(), MAX_EVENTS);
        assert_eq!(record.intercept_captured_bytes, MAX_EVENT_BYTES);
        assert!(record.intercept_truncated);
        assert_eq!(record.intercept_event_count, (MAX_EVENTS + 2) as u64);
        let loaded = TcpCapture::load(capture.directory.clone());
        assert!(!loaded.status().await.load_error);
        let mut corrupt = record;
        corrupt.intercept_events[0].written_bytes = MAX_PENDING_BYTES + 1;
        crate::session::write_json(&capture.directory.join(format!("{id}.json")), &corrupt)
            .unwrap();
        assert!(
            TcpCapture::load(capture.directory.clone())
                .status()
                .await
                .load_error
        );
    }
    #[tokio::test]
    async fn loopback_intercept_full_duplex_half_close_and_direction_changes() {
        let capture = temporary();
        enable(&capture);
        let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let settings = TcpSettings {
            local_port: address.port(),
            target_host: "127.0.0.1".into(),
            target_port: upstream.local_addr().unwrap().port(),
            ..Default::default()
        };
        let (stop, rx) = watch::channel(false);
        let copy = capture.clone();
        let relay =
            tokio::spawn(
                async move { copy.serve(listener, settings, Default::default(), rx).await },
            );
        let mut client = TcpStream::connect(address).await.unwrap();
        let (mut server, _) = upstream.accept().await.unwrap();
        client.write_all(b"client").await.unwrap();
        server.write_all(b"server").await.unwrap();
        client.shutdown().await.unwrap();
        let id = capture.records().await[0].id;
        let items = wait_pending(&capture, id, 2).await;
        assert_eq!(capture.policy().pending_count, 2);
        capture
            .set_policy(PolicyUpdate {
                enabled: true,
                direction: PolicyDirection::ServerToClient,
                expected_revision: 1,
                filter: None,
            })
            .unwrap();
        // Direction changes cannot release either already-held range.
        assert_eq!(capture.pending(id).unwrap().items.len(), 2);
        for item in items {
            capture
                .decide(
                    id,
                    item.pending_id,
                    DecisionRequest {
                        action: if item.direction == Direction::ClientToServer {
                            DecisionAction::Forward
                        } else {
                            DecisionAction::Drop
                        },
                        replacement_base64: None,
                        expected_revision: 0,
                    },
                )
                .await
                .unwrap();
        }
        let mut received = vec![];
        tokio::time::timeout(Duration::from_secs(3), server.read_to_end(&mut received))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received, b"client");
        server.write_all(b"reply").await.unwrap();
        server.shutdown().await.unwrap();
        let item = wait_pending(&capture, id, 1).await.remove(0);
        assert_eq!(item.direction, Direction::ServerToClient);
        capture
            .decide(
                id,
                item.pending_id,
                DecisionRequest {
                    action: DecisionAction::Forward,
                    replacement_base64: None,
                    expected_revision: 0,
                },
            )
            .await
            .unwrap();
        let mut response = vec![];
        tokio::time::timeout(Duration::from_secs(3), client.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response, b"reply");
        stop.send(true).unwrap();
        relay.await.unwrap();
        let record = capture.detail(id).await.unwrap().unwrap();
        assert_eq!(record.client_bytes, 6);
        assert_eq!(record.server_bytes, 5);
        assert_eq!(record.server_received_bytes, 11);
        assert_eq!(record.intercept_events.len(), 3);
        assert_eq!(capture.policy().pending_count, 0);
    }
    #[tokio::test]
    async fn loopback_close_and_stop_drain_pending_without_forwarding() {
        for explicit_close in [false, true] {
            let capture = temporary();
            enable(&capture);
            let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let address = listener.local_addr().unwrap();
            let settings = TcpSettings {
                local_port: address.port(),
                target_host: "127.0.0.1".into(),
                target_port: upstream.local_addr().unwrap().port(),
                ..Default::default()
            };
            let (stop, rx) = watch::channel(false);
            let copy = capture.clone();
            let relay = tokio::spawn(async move {
                copy.serve(listener, settings, Default::default(), rx).await
            });
            let mut client = TcpStream::connect(address).await.unwrap();
            let (mut server, _) = upstream.accept().await.unwrap();
            client.write_all(b"held").await.unwrap();
            server.write_all(b"also held").await.unwrap();
            let id = capture.records().await[0].id;
            wait_pending(&capture, id, 2).await;
            if explicit_close {
                capture.close(id).unwrap();
            } else {
                stop.send(true).unwrap();
            }
            let mut bytes = vec![];
            tokio::time::timeout(Duration::from_secs(3), server.read_to_end(&mut bytes))
                .await
                .unwrap()
                .unwrap();
            assert!(bytes.is_empty());
            let _ = stop.send(true);
            relay.await.unwrap();
            let record = capture.detail(id).await.unwrap().unwrap();
            assert_eq!(record.client_bytes, 0);
            assert_eq!(record.server_bytes, 0);
            assert_eq!(record.status, "stopped");
            assert_eq!(record.failure, None);
            assert_eq!(record.intercept_events.len(), 2);
            assert!(record
                .intercept_events
                .iter()
                .all(|e| e.state == "cancelled" && e.written_bytes == 0));
            assert_eq!(capture.policy().pending_count, 0);
            assert!(capture.intercept.lock().unwrap().connections.is_empty());
            assert!(record.durable);
        }
    }
    #[tokio::test]
    async fn intercept_offsets_follow_received_and_delivered_independently_with_duplicate_race() {
        let (capture, id) = setup_intercept();
        let (mut client, input) = tokio::io::duplex(128);
        let (output, mut server) = tokio::io::duplex(128);
        let copy = capture.clone();
        let pump = tokio::spawn(async move {
            copy.pump(id, Direction::ClientToServer, input, output)
                .await
        });
        for (input, action, replacement) in [
            (
                &b"abc"[..],
                DecisionAction::Forward,
                Some(STANDARD.encode(b"12345")),
            ),
            (&b"drop"[..], DecisionAction::Drop, None),
        ] {
            client.write_all(input).await.unwrap();
            let item = wait_pending(&capture, id, 1).await.remove(0);
            capture
                .decide(
                    id,
                    item.pending_id,
                    DecisionRequest {
                        action,
                        replacement_base64: replacement,
                        expected_revision: 0,
                    },
                )
                .await
                .unwrap();
            wait_pending(&capture, id, 0).await;
        }
        client.write_all(b"z").await.unwrap();
        let item = wait_pending(&capture, id, 1).await.remove(0);
        let request = || DecisionRequest {
            action: DecisionAction::Forward,
            replacement_base64: None,
            expected_revision: 0,
        };
        let (a, b) = tokio::join!(
            capture.decide(id, item.pending_id, request()),
            capture.decide(id, item.pending_id, request())
        );
        assert_ne!(a.is_ok(), b.is_ok());
        client.shutdown().await.unwrap();
        let mut bytes = vec![];
        server.read_to_end(&mut bytes).await.unwrap();
        pump.await.unwrap().unwrap();
        assert_eq!(bytes, b"12345z");
        let record = capture.detail(id).await.unwrap().unwrap();
        assert_eq!(
            record
                .intercept_events
                .iter()
                .map(|e| (e.original_offset, e.destination_offset, e.written_bytes))
                .collect::<Vec<_>>(),
            vec![(0, 0, 5), (3, 5, 0), (7, 5, 1)]
        );
    }
    #[tokio::test]
    async fn intercepted_write_error_retains_successful_prefix() {
        let (capture, id) = setup_intercept();
        let (mut client, input) = tokio::io::duplex(128);
        let (output, server) = tokio::io::duplex(3);
        let copy = capture.clone();
        let pump = tokio::spawn(async move {
            copy.pump(id, Direction::ClientToServer, input, output)
                .await
        });
        client.write_all(b"abcdef").await.unwrap();
        let item = wait_pending(&capture, id, 1).await.remove(0);
        capture
            .decide(
                id,
                item.pending_id,
                DecisionRequest {
                    action: DecisionAction::Forward,
                    replacement_base64: None,
                    expected_revision: 0,
                },
            )
            .await
            .unwrap();
        wait_written(&capture, id, 3).await;
        drop(server);
        assert!(pump.await.unwrap().is_err());
        capture
            .finish(id, "failed", Some(TcpFailure::RelayFailed))
            .await;
        let record = capture.detail(id).await.unwrap().unwrap();
        assert_eq!(record.failure, Some(TcpFailure::RelayFailed));
        assert_eq!(record.client_bytes, 3);
        assert_eq!(record.intercept_events[0].written_bytes, 3);
        assert_eq!(record.intercept_events[0].state, "failed");
        assert_eq!(record.intercept_events[0].selected_length, 6);
    }

    async fn echo_server() -> u16 {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buffer = [0; 1024];
                    while let Ok(read @ 1..) = socket.read(&mut buffer).await {
                        if socket.write_all(&buffer[..read]).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        port
    }
    fn free_port() -> u16 {
        std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }
    fn loopback(local_port: u16, target_port: u16) -> TcpSettings {
        TcpSettings {
            local_port,
            target_host: "127.0.0.1".into(),
            target_port,
            ..Default::default()
        }
    }
    async fn echo_through(local_port: u16, bytes: &[u8]) -> Vec<u8> {
        let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, local_port))
            .await
            .unwrap();
        client.write_all(bytes).await.unwrap();
        let mut back = vec![0; bytes.len()];
        tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut back))
            .await
            .unwrap()
            .unwrap();
        back
    }
    #[tokio::test]
    async fn two_listeners_relay_at_once_and_name_their_port() {
        let (first_target, second_target) = (echo_server().await, echo_server().await);
        let (first, second) = (free_port(), free_port());
        let capture = temporary();
        for (local, target) in [(first, first_target), (second, second_target)] {
            capture
                .add_listener(TcpListenerInput {
                    enabled: true,
                    settings: loopback(local, target),
                })
                .await
                .unwrap();
        }
        assert_eq!(echo_through(first, b"one").await, b"one");
        assert_eq!(echo_through(second, b"two").await, b"two");
        assert!(capture.status().await.listeners.iter().all(|l| l.running));
        capture.stop().await.unwrap();
        let mut seen: Vec<_> = capture
            .records()
            .await
            .into_iter()
            .map(|record| (record.local_port, record.target))
            .collect();
        seen.sort();
        let mut expected = vec![
            (first, format!("127.0.0.1:{first_target}")),
            (second, format!("127.0.0.1:{second_target}")),
        ];
        expected.sort();
        assert_eq!(seen, expected);
        assert!(capture.status().await.listeners.iter().all(|l| !l.running));
    }
    #[tokio::test]
    async fn saved_listeners_start_again_and_a_taken_port_keeps_its_error() {
        let target = echo_server().await;
        let taken = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let taken_port = taken.local_addr().unwrap().port();
        let open_port = free_port();
        let saved = |local_port, enabled| TcpListenerConfig {
            id: Uuid::new_v4(),
            enabled,
            settings: loopback(local_port, target),
        };
        let (blocked, open, off) = (
            saved(taken_port, true),
            saved(open_port, true),
            saved(free_port(), false),
        );
        let capture = temporary();
        capture.restore_listeners(vec![blocked.clone(), open.clone(), off.clone()]);
        capture.start_saved().await;
        assert_eq!(echo_through(open_port, b"back").await, b"back");
        let status = capture.status().await;
        let find = |id| status.listeners.iter().find(|l| l.config.id == id).unwrap();
        assert!(!find(blocked.id).running);
        assert_eq!(
            find(blocked.id).error.as_deref(),
            Some(format!("Local port {taken_port} is already in use. Choose another Local port or stop the listener using it.").as_str())
        );
        assert!(find(open.id).running && find(open.id).error.is_none());
        assert!(!find(off.id).running && find(off.id).error.is_none());
        assert_eq!(capture.listener_configs(), vec![blocked, open, off]);
        capture.stop().await.unwrap();
        drop(taken);
    }
    #[tokio::test]
    async fn listeners_are_checked_changed_and_removed() {
        let capture = temporary();
        let port = free_port();
        let off = |local_port, target_port| TcpListenerInput {
            enabled: false,
            settings: loopback(local_port, target_port),
        };
        let id = capture.add_listener(off(port, 1)).await.unwrap();
        let error = capture.add_listener(off(port, 2)).await.unwrap_err();
        assert_eq!(
            error.to_string(),
            format!("Another listener already uses local port {port}.")
        );
        for extra in 1..MAX_LISTENERS {
            capture
                .add_listener(off(20000 + extra as u16, 1))
                .await
                .unwrap();
        }
        let error = capture.add_listener(off(30000, 1)).await.unwrap_err();
        assert_eq!(
            error.to_string(),
            format!("A session keeps at most {MAX_LISTENERS} TCP listeners.")
        );
        let target = echo_server().await;
        capture
            .update_listener(
                id,
                TcpListenerInput {
                    enabled: true,
                    settings: loopback(port, target),
                },
            )
            .await
            .unwrap();
        assert_eq!(echo_through(port, b"changed").await, b"changed");
        let saved = capture.listener_configs();
        assert!(saved[0].enabled && saved[0].settings.target_port == target);
        capture.remove_listener(id).await.unwrap();
        assert!(!capture.listener_configs().iter().any(|l| l.id == id));
        assert!(TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .is_err());
        let error = capture.remove_listener(id).await.unwrap_err();
        assert_eq!(error.to_string(), UNKNOWN_LISTENER);
    }
    #[test]
    fn a_record_saved_before_listeners_had_ports_still_loads() {
        let mut value = serde_json::to_value(record()).unwrap();
        value.as_object_mut().unwrap().remove("local_port");
        let loaded: TcpConnection = serde_json::from_value(value).unwrap();
        assert_eq!(loaded.local_port, 0);
    }
    async fn wait_saved(capture: &TcpCapture, count: usize) -> Vec<TcpConnection> {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let saved: Vec<_> = capture
                    .summaries()
                    .await
                    .into_iter()
                    .filter(|record| record.ended_at.is_some() && record.durable)
                    .collect();
                if saved.len() >= count {
                    return saved;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap()
    }
    #[tokio::test]
    async fn a_full_history_still_relays_and_counts_what_it_did_not_record() {
        let target = echo_server().await;
        let capture = temporary();
        {
            let mut history = capture.history.lock().unwrap();
            for _ in 0..MAX_CONNECTIONS {
                let mut saved = record();
                saved.status = "closed".into();
                saved.ended_at = Some(Utc::now());
                saved.durable = true;
                history.records.insert(saved.id, saved);
            }
        }
        let port = free_port();
        capture
            .add_listener(TcpListenerInput {
                enabled: true,
                settings: loopback(port, target),
            })
            .await
            .unwrap();
        assert_eq!(echo_through(port, b"still relayed").await, b"still relayed");
        let status = capture.status().await;
        assert_eq!(status.history_count, MAX_CONNECTIONS);
        assert_eq!(status.unrecorded_count, 1);
        capture.stop().await.unwrap();
    }
    #[tokio::test]
    async fn clearing_history_removes_ended_records_and_keeps_live_ones() {
        let target = echo_server().await;
        let capture = temporary();
        let port = free_port();
        capture
            .add_listener(TcpListenerInput {
                enabled: true,
                settings: loopback(port, target),
            })
            .await
            .unwrap();
        assert_eq!(echo_through(port, b"ended").await, b"ended");
        let ended = wait_saved(&capture, 1).await.remove(0);
        let mut live = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        live.write_all(b"live").await.unwrap();
        let mut back = [0; 4];
        live.read_exact(&mut back).await.unwrap();
        capture.unrecorded.store(3, Ordering::Relaxed);
        assert_eq!(capture.clear().await.unwrap(), 1);
        let left = capture.summaries().await;
        assert_eq!(left.len(), 1);
        assert!(left[0].ended_at.is_none());
        assert!(!capture
            .directory
            .join(format!("{}.json", ended.id))
            .exists());
        assert_eq!(capture.status().await.unrecorded_count, 0);
        assert_eq!(
            TcpCapture::load(capture.directory.clone()).connection_count(),
            Some(1)
        );
        drop(live);
        capture.stop().await.unwrap();
    }
    fn holding(capture: &TcpCapture, filter: Option<InterceptFilter>) {
        let expected_revision = capture.policy().revision;
        capture
            .set_policy(PolicyUpdate {
                enabled: true,
                direction: PolicyDirection::ClientToServer,
                expected_revision,
                filter,
            })
            .unwrap();
    }
    async fn wait_paused(capture: &TcpCapture, count: usize) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while capture.policy().paused_count < count {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }
    async fn send_to(port: u16, bytes: &[u8]) -> TcpStream {
        let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        client.write_all(bytes).await.unwrap();
        client
    }
    async fn read_back(client: &mut TcpStream, length: usize) -> Vec<u8> {
        let mut back = vec![0; length];
        tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut back))
            .await
            .unwrap()
            .unwrap();
        back
    }
    async fn relaying() -> (Arc<TcpCapture>, u16) {
        let target = echo_server().await;
        let capture = temporary();
        let port = free_port();
        capture
            .add_listener(TcpListenerInput {
                enabled: true,
                settings: loopback(port, target),
            })
            .await
            .unwrap();
        (capture, port)
    }
    async fn turn_off(capture: &TcpCapture) {
        let expected_revision = capture.policy().revision;
        capture
            .update_policy(PolicyUpdate {
                enabled: false,
                direction: PolicyDirection::Both,
                expected_revision,
                filter: None,
            })
            .await
            .unwrap();
    }
    #[tokio::test]
    async fn forward_all_and_turning_off_release_every_held_read() {
        let (capture, port) = relaying().await;
        holding(&capture, None);
        let (mut first, mut second) = (send_to(port, b"one").await, send_to(port, b"two").await);
        wait_paused(&capture, 2).await;
        assert_eq!(capture.release_all(DecisionAction::Forward).await, 2);
        assert_eq!(read_back(&mut first, 3).await, b"one");
        assert_eq!(read_back(&mut second, 3).await, b"two");
        let mut third = send_to(port, b"off").await;
        wait_paused(&capture, 1).await;
        turn_off(&capture).await;
        assert_eq!(read_back(&mut third, 3).await, b"off");
        assert_eq!(capture.policy().pending_count, 0);
        capture.stop().await.unwrap();
    }
    #[tokio::test]
    async fn drop_all_discards_every_held_read() {
        let (capture, port) = relaying().await;
        holding(&capture, None);
        let mut client = send_to(port, b"gone").await;
        wait_paused(&capture, 1).await;
        assert_eq!(capture.release_all(DecisionAction::Drop).await, 1);
        turn_off(&capture).await;
        client.write_all(b"kept").await.unwrap();
        assert_eq!(read_back(&mut client, 4).await, b"kept");
        capture.stop().await.unwrap();
    }
    #[tokio::test]
    async fn a_filter_holds_only_the_reads_that_match() {
        let (capture, port) = relaying().await;
        holding(
            &capture,
            Some(InterceptFilter {
                kind: FilterKind::Text,
                value: "PING".into(),
            }),
        );
        assert_eq!(capture.policy().filter.as_ref().unwrap().value, "PING");
        let mut passing = send_to(port, b"PONG").await;
        assert_eq!(read_back(&mut passing, 4).await, b"PONG");
        let _held = send_to(port, b"xPINGx").await;
        wait_paused(&capture, 1).await;
        capture.stop().await.unwrap();
    }
    #[test]
    fn filters_match_text_hex_and_patterns_and_refuse_bad_ones() {
        let compile = |kind, value: &str| {
            Matcher::compile(&InterceptFilter {
                kind,
                value: value.into(),
            })
        };
        assert!(compile(FilterKind::Hex, "50 49 4e 47")
            .unwrap()
            .matches(b"xPINGx"));
        assert!(!compile(FilterKind::Hex, "50494e47")
            .unwrap()
            .matches(b"PONG"));
        assert!(compile(FilterKind::Regex, "^P.NG$")
            .unwrap()
            .matches(b"PANG"));
        assert!(compile(FilterKind::Text, "ING").unwrap().matches(b"PING"));
        for (kind, value) in [
            (FilterKind::Hex, "5"),
            (FilterKind::Hex, "zz"),
            (FilterKind::Regex, "("),
            (FilterKind::Text, ""),
        ] {
            assert!(matches!(
                compile(kind, value),
                Err(InterceptError::BadRequest(_))
            ));
        }
    }
    /// A CONNECT proxy that sends every tunnel to `target` and reports the
    /// authority each CONNECT asked for.
    async fn connect_proxy(target: u16) -> (u16, tokio::sync::mpsc::UnboundedReceiver<String>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (asked, seen) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok((mut client, _)) = listener.accept().await {
                let asked = asked.clone();
                tokio::spawn(async move {
                    let mut head = Vec::new();
                    while !head.ends_with(b"\r\n\r\n") {
                        let mut byte = [0; 1];
                        if client.read_exact(&mut byte).await.is_err() {
                            return;
                        }
                        head.push(byte[0]);
                    }
                    let line = String::from_utf8_lossy(&head)
                        .lines()
                        .next()
                        .unwrap_or("")
                        .to_string();
                    let _ = asked.send(line);
                    let mut upstream = TcpStream::connect((Ipv4Addr::LOCALHOST, target))
                        .await
                        .unwrap();
                    client
                        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                        .await
                        .unwrap();
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                });
            }
        });
        (port, seen)
    }
    fn proxied(proxy_port: u16, bypass: &[&str]) -> Arc<crate::runtime::RuntimeSettings> {
        Arc::new(crate::runtime::RuntimeSettings::from_snapshot(
            crate::runtime::RuntimeSettingsSnapshot {
                upstream_proxy: crate::upstream_proxy::UpstreamProxy {
                    enabled: true,
                    url: format!("http://127.0.0.1:{proxy_port}"),
                    ..Default::default()
                },
                upstream_bypass_hosts: bypass.iter().map(|host| host.to_string()).collect(),
                ..Default::default()
            },
        ))
    }
    #[tokio::test]
    async fn a_connection_goes_through_the_upstream_proxy_when_it_is_on() {
        let target = echo_server().await;
        let (proxy_port, mut seen) = connect_proxy(target).await;
        let capture = temporary();
        capture.use_runtime(proxied(proxy_port, &[]));
        let port = free_port();
        capture
            .add_listener(TcpListenerInput {
                enabled: true,
                settings: TcpSettings {
                    local_port: port,
                    target_host: "relay.example.com".into(),
                    target_port: 5432,
                    ..Default::default()
                },
            })
            .await
            .unwrap();
        assert_eq!(echo_through(port, b"through").await, b"through");
        assert_eq!(
            seen.recv().await.unwrap(),
            "CONNECT relay.example.com:5432 HTTP/1.1"
        );
        let record = wait_saved(&capture, 1).await.remove(0);
        assert!(record.via_proxy);
        capture.stop().await.unwrap();
    }
    #[tokio::test]
    async fn this_machine_and_bypassed_hosts_go_direct() {
        let target = echo_server().await;
        let (proxy_port, mut seen) = connect_proxy(target).await;
        let capture = temporary();
        let runtime = proxied(proxy_port, &["*.internal.example.com"]);
        capture.use_runtime(runtime.clone());
        let port = free_port();
        capture
            .add_listener(TcpListenerInput {
                enabled: true,
                settings: loopback(port, target),
            })
            .await
            .unwrap();
        assert_eq!(echo_through(port, b"direct").await, b"direct");
        let record = wait_saved(&capture, 1).await.remove(0);
        assert!(!record.via_proxy);
        assert!(seen.try_recv().is_err(), "the proxy saw nothing");
        let proxy = runtime.upstream_proxy().await;
        assert!(!routes_through(&proxy, "db.internal.example.com"));
        assert!(!routes_through(&proxy, "localhost"));
        assert!(!routes_through(&proxy, "::1"));
        assert!(routes_through(&proxy, "relay.example.com"));
        capture.stop().await.unwrap();
    }
    fn test_ca() -> Arc<crate::certificate::CertificateAuthority> {
        let dir = std::env::temp_dir().join(format!("sniper-tcp-ca-{}", Uuid::new_v4()));
        Arc::new(crate::certificate::CertificateAuthority::load_or_create(&dir).unwrap())
    }
    /// A TLS server with a certificate from `ca`: says `banner` first when it is
    /// not empty, then echoes.
    async fn tls_server(
        ca: &crate::certificate::CertificateAuthority,
        banner: &'static [u8],
    ) -> u16 {
        let acceptor = ca.tls_acceptor_for_host("db.example.com").unwrap();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(socket).await else {
                        return;
                    };
                    if !banner.is_empty() && tls.write_all(banner).await.is_err() {
                        return;
                    }
                    let mut buffer = [0; 1024];
                    while let Ok(read @ 1..) = tls.read(&mut buffer).await {
                        if tls.write_all(&buffer[..read]).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        port
    }
    fn trusting(ca: &crate::certificate::CertificateAuthority) -> tokio_rustls26::TlsConnector {
        let mut roots = rustls23::RootCertStore::empty();
        roots
            .add(rustls23::pki_types::CertificateDer::from(
                ca.root_der_bytes().to_vec(),
            ))
            .unwrap();
        let config = rustls23::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tokio_rustls26::TlsConnector::from(Arc::new(config))
    }
    async fn tls_listener(
        ca: &Arc<crate::certificate::CertificateAuthority>,
        target_port: u16,
        tls: TlsMode,
    ) -> (Arc<TcpCapture>, u16) {
        let capture = temporary();
        capture.use_certificates(ca.clone());
        let port = free_port();
        capture
            .add_listener(TcpListenerInput {
                enabled: true,
                settings: TcpSettings {
                    local_port: port,
                    target_host: "127.0.0.1".into(),
                    target_port,
                    tls,
                    ..Default::default()
                },
            })
            .await
            .unwrap();
        (capture, port)
    }
    fn sent(record: &TcpConnection) -> Vec<u8> {
        record
            .chunks
            .iter()
            .filter(|chunk| chunk.direction == Direction::ClientToServer)
            .flat_map(|chunk| STANDARD.decode(&chunk.data_base64).unwrap())
            .collect()
    }
    #[tokio::test]
    async fn a_tls_client_is_decrypted_and_the_target_reached_over_tls() {
        let ca = test_ca();
        let server = tls_server(&ca, b"").await;
        let (capture, port) = tls_listener(&ca, server, TlsMode::Decrypt).await;
        let stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        let name = rustls23::pki_types::ServerName::try_from("db.example.com").unwrap();
        let mut tls = trusting(&ca).connect(name, stream).await.unwrap();
        tls.write_all(b"secret").await.unwrap();
        let mut back = [0; 6];
        tokio::time::timeout(Duration::from_secs(5), tls.read_exact(&mut back))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&back, b"secret");
        drop(tls);
        let record = wait_saved(&capture, 1).await.remove(0);
        assert!(record.client_tls && record.server_tls);
        // Dropped without close_notify, as many clients close: still a clean end.
        assert_eq!((record.status.as_str(), record.failure), ("closed", None));
        let detail = capture.detail(record.id).await.unwrap().unwrap();
        assert_eq!(sent(&detail), b"secret", "captured in plain text");
        capture.stop().await.unwrap();
    }
    #[tokio::test]
    async fn a_server_that_speaks_first_is_relayed_as_it_is() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let server = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.write_all(b"220 ready\r\n").await.unwrap();
            let mut hold = [0; 1];
            let _ = socket.read(&mut hold).await;
        });
        let (capture, port) = tls_listener(&test_ca(), server, TlsMode::Decrypt).await;
        let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        assert_eq!(read_back(&mut client, 11).await, b"220 ready\r\n");
        drop(client);
        let record = wait_saved(&capture, 1).await.remove(0);
        assert!(!record.client_tls && !record.server_tls);
        capture.stop().await.unwrap();
    }
    #[tokio::test]
    async fn a_plain_client_on_a_decrypting_listener_is_relayed_as_it_is() {
        let (capture, port) = tls_listener(&test_ca(), echo_server().await, TlsMode::Decrypt).await;
        assert_eq!(echo_through(port, b"plain").await, b"plain");
        capture.stop().await.unwrap();
    }
    #[tokio::test]
    async fn upstream_mode_adds_tls_towards_the_target_only() {
        let ca = test_ca();
        let server = tls_server(&ca, b"").await;
        let (capture, port) = tls_listener(&ca, server, TlsMode::Upstream).await;
        assert_eq!(echo_through(port, b"wrapped").await, b"wrapped");
        let record = wait_saved(&capture, 1).await.remove(0);
        assert!(!record.client_tls && record.server_tls);
        capture.stop().await.unwrap();
    }
    fn replay_of(target_port: u16, messages: &[&[u8]]) -> ReplayRequest {
        ReplayRequest {
            target_host: "127.0.0.1".into(),
            target_port,
            tls: false,
            messages: messages
                .iter()
                .map(|message| STANDARD.encode(message))
                .collect(),
            wait_ms: 200,
            from: None,
        }
    }
    fn exchange_of(record: &TcpConnection) -> Vec<(Direction, Vec<u8>)> {
        record
            .chunks
            .iter()
            .map(|chunk| {
                (
                    chunk.direction,
                    STANDARD.decode(&chunk.data_base64).unwrap(),
                )
            })
            .collect()
    }
    #[tokio::test]
    async fn a_replay_sends_each_message_and_records_the_replies_in_order() {
        let capture = temporary();
        let from = Uuid::new_v4();
        let record = capture
            .replay(ReplayRequest {
                from: Some(from),
                ..replay_of(echo_server().await, &[b"one", b"two"])
            })
            .await
            .unwrap();
        assert_eq!(
            exchange_of(&record),
            vec![
                (Direction::ClientToServer, b"one".to_vec()),
                (Direction::ServerToClient, b"one".to_vec()),
                (Direction::ClientToServer, b"two".to_vec()),
                (Direction::ServerToClient, b"two".to_vec()),
            ]
        );
        assert_eq!(record.source, TcpSource::Replay);
        assert_eq!(record.replayed_from, Some(from));
        assert_eq!((record.status.as_str(), record.durable), ("closed", true));
        assert_eq!(capture.summaries().await.len(), 1, "kept in the history");
    }
    #[tokio::test]
    async fn a_replay_ends_when_the_target_closes() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut first = [0; 3];
            socket.read_exact(&mut first).await.unwrap();
            socket.write_all(b"bye").await.unwrap();
        });
        let record = temporary()
            .replay(replay_of(port, &[b"one", b"two"]))
            .await
            .unwrap();
        assert_eq!(
            exchange_of(&record),
            vec![
                (Direction::ClientToServer, b"one".to_vec()),
                (Direction::ServerToClient, b"bye".to_vec()),
            ]
        );
        assert_eq!(record.status, "closed");
    }
    #[tokio::test]
    async fn replays_are_checked_before_anything_is_sent() {
        let capture = temporary();
        let refused = |request| {
            let capture = capture.clone();
            async move { capture.replay(request).await.unwrap_err() }
        };
        for request in [
            replay_of(9, &[]),
            replay_of(9, &[b"x".as_slice(); MAX_REPLAY_MESSAGES + 1]),
            ReplayRequest {
                wait_ms: 10,
                ..replay_of(9, &[b"x"])
            },
            ReplayRequest {
                messages: vec!["%%".into()],
                ..replay_of(9, &[b"x"])
            },
            ReplayRequest {
                target_host: "http://example.com".into(),
                ..replay_of(9, &[b"x"])
            },
        ] {
            assert!(matches!(
                refused(request).await,
                InterceptError::BadRequest(_)
            ));
        }
        {
            let mut history = capture.history.lock().unwrap();
            for _ in 0..MAX_CONNECTIONS {
                let saved = record();
                history.records.insert(saved.id, saved);
            }
        }
        assert!(matches!(
            refused(replay_of(9, &[b"x"])).await,
            InterceptError::Conflict(_)
        ));
    }
    #[tokio::test]
    async fn a_large_exchange_is_kept_whole() {
        let (capture, port) = relaying().await;
        let big = vec![b'x'; 400 * 1024];
        assert_eq!(echo_through(port, &big).await, big);
        let record = wait_saved(&capture, 1).await.remove(0);
        assert_eq!(record.captured_bytes, 2 * big.len());
        assert!(!record.capture_truncated);
        capture.stop().await.unwrap();
    }
    fn needle(kind: FilterKind, value: &str) -> Matcher {
        Matcher::compile(&InterceptFilter {
            kind,
            value: value.into(),
        })
        .unwrap()
    }
    #[tokio::test]
    async fn search_finds_records_by_their_bytes_even_across_reads() {
        let (capture, port) = relaying().await;
        let mut split = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        split.write_all(b"ab").await.unwrap();
        assert_eq!(read_back(&mut split, 2).await, b"ab");
        split.write_all(b"cd").await.unwrap();
        assert_eq!(read_back(&mut split, 2).await, b"cd");
        drop(split);
        assert_eq!(echo_through(port, b"other").await, b"other");
        let saved = wait_saved(&capture, 2).await;
        let split_id = saved
            .iter()
            .find(|record| record.client_bytes == 4)
            .unwrap()
            .id;
        assert_eq!(
            capture.search(&needle(FilterKind::Text, "bc")).await,
            (vec![split_id], false)
        );
        assert_eq!(
            capture.search(&needle(FilterKind::Hex, "62 63")).await,
            (vec![split_id], false)
        );
        assert_eq!(
            capture
                .search(&needle(FilterKind::Regex, "^oth"))
                .await
                .0
                .len(),
            1
        );
        assert_eq!(
            capture.search(&needle(FilterKind::Text, "zz")).await,
            (vec![], false)
        );
        capture.stop().await.unwrap();
    }
    #[tokio::test]
    async fn raw_bytes_come_back_exactly_one_direction_at_a_time() {
        let capture = temporary();
        let record = capture
            .replay(replay_of(echo_server().await, &[b"\x00\xffab"]))
            .await
            .unwrap();
        assert_eq!(
            capture
                .raw(record.id, Direction::ClientToServer)
                .await
                .unwrap(),
            Some(b"\x00\xffab".to_vec())
        );
        assert_eq!(
            capture
                .raw(record.id, Direction::ServerToClient)
                .await
                .unwrap(),
            Some(b"\x00\xffab".to_vec())
        );
        assert_eq!(
            capture
                .raw(Uuid::new_v4(), Direction::ClientToServer)
                .await
                .unwrap(),
            None
        );
    }
    fn remote(local_port: u16, target_port: u16, allowed: &[&str]) -> TcpSettings {
        TcpSettings {
            remote: true,
            allowed_clients: allowed.iter().map(|entry| entry.to_string()).collect(),
            ..loopback(local_port, target_port)
        }
    }
    #[tokio::test]
    async fn a_listener_open_to_other_devices_names_them() {
        let capture = temporary();
        let add = |settings| {
            let capture = capture.clone();
            async move {
                capture
                    .add_listener(TcpListenerInput {
                        enabled: false,
                        settings,
                    })
                    .await
            }
        };
        let error = add(remote(free_port(), 1, &[])).await.unwrap_err();
        assert_eq!(
            error.to_string(),
            "Name the devices that may connect: IP addresses or networks such as 192.0.2.0/24."
        );
        assert!(add(remote(free_port(), 1, &["nope"])).await.is_err());
        assert!(add(remote(free_port(), 1, &["192.0.2.0/33"]))
            .await
            .is_err());
        assert!(add(remote(free_port(), 1, &["192.0.2.7", "2001:db8::/32"]))
            .await
            .is_ok());
    }
    #[test]
    fn listed_devices_and_this_machine_are_let_in() {
        let allowed: Vec<String> = ["192.0.2.0/24", "2001:db8::1"].map(String::from).to_vec();
        let ip = |text: &str| text.parse::<std::net::IpAddr>().unwrap();
        assert!(client_allowed(ip("192.0.2.200"), &allowed));
        assert!(
            client_allowed(ip("::ffff:192.0.2.9"), &allowed),
            "IPv4 on a dual-stack socket"
        );
        assert!(client_allowed(ip("2001:db8::1"), &allowed));
        assert!(client_allowed(ip("127.0.0.1"), &allowed), "this machine");
        assert!(!client_allowed(ip("198.51.100.1"), &allowed));
        assert!(!client_allowed(ip("2001:db8::2"), &allowed));
    }
    #[test]
    fn a_target_on_a_guarded_port_of_this_machine_is_recognised() {
        let guarded = [std::net::SocketAddr::from((Ipv4Addr::LOCALHOST, 23001))];
        let at = |text: &str| text.parse::<std::net::SocketAddr>().unwrap();
        assert!(reaches_guarded(&[at("127.0.0.1:23001")], &guarded));
        assert!(reaches_guarded(&[at("[::ffff:127.0.0.1]:23001")], &guarded));
        assert!(!reaches_guarded(&[at("127.0.0.1:23002")], &guarded));
        assert!(!reaches_guarded(&[at("192.0.2.1:23001")], &guarded));
    }
    /// macOS gives lo0 the link-local fe80::1: a client bound to it reaches the
    /// listener from an address that is not loopback, as another device would.
    #[cfg(target_os = "macos")]
    async fn from_another_device(port: u16) -> std::io::Result<TcpStream> {
        let device = std::net::SocketAddrV6::new("fe80::1".parse().unwrap(), 0, 0, 1);
        let socket = tokio::net::TcpSocket::new_v6()?;
        socket.bind(device.into())?;
        socket
            .connect(std::net::SocketAddrV6::new("fe80::1".parse().unwrap(), port, 0, 1).into())
            .await
    }
    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn only_listed_devices_reach_a_remote_listener_and_never_sniper_itself() {
        let target = echo_server().await;
        let capture = temporary();
        let guarded = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let guarded_port = guarded.local_addr().unwrap().port();
        capture.use_own_addresses(vec![guarded.local_addr().unwrap()]);
        let (open, closed, onto_sniper) = (free_port(), free_port(), free_port());
        for settings in [
            remote(open, target, &["fe80::1"]),
            remote(closed, target, &["192.0.2.0/24"]),
            remote(onto_sniper, guarded_port, &["fe80::1"]),
        ] {
            capture
                .add_listener(TcpListenerInput {
                    enabled: true,
                    settings,
                })
                .await
                .unwrap();
        }
        let mut client = from_another_device(open).await.unwrap();
        client.write_all(b"device").await.unwrap();
        assert_eq!(read_back(&mut client, 6).await, b"device");
        drop(client);
        // This machine on a dual-stack socket is recorded as plain IPv4.
        assert_eq!(echo_through(open, b"here").await, b"here");
        let local = wait_saved(&capture, 2).await;
        assert!(
            local
                .iter()
                .any(|record| record.peer.starts_with("127.0.0.1:")),
            "{local:?}"
        );
        let mut refused = from_another_device(closed).await.unwrap();
        let mut nothing = [0; 1];
        assert_eq!(
            refused.read(&mut nothing).await.unwrap_or(0),
            0,
            "closed at once"
        );
        let status = capture.status().await;
        let of = |port: u16| {
            status
                .listeners
                .iter()
                .find(|l| l.config.settings.local_port == port)
                .unwrap()
        };
        assert_eq!(of(closed).refused, 1);
        let mut looping = from_another_device(onto_sniper).await.unwrap();
        let _ = looping.read(&mut nothing).await;
        let failed = wait_saved(&capture, 3).await;
        assert!(failed
            .iter()
            .any(|record| record.failure == Some(TcpFailure::GuardedTarget)));
        drop(guarded);
        capture.stop().await.unwrap();
    }
}

#[cfg(test)]
mod restore_tests;
