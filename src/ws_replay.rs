use std::{collections::HashMap, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use chrono::Utc;
use futures_util::{
    future::{AbortHandle, Abortable},
    SinkExt, StreamExt,
};
use http::{
    header::{COOKIE, HOST},
    HeaderMap, HeaderName, HeaderValue,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, RwLock};
use tokio_tungstenite::{
    client_async_tls_with_config,
    tungstenite::{client::IntoClientRequest, protocol::Message as WsMessage},
};
use tracing::warn;
use uuid::Uuid;

use crate::model::{BodyEncoding, WebSocketFrameDirection, WebSocketFrameKind};

const MAX_WS_REPLAY_FRAMES_PER_CONNECTION: usize = 10_000;
const MAX_WS_REPLAY_FRAMES_PER_RESPONSE: usize = 1_000;
const MAX_WS_REPLAY_FRAME_PREVIEW_BYTES: usize = 64 * 1024;
const MAX_WS_REPLAY_CONNECTIONS: usize = 256;
const WS_REPLAY_OUTBOUND_QUEUE_CAPACITY: usize = 128;
const WS_REPLAY_CLOSE_GRACE: Duration = Duration::from_secs(2);

/// A single frame in the WS replay conversation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WsReplayFrame {
    pub index: usize,
    pub captured_at: String,
    pub direction: WebSocketFrameDirection,
    pub kind: WebSocketFrameKind,
    pub body: String,
    pub body_encoding: BodyEncoding,
    pub body_size: usize,
    #[serde(default)]
    pub preview_truncated: bool,
}

/// Status of a WS replay connection.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum WsReplayStatus {
    Connecting,
    Connected,
    Disconnected,
    Error,
}

/// Snapshot of a WS replay connection state (returned to frontend).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WsReplaySnapshot {
    pub id: Uuid,
    pub status: WsReplayStatus,
    pub frames: Vec<WsReplayFrame>,
    pub error: Option<String>,
}

/// Incremental frame polling response for a WS replay connection.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WsReplayFramesSince {
    pub status: WsReplayStatus,
    pub error: Option<String>,
    pub frames: Vec<WsReplayFrame>,
    pub first_retained_index: Option<usize>,
    pub next_index: usize,
    pub gap: bool,
    pub truncated: bool,
}

/// Sender half to push messages into the WebSocket.
type WsSender = mpsc::Sender<WsReplayOutboundMessage>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WsReplaySendError {
    QueueFull,
    Closed,
}

impl std::fmt::Display for WsReplaySendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::QueueFull => write!(
                f,
                "WebSocket replay send queue is full; wait for pending frames to flush"
            ),
            Self::Closed => write!(f, "failed to send message"),
        }
    }
}

impl std::error::Error for WsReplaySendError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WsReplayOwnerConflict {
    pub owner_session_id: Uuid,
}

impl std::fmt::Display for WsReplayOwnerConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "WS replay connection belongs to session {}",
            self.owner_session_id
        )
    }
}

impl std::error::Error for WsReplayOwnerConflict {}

#[derive(Debug)]
enum WsReplayOutboundMessage {
    Message {
        msg: WsMessage,
        recorded_index: Option<usize>,
    },
    Close {
        recorded_index: Option<usize>,
    },
}

/// Internal state for a single WS replay connection.
struct WsReplayConnection {
    owner_session_id: Uuid,
    status: WsReplayStatus,
    frames: Vec<WsReplayFrame>,
    frame_counter: usize,
    retention_gap_floor: usize,
    sender: Option<WsSender>,
    task_abort: Option<AbortHandle>,
    writer_abort: Option<AbortHandle>,
    error: Option<String>,
}

type WsReplayConnectionHandle = Arc<RwLock<WsReplayConnection>>;
type WsReplayConnectionMap = Arc<RwLock<HashMap<Uuid, WsReplayConnectionHandle>>>;

impl WsReplayConnection {
    fn snapshot(&self, id: Uuid) -> WsReplaySnapshot {
        WsReplaySnapshot {
            id,
            status: self.status.clone(),
            frames: replay_frame_tail(&self.frames),
            error: self.error.clone(),
        }
    }

    fn push_frame(&mut self, direction: WebSocketFrameDirection, msg: &WsMessage) -> Option<usize> {
        let (kind, body, encoding, size, preview_truncated) = match msg {
            WsMessage::Text(text) => {
                let text = text.to_string();
                let size = text.len();
                let (preview, truncated) = truncate_text_preview(&text);
                (
                    WebSocketFrameKind::Text,
                    preview,
                    BodyEncoding::Utf8,
                    size,
                    truncated,
                )
            }
            WsMessage::Binary(data) => {
                use base64::Engine;
                let bytes = data.as_ref();
                let (preview, truncated) = preview_bytes(bytes);
                let b64 = base64::engine::general_purpose::STANDARD.encode(preview);
                (
                    WebSocketFrameKind::Binary,
                    b64,
                    BodyEncoding::Base64,
                    bytes.len(),
                    truncated,
                )
            }
            WsMessage::Ping(data) => {
                use base64::Engine;
                let bytes = data.as_ref();
                let (preview, truncated) = preview_bytes(bytes);
                (
                    WebSocketFrameKind::Ping,
                    base64::engine::general_purpose::STANDARD.encode(preview),
                    BodyEncoding::Base64,
                    bytes.len(),
                    truncated,
                )
            }
            WsMessage::Pong(data) => {
                use base64::Engine;
                let bytes = data.as_ref();
                let (preview, truncated) = preview_bytes(bytes);
                (
                    WebSocketFrameKind::Pong,
                    base64::engine::general_purpose::STANDARD.encode(preview),
                    BodyEncoding::Base64,
                    bytes.len(),
                    truncated,
                )
            }
            WsMessage::Close(frame) => {
                let text = frame
                    .as_ref()
                    .map(|f| format!("{}: {}", f.code, f.reason))
                    .unwrap_or_default();
                let size = text.len();
                let (preview, truncated) = truncate_text_preview(&text);
                (
                    WebSocketFrameKind::Close,
                    preview,
                    BodyEncoding::Utf8,
                    size,
                    truncated,
                )
            }
            WsMessage::Frame(_) => return None,
        };

        let index = self.frame_counter;
        let frame = WsReplayFrame {
            index,
            captured_at: Utc::now().to_rfc3339(),
            direction,
            kind,
            body,
            body_encoding: encoding,
            body_size: size,
            preview_truncated,
        };
        self.frame_counter += 1;
        self.frames.push(frame);
        if self.frames.len() > MAX_WS_REPLAY_FRAMES_PER_CONNECTION {
            let overflow = self.frames.len() - MAX_WS_REPLAY_FRAMES_PER_CONNECTION;
            self.frames.drain(..overflow);
            if let Some(frame) = self.frames.first() {
                self.retention_gap_floor = self.retention_gap_floor.max(frame.index);
            }
        }
        Some(index)
    }

    fn remove_frame(&mut self, index: usize) {
        if let Some(position) = self.frames.iter().position(|frame| frame.index == index) {
            self.frames.remove(position);
        }
    }

    fn record_writer_outbound_frame(
        &mut self,
        msg: &WsMessage,
        recorded_index: Option<usize>,
    ) -> (Option<usize>, bool) {
        if let Some(index) = recorded_index {
            return (Some(index), false);
        }
        (
            self.push_frame(WebSocketFrameDirection::ClientToServer, msg),
            true,
        )
    }

    fn rollback_writer_recorded_frame(&mut self, index: Option<usize>, recorded_by_writer: bool) {
        if recorded_by_writer {
            if let Some(index) = index {
                self.remove_frame(index);
            }
        }
    }

    fn push_auto_reply_frame(&mut self, msg: &WsMessage) -> Option<usize> {
        match msg {
            WsMessage::Ping(payload) => self.push_frame(
                WebSocketFrameDirection::ClientToServer,
                &WsMessage::Pong(payload.clone()),
            ),
            WsMessage::Close(frame) => self.push_frame(
                WebSocketFrameDirection::ClientToServer,
                &WsMessage::Close(frame.clone()),
            ),
            _ => None,
        }
    }

    fn is_terminal(&self) -> bool {
        matches!(
            self.status,
            WsReplayStatus::Disconnected | WsReplayStatus::Error
        ) && self.sender.is_none()
            && self.task_abort.is_none()
            && self.writer_abort.is_none()
    }
}

/// Manages all active WS replay connections.
pub struct WsReplayStore {
    connections: WsReplayConnectionMap,
}

impl WsReplayStore {
    pub fn new() -> Self {
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    #[cfg(test)]
    pub(crate) async fn remember_disconnected_connection_for_test(
        &self,
        id: Uuid,
        owner_session_id: Uuid,
    ) {
        let conn = Arc::new(RwLock::new(WsReplayConnection {
            owner_session_id,
            status: WsReplayStatus::Disconnected,
            frames: Vec::new(),
            frame_counter: 0,
            retention_gap_floor: 0,
            sender: None,
            task_abort: None,
            writer_abort: None,
            error: None,
        }));
        self.connections.write().await.insert(id, conn);
    }

    /// Connect to a WebSocket server.
    pub async fn connect(
        &self,
        id: Uuid,
        owner_session_id: Uuid,
        url: &str,
        extra_headers: Vec<(String, String)>,
        upstream_insecure: bool,
        proxy: crate::upstream_proxy::UpstreamProxy,
    ) -> Result<()> {
        // Build the tungstenite request with custom headers
        let mut request = url.into_client_request().context("invalid WebSocket URL")?;
        {
            let headers = request.headers_mut();
            for (name, value) in &extra_headers {
                if let (Ok(n), Ok(v)) = (
                    HeaderName::from_bytes(name.as_bytes()),
                    HeaderValue::from_str(value),
                ) {
                    insert_ws_replay_header(headers, n, v);
                }
            }
        }
        self.prune_terminal_connections(Some(owner_session_id))
            .await;

        let (task_abort, abort_registration) = AbortHandle::new_pair();

        // Create connection entry
        let conn = Arc::new(RwLock::new(WsReplayConnection {
            owner_session_id,
            status: WsReplayStatus::Connecting,
            frames: Vec::new(),
            frame_counter: 0,
            retention_gap_floor: 0,
            sender: None,
            task_abort: Some(task_abort),
            writer_abort: None,
            error: None,
        }));
        let previous = self
            .replace_connection_for_owner(id, owner_session_id, conn.clone())
            .await?;
        if let Some(previous) = previous {
            disconnect_connection_handle(previous).await;
        }

        // Connect in the background
        let connections = Arc::clone(&self.connections);
        tokio::spawn(Abortable::new(
            async move {
                let result = async {
                    let host = request.uri().host().context("Missing WebSocket host")?;
                    let port = request.uri().port_u16().unwrap_or(
                        if request.uri().scheme_str() == Some("wss") {
                            443
                        } else {
                            80
                        },
                    );
                    let stream = proxy.connect(host, port).await?;
                    Ok::<_, anyhow::Error>(
                        client_async_tls_with_config(
                            request,
                            stream,
                            None,
                            crate::ws_tls::insecure_connector(upstream_insecure),
                        )
                        .await?,
                    )
                }
                .await;
                match result {
                    Ok((mut ws_stream, _response)) => {
                        if !connection_is_current(&connections, id, &conn).await {
                            let _ = ws_stream.close(None).await;
                            return;
                        }

                        let (tx, mut rx) = mpsc::channel::<WsReplayOutboundMessage>(
                            WS_REPLAY_OUTBOUND_QUEUE_CAPACITY,
                        );
                        let (writer_abort, writer_abort_registration) = AbortHandle::new_pair();

                        {
                            let mut c = conn.write().await;
                            if c.status != WsReplayStatus::Connecting {
                                c.task_abort = None;
                                let _ = ws_stream.close(None).await;
                                return;
                            }
                            c.status = WsReplayStatus::Connected;
                            c.sender = Some(tx);
                            c.writer_abort = Some(writer_abort);
                        }

                        let (mut write, mut read) = ws_stream.split();

                        // Spawn writer task
                        let conn_for_writer = conn.clone();
                        let mut write_task = tokio::spawn(Abortable::new(
                            async move {
                                while let Some(outbound) = rx.recv().await {
                                    let (msg, recorded_index) = match outbound {
                                        WsReplayOutboundMessage::Message {
                                            msg,
                                            recorded_index,
                                        } => (msg, recorded_index),
                                        WsReplayOutboundMessage::Close { recorded_index } => {
                                            (WsMessage::Close(None), recorded_index)
                                        }
                                    };
                                    let (recorded_index, recorded_by_writer) = {
                                        let mut c = conn_for_writer.write().await;
                                        c.record_writer_outbound_frame(&msg, recorded_index)
                                    };
                                    if let Err(error) = write.send(msg).await {
                                        let mut c = conn_for_writer.write().await;
                                        c.rollback_writer_recorded_frame(
                                            recorded_index,
                                            recorded_by_writer,
                                        );
                                        c.status = WsReplayStatus::Error;
                                        c.error = Some(format!(
                                            "failed to send WebSocket frame: {error}"
                                        ));
                                        c.sender = None;
                                        break;
                                    }
                                }
                                if let Err(error) = write.close().await {
                                    warn!(?error, "failed to close WebSocket replay writer");
                                }
                                conn_for_writer.write().await.writer_abort = None;
                            },
                            writer_abort_registration,
                        ));

                        // Read incoming messages
                        let mut read_error = None;
                        while let Some(msg_result) = read.next().await {
                            match msg_result {
                                Ok(msg) => {
                                    if let WsMessage::Ping(payload) = msg {
                                        let ping = WsMessage::Ping(payload);
                                        let mut c = conn.write().await;
                                        c.push_frame(
                                            WebSocketFrameDirection::ServerToClient,
                                            &ping,
                                        );
                                        c.push_auto_reply_frame(&ping);
                                        continue;
                                    }

                                    let is_close = matches!(msg, WsMessage::Close(_));
                                    {
                                        let mut c = conn.write().await;
                                        c.push_frame(WebSocketFrameDirection::ServerToClient, &msg);
                                        if is_close {
                                            c.push_auto_reply_frame(&msg);
                                            c.sender = None;
                                        }
                                    }
                                    if is_close {
                                        break;
                                    }
                                }
                                Err(e) => {
                                    let message = format!("ws replay read error: {e}");
                                    warn!("{}", message);
                                    read_error = Some(message);
                                    break;
                                }
                            }
                        }

                        // Clean up
                        {
                            let mut c = conn.write().await;
                            c.sender = None;
                        }
                        if tokio::time::timeout(WS_REPLAY_CLOSE_GRACE, &mut write_task)
                            .await
                            .is_err()
                        {
                            write_task.abort();
                        }
                        let mut c = conn.write().await;
                        if let Some(error) = read_error {
                            if c.status != WsReplayStatus::Disconnected {
                                c.status = WsReplayStatus::Error;
                                c.error = Some(error);
                            }
                        } else if c.status != WsReplayStatus::Error {
                            c.status = WsReplayStatus::Disconnected;
                        }
                        c.sender = None;
                        c.task_abort = None;
                        c.writer_abort = None;
                    }
                    Err(e) => {
                        if !connection_is_current(&connections, id, &conn).await {
                            return;
                        }
                        let mut c = conn.write().await;
                        if c.status != WsReplayStatus::Connecting {
                            return;
                        }
                        c.status = WsReplayStatus::Error;
                        c.error = Some(e.to_string());
                        c.sender = None;
                        c.task_abort = None;
                        c.writer_abort = None;
                    }
                }
            },
            abort_registration,
        ));

        Ok(())
    }

    async fn close_existing_connection(&self, id: Uuid) {
        let existing = {
            let mut connections = self.connections.write().await;
            connections.remove(&id)
        };

        if let Some(conn) = existing {
            disconnect_connection_handle(conn).await;
        }
    }

    async fn connection(&self, id: Uuid) -> Option<WsReplayConnectionHandle> {
        self.connections.read().await.get(&id).cloned()
    }

    async fn replace_connection_for_owner(
        &self,
        id: Uuid,
        owner_session_id: Uuid,
        conn: WsReplayConnectionHandle,
    ) -> Result<Option<WsReplayConnectionHandle>> {
        loop {
            let expected = self.connection(id).await;
            if let Some(existing) = expected.as_ref() {
                let existing = existing.read().await;
                if existing.owner_session_id != owner_session_id {
                    anyhow::bail!(WsReplayOwnerConflict {
                        owner_session_id: existing.owner_session_id,
                    });
                }
            }

            let mut connections = self.connections.write().await;
            match (expected.as_ref(), connections.get(&id)) {
                (None, None) => {
                    if connections.len() >= MAX_WS_REPLAY_CONNECTIONS {
                        drop(connections);
                        if self.prune_terminal_connections(None).await > 0 {
                            continue;
                        }
                        anyhow::bail!(
                            "too many WebSocket replay connections; close stale replay tabs first"
                        );
                    }
                    return Ok(connections.insert(id, conn.clone()));
                }
                (Some(expected), Some(current)) if Arc::ptr_eq(expected, current) => {
                    return Ok(connections.insert(id, conn.clone()));
                }
                _ => {}
            }
            drop(connections);
            tokio::task::yield_now().await;
        }
    }

    async fn prune_terminal_connections(&self, owner_session_id: Option<Uuid>) -> usize {
        let candidates = {
            let connections = self.connections.read().await;
            connections
                .iter()
                .map(|(id, conn)| (*id, conn.clone()))
                .collect::<Vec<_>>()
        };
        let mut remove_candidates = Vec::new();
        for (id, conn) in candidates {
            let should_remove = {
                let connection = conn.read().await;
                owner_session_id.is_none_or(|owner| connection.owner_session_id == owner)
                    && connection.is_terminal()
            };
            if should_remove {
                remove_candidates.push((id, conn));
            }
        }
        if remove_candidates.is_empty() {
            return 0;
        }
        let mut connections = self.connections.write().await;
        let mut removed = 0;
        for (id, candidate) in remove_candidates {
            if connections
                .get(&id)
                .is_some_and(|current| Arc::ptr_eq(current, &candidate))
            {
                connections.remove(&id);
                removed += 1;
            }
        }
        removed
    }

    pub async fn owner_session_id(&self, id: Uuid) -> Option<Uuid> {
        let conn = self.connection(id).await?;
        let c = conn.read().await;
        Some(c.owner_session_id)
    }

    pub async fn belongs_to_session(&self, id: Uuid, session_id: Uuid) -> Option<bool> {
        self.owner_session_id(id)
            .await
            .map(|owner_session_id| owner_session_id == session_id)
    }

    async fn send_message(&self, id: Uuid, msg: WsMessage) -> Result<()> {
        let conn = self
            .connection(id)
            .await
            .context("no such WS replay connection")?;
        let mut c = conn.write().await;
        let sender = c.sender.as_ref().context("connection is not open")?.clone();
        let recorded_index = c.push_frame(WebSocketFrameDirection::ClientToServer, &msg);
        sender
            .try_send(WsReplayOutboundMessage::Message {
                msg,
                recorded_index,
            })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => {
                    if let Some(index) = recorded_index {
                        c.remove_frame(index);
                    }
                    anyhow::Error::new(WsReplaySendError::QueueFull)
                }
                mpsc::error::TrySendError::Closed(_) => {
                    if let Some(index) = recorded_index {
                        c.remove_frame(index);
                    }
                    anyhow::Error::new(WsReplaySendError::Closed)
                }
            })?;
        Ok(())
    }

    /// Send a text message on an existing connection.
    pub async fn send_text(&self, id: Uuid, text: String) -> Result<()> {
        self.send_message(id, WsMessage::Text(text.into())).await
    }

    /// Send a binary message on an existing connection.
    pub async fn send_binary(&self, id: Uuid, data: Vec<u8>) -> Result<()> {
        self.send_message(id, WsMessage::Binary(data.into())).await
    }

    /// Send a ping control frame on an existing connection.
    pub async fn send_ping(&self, id: Uuid, data: Vec<u8>) -> Result<()> {
        self.send_message(id, WsMessage::Ping(data.into())).await
    }

    /// Send a pong control frame on an existing connection.
    pub async fn send_pong(&self, id: Uuid, data: Vec<u8>) -> Result<()> {
        self.send_message(id, WsMessage::Pong(data.into())).await
    }

    /// Disconnect an active connection.
    pub async fn disconnect(&self, id: Uuid) -> Result<()> {
        if let Some(conn) = self.connection(id).await {
            let (abort, writer_abort, graceful_close) = {
                let mut c = conn.write().await;
                let graceful_close = if let Some(sender) = c.sender.take() {
                    let recorded_index = c.push_frame(
                        WebSocketFrameDirection::ClientToServer,
                        &WsMessage::Close(None),
                    );
                    match sender.try_send(WsReplayOutboundMessage::Close { recorded_index }) {
                        Ok(()) => true,
                        Err(_) => {
                            if let Some(index) = recorded_index {
                                c.remove_frame(index);
                            }
                            false
                        }
                    }
                } else {
                    false
                };
                let abort = c.task_abort.take();
                let writer_abort = (!graceful_close).then(|| c.writer_abort.take()).flatten();
                c.status = WsReplayStatus::Disconnected;
                (abort, writer_abort, graceful_close)
            };
            if let Some(writer_abort) = writer_abort {
                writer_abort.abort();
            }
            if let Some(abort) = abort {
                abort_connection_after_close(abort, graceful_close);
            }
        }
        Ok(())
    }

    /// Get the current snapshot of a connection (status + all frames).
    pub async fn snapshot(&self, id: Uuid) -> Option<WsReplaySnapshot> {
        let conn = self.connection(id).await?;
        let c = conn.read().await;
        Some(c.snapshot(id))
    }

    /// Get frames since a given index (for polling).
    pub async fn frames_since(&self, id: Uuid, since_index: usize) -> Option<WsReplayFramesSince> {
        let conn = self.connection(id).await?;
        let c = conn.read().await;
        let first_retained_index = c.frames.first().map(|frame| frame.index);
        let gap = since_index < c.retention_gap_floor;
        let first_new = c.frames.partition_point(|frame| frame.index < since_index);
        let end = (first_new + MAX_WS_REPLAY_FRAMES_PER_RESPONSE).min(c.frames.len());
        let frames = c.frames[first_new..end].to_vec();
        let next_index = frames
            .last()
            .map(|frame| frame.index.saturating_add(1))
            .unwrap_or_else(|| {
                if gap {
                    c.retention_gap_floor.max(since_index)
                } else {
                    since_index
                }
            });
        Some(WsReplayFramesSince {
            status: c.status.clone(),
            error: c.error.clone(),
            frames,
            first_retained_index,
            next_index,
            gap,
            truncated: gap || end < c.frames.len(),
        })
    }

    /// Remove a connection and its data.
    pub async fn remove(&self, id: Uuid) {
        self.close_existing_connection(id).await;
    }

    /// Remove every replay connection owned by a deleted session.
    pub async fn remove_session(&self, session_id: Uuid) {
        let ids = {
            let connections = self.connections.read().await;
            let mut ids = Vec::new();
            for (id, conn) in connections.iter() {
                if conn.read().await.owner_session_id == session_id {
                    ids.push(*id);
                }
            }
            ids
        };
        for id in ids {
            self.remove(id).await;
        }
    }

    /// Disconnect and remove every replay connection.
    pub async fn disconnect_all(&self) {
        let ids = {
            let connections = self.connections.read().await;
            connections.keys().copied().collect::<Vec<_>>()
        };
        for id in ids {
            self.remove(id).await;
        }
    }
}

fn truncate_text_preview(text: &str) -> (String, bool) {
    if text.len() <= MAX_WS_REPLAY_FRAME_PREVIEW_BYTES {
        return (text.to_string(), false);
    }

    let end = text
        .char_indices()
        .map(|(idx, ch)| idx + ch.len_utf8())
        .take_while(|end| *end <= MAX_WS_REPLAY_FRAME_PREVIEW_BYTES)
        .last()
        .unwrap_or(0);
    (text[..end].to_string(), true)
}

fn preview_bytes(bytes: &[u8]) -> (&[u8], bool) {
    let end = bytes.len().min(MAX_WS_REPLAY_FRAME_PREVIEW_BYTES);
    (&bytes[..end], bytes.len() > end)
}

fn insert_ws_replay_header(headers: &mut HeaderMap, name: HeaderName, value: HeaderValue) {
    if name == COOKIE {
        if let (Some(existing), Ok(next)) = (
            headers.get(COOKIE).and_then(|value| value.to_str().ok()),
            value.to_str(),
        ) {
            let existing = existing.trim();
            let next = next.trim();
            let merged = match (existing.is_empty(), next.is_empty()) {
                (true, true) => String::new(),
                (true, false) => next.to_string(),
                (false, true) => existing.to_string(),
                (false, false) => format!("{existing}; {next}"),
            };
            if let Ok(merged) = HeaderValue::from_str(&merged) {
                headers.insert(COOKIE, merged);
                return;
            }
        }
        headers.insert(COOKIE, value);
    } else if name == HOST {
        headers.insert(name, value);
    } else {
        headers.append(name, value);
    }
}

async fn connection_is_current(
    connections: &WsReplayConnectionMap,
    id: Uuid,
    conn: &WsReplayConnectionHandle,
) -> bool {
    connections
        .read()
        .await
        .get(&id)
        .is_some_and(|current| Arc::ptr_eq(current, conn))
}

async fn disconnect_connection_handle(conn: WsReplayConnectionHandle) {
    let mut c = conn.write().await;
    let graceful_close = if let Some(sender) = c.sender.take() {
        sender
            .try_send(WsReplayOutboundMessage::Close {
                recorded_index: None,
            })
            .is_ok()
    } else {
        false
    };
    let writer_abort = (!graceful_close).then(|| c.writer_abort.take()).flatten();
    if let Some(abort) = c.task_abort.take() {
        abort_connection_after_close(abort, graceful_close);
    }
    if let Some(writer_abort) = writer_abort {
        writer_abort.abort();
    }
    c.status = WsReplayStatus::Disconnected;
}

impl Default for WsReplayStore {
    fn default() -> Self {
        Self::new()
    }
}

fn abort_connection_after_close(abort: AbortHandle, graceful_close: bool) {
    if !graceful_close {
        abort.abort();
        return;
    }
    tokio::spawn(async move {
        tokio::time::sleep(WS_REPLAY_CLOSE_GRACE).await;
        abort.abort();
    });
}

fn replay_frame_tail(frames: &[WsReplayFrame]) -> Vec<WsReplayFrame> {
    let start = frames
        .len()
        .saturating_sub(MAX_WS_REPLAY_FRAMES_PER_RESPONSE);
    frames[start..].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_connection(status: WsReplayStatus, sender: Option<WsSender>) -> WsReplayConnection {
        WsReplayConnection {
            owner_session_id: Uuid::new_v4(),
            status,
            frames: Vec::new(),
            frame_counter: 0,
            retention_gap_floor: 0,
            sender,
            task_abort: None,
            writer_abort: None,
            error: None,
        }
    }

    fn test_frame(index: usize) -> WsReplayFrame {
        WsReplayFrame {
            index,
            captured_at: Utc::now().to_rfc3339(),
            direction: WebSocketFrameDirection::ServerToClient,
            kind: WebSocketFrameKind::Text,
            body: format!("frame-{index}"),
            body_encoding: BodyEncoding::Utf8,
            body_size: 0,
            preview_truncated: false,
        }
    }

    fn test_channel() -> (WsSender, mpsc::Receiver<WsReplayOutboundMessage>) {
        mpsc::channel(WS_REPLAY_OUTBOUND_QUEUE_CAPACITY)
    }

    #[tokio::test]
    async fn frames_since_includes_connection_error() {
        let store = WsReplayStore::new();
        let id = Uuid::new_v4();
        let owner = Uuid::new_v4();
        let mut connection = test_connection(WsReplayStatus::Error, None);
        connection.owner_session_id = owner;
        connection.error = Some("connection refused".to_string());
        store
            .connections
            .write()
            .await
            .insert(id, Arc::new(RwLock::new(connection)));

        let response = store.frames_since(id, 0).await.unwrap();
        assert_eq!(response.status, WsReplayStatus::Error);
        assert_eq!(response.error.as_deref(), Some("connection refused"));
        assert!(response.frames.is_empty());
    }

    #[tokio::test]
    async fn frames_since_and_snapshot_are_response_capped() {
        let store = WsReplayStore::new();
        let id = Uuid::new_v4();
        let mut connection = test_connection(WsReplayStatus::Connected, None);
        connection.frames = (0..=MAX_WS_REPLAY_FRAMES_PER_RESPONSE + 5)
            .map(test_frame)
            .collect();
        store
            .connections
            .write()
            .await
            .insert(id, Arc::new(RwLock::new(connection)));

        let response = store.frames_since(id, 0).await.unwrap();
        assert_eq!(response.frames.len(), MAX_WS_REPLAY_FRAMES_PER_RESPONSE);
        assert_eq!(response.frames[0].index, 0);
        assert_eq!(
            response.frames[MAX_WS_REPLAY_FRAMES_PER_RESPONSE - 1].index,
            999
        );
        assert_eq!(response.first_retained_index, Some(0));
        assert_eq!(response.next_index, 1000);
        assert!(!response.gap);
        assert!(response.truncated);

        let snapshot = store.snapshot(id).await.unwrap();
        assert_eq!(snapshot.frames.len(), MAX_WS_REPLAY_FRAMES_PER_RESPONSE);
        assert_eq!(snapshot.frames[0].index, 6);
        assert_eq!(
            snapshot.frames[MAX_WS_REPLAY_FRAMES_PER_RESPONSE - 1].index,
            1005
        );
    }

    #[tokio::test]
    async fn frames_since_reports_retention_gap_when_requested_index_was_trimmed() {
        let store = WsReplayStore::new();
        let id = Uuid::new_v4();
        let mut connection = test_connection(WsReplayStatus::Connected, None);
        connection.frames = (50..55).map(test_frame).collect();
        connection.retention_gap_floor = 50;
        store
            .connections
            .write()
            .await
            .insert(id, Arc::new(RwLock::new(connection)));

        let response = store.frames_since(id, 10).await.unwrap();

        assert_eq!(response.first_retained_index, Some(50));
        assert_eq!(response.next_index, 55);
        assert!(response.gap);
        assert!(response.truncated);
        assert_eq!(response.frames.first().map(|frame| frame.index), Some(50));
    }

    #[tokio::test]
    async fn frames_since_advances_when_retention_gap_has_no_retained_frames() {
        let store = WsReplayStore::new();
        let id = Uuid::new_v4();
        let mut connection = test_connection(WsReplayStatus::Connected, None);
        connection.retention_gap_floor = 50;
        store
            .connections
            .write()
            .await
            .insert(id, Arc::new(RwLock::new(connection)));

        let response = store.frames_since(id, 10).await.unwrap();

        assert!(response.frames.is_empty());
        assert_eq!(response.first_retained_index, None);
        assert_eq!(response.next_index, 50);
        assert!(response.gap);
        assert!(response.truncated);
    }

    #[tokio::test]
    async fn connection_owner_is_checked_by_session_id() {
        let store = WsReplayStore::new();
        let id = Uuid::new_v4();
        let owner = Uuid::new_v4();
        let mut connection = test_connection(WsReplayStatus::Connected, None);
        connection.owner_session_id = owner;
        store
            .connections
            .write()
            .await
            .insert(id, Arc::new(RwLock::new(connection)));

        assert_eq!(store.belongs_to_session(id, owner).await, Some(true));
        assert_eq!(
            store.belongs_to_session(id, Uuid::new_v4()).await,
            Some(false)
        );
        assert_eq!(store.belongs_to_session(Uuid::new_v4(), owner).await, None);
        assert_eq!(store.owner_session_id(id).await, Some(owner));
        assert_eq!(store.owner_session_id(Uuid::new_v4()).await, None);
    }

    #[tokio::test]
    async fn remove_session_closes_only_owned_connections() {
        let store = WsReplayStore::new();
        let owner = Uuid::new_v4();
        let other_owner = Uuid::new_v4();
        let owned_id = Uuid::new_v4();
        let other_id = Uuid::new_v4();
        let owned = Arc::new(RwLock::new(test_connection(
            WsReplayStatus::Connected,
            None,
        )));
        owned.write().await.owner_session_id = owner;
        let other = Arc::new(RwLock::new(test_connection(
            WsReplayStatus::Connected,
            None,
        )));
        other.write().await.owner_session_id = other_owner;
        {
            let mut connections = store.connections.write().await;
            connections.insert(owned_id, owned);
            connections.insert(other_id, other);
        }

        store.remove_session(owner).await;

        assert_eq!(store.belongs_to_session(owned_id, owner).await, None);
        assert_eq!(
            store.belongs_to_session(other_id, other_owner).await,
            Some(true)
        );
    }

    #[test]
    fn replay_frame_body_is_preview_capped() {
        let mut conn = test_connection(WsReplayStatus::Connected, None);
        let data = vec![7_u8; MAX_WS_REPLAY_FRAME_PREVIEW_BYTES + 11];

        conn.push_frame(
            WebSocketFrameDirection::ServerToClient,
            &WsMessage::Binary(data.clone().into()),
        );

        let frame = conn.frames.first().unwrap();
        assert_eq!(frame.body_size, data.len());
        assert!(frame.preview_truncated);

        use base64::Engine;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(frame.body.as_bytes())
            .unwrap();
        assert_eq!(decoded.len(), MAX_WS_REPLAY_FRAME_PREVIEW_BYTES);
    }

    #[test]
    fn replay_handshake_merges_cookie_headers() {
        let mut headers = HeaderMap::new();
        insert_ws_replay_header(
            &mut headers,
            COOKIE,
            HeaderValue::from_static("session=abc"),
        );
        insert_ws_replay_header(&mut headers, COOKIE, HeaderValue::from_static("theme=dark"));

        assert_eq!(headers.get_all(COOKIE).iter().count(), 1);
        assert_eq!(headers.get(COOKIE).unwrap(), "session=abc; theme=dark");
    }

    #[test]
    fn replay_connection_caps_frames_but_keeps_monotonic_indexes() {
        let mut conn = test_connection(WsReplayStatus::Connected, None);

        for index in 0..(MAX_WS_REPLAY_FRAMES_PER_CONNECTION + 3) {
            conn.push_frame(
                WebSocketFrameDirection::ClientToServer,
                &WsMessage::Text(format!("frame-{index}").into()),
            );
        }

        assert_eq!(conn.frames.len(), MAX_WS_REPLAY_FRAMES_PER_CONNECTION);
        assert_eq!(conn.frame_counter, MAX_WS_REPLAY_FRAMES_PER_CONNECTION + 3);
        assert_eq!(conn.retention_gap_floor, 3);
        assert_eq!(conn.frames.first().map(|frame| frame.index), Some(3));
        assert_eq!(
            conn.frames.last().map(|frame| frame.index),
            Some(MAX_WS_REPLAY_FRAMES_PER_CONNECTION + 2)
        );
    }

    #[test]
    fn replay_connection_can_remove_unsent_frame_by_index() {
        let mut conn = test_connection(WsReplayStatus::Connected, None);
        let first = conn
            .push_frame(
                WebSocketFrameDirection::ClientToServer,
                &WsMessage::Text("first".into()),
            )
            .unwrap();
        conn.push_frame(
            WebSocketFrameDirection::ServerToClient,
            &WsMessage::Text("reply".into()),
        );

        conn.remove_frame(first);

        assert_eq!(conn.frames.len(), 1);
        assert!(matches!(
            conn.frames[0].direction,
            WebSocketFrameDirection::ServerToClient
        ));
        assert_eq!(conn.frame_counter, 2);
    }

    #[test]
    fn replay_connection_keeps_indexes_monotonic_after_rollback() {
        let mut conn = test_connection(WsReplayStatus::Connected, None);
        let recorded = conn
            .push_frame(
                WebSocketFrameDirection::ClientToServer,
                &WsMessage::Text("pending".into()),
            )
            .unwrap();

        conn.remove_frame(recorded);
        let next = conn
            .push_frame(
                WebSocketFrameDirection::ClientToServer,
                &WsMessage::Text("retry".into()),
            )
            .unwrap();

        assert_eq!(recorded, 0);
        assert_eq!(next, 1);
        assert_eq!(conn.frame_counter, 2);
        assert_eq!(conn.frames.len(), 1);
        assert_eq!(conn.frames[0].index, 1);
    }

    #[test]
    fn writer_rollback_preserves_pre_recorded_user_frame() {
        let mut conn = test_connection(WsReplayStatus::Connected, None);
        let recorded = conn
            .push_frame(
                WebSocketFrameDirection::ClientToServer,
                &WsMessage::Text("user-send".into()),
            )
            .unwrap();
        let (writer_index, recorded_by_writer) =
            conn.record_writer_outbound_frame(&WsMessage::Text("user-send".into()), Some(recorded));

        conn.rollback_writer_recorded_frame(writer_index, recorded_by_writer);

        assert_eq!(writer_index, Some(recorded));
        assert!(!recorded_by_writer);
        assert_eq!(conn.frames.len(), 1);
        assert_eq!(conn.frames[0].index, recorded);
        assert!(matches!(conn.frames[0].kind, WebSocketFrameKind::Text));
    }

    #[test]
    fn writer_rollback_removes_only_writer_recorded_frame() {
        let mut conn = test_connection(WsReplayStatus::Connected, None);
        let (writer_index, recorded_by_writer) =
            conn.record_writer_outbound_frame(&WsMessage::Pong(b"auto".to_vec().into()), None);

        conn.rollback_writer_recorded_frame(writer_index, recorded_by_writer);

        assert_eq!(writer_index, Some(0));
        assert!(recorded_by_writer);
        assert!(conn.frames.is_empty());
        assert_eq!(conn.frame_counter, 1);
    }

    #[tokio::test]
    async fn frames_since_does_not_report_gap_for_rolled_back_index_hole() {
        let store = WsReplayStore::new();
        let id = Uuid::new_v4();
        let mut connection = test_connection(WsReplayStatus::Connected, None);
        let rolled_back = connection
            .push_frame(
                WebSocketFrameDirection::ClientToServer,
                &WsMessage::Text("pending".into()),
            )
            .unwrap();

        connection.remove_frame(rolled_back);
        connection.push_frame(
            WebSocketFrameDirection::ServerToClient,
            &WsMessage::Text("reply".into()),
        );
        store
            .connections
            .write()
            .await
            .insert(id, Arc::new(RwLock::new(connection)));

        let response = store.frames_since(id, rolled_back).await.unwrap();

        assert_eq!(response.first_retained_index, Some(1));
        assert_eq!(response.next_index, 2);
        assert_eq!(response.frames.len(), 1);
        assert_eq!(response.frames[0].index, 1);
        assert!(!response.gap);
        assert!(!response.truncated);
    }

    #[test]
    fn replay_connection_records_automatic_control_replies() {
        let mut conn = test_connection(WsReplayStatus::Connected, None);
        let ping = WsMessage::Ping(b"hello".to_vec().into());

        conn.push_frame(WebSocketFrameDirection::ServerToClient, &ping);
        conn.push_auto_reply_frame(&ping);

        assert_eq!(conn.frames.len(), 2);
        assert!(matches!(conn.frames[0].kind, WebSocketFrameKind::Ping));
        assert!(matches!(conn.frames[1].kind, WebSocketFrameKind::Pong));
        assert!(matches!(
            conn.frames[1].direction,
            WebSocketFrameDirection::ClientToServer
        ));

        let close = WsMessage::Close(None);
        conn.push_frame(WebSocketFrameDirection::ServerToClient, &close);
        conn.push_auto_reply_frame(&close);

        assert!(matches!(conn.frames[2].kind, WebSocketFrameKind::Close));
        assert!(matches!(conn.frames[3].kind, WebSocketFrameKind::Close));
        assert!(matches!(
            conn.frames[3].direction,
            WebSocketFrameDirection::ClientToServer
        ));
    }

    #[tokio::test]
    async fn server_ping_receives_single_automatic_pong() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            ws.send(WsMessage::Ping(b"hello".to_vec().into()))
                .await
                .unwrap();

            let deadline = std::time::Instant::now() + std::time::Duration::from_millis(500);
            let mut pongs = Vec::new();
            while let Some(remaining) = deadline.checked_duration_since(std::time::Instant::now()) {
                match tokio::time::timeout(remaining, ws.next()).await {
                    Ok(Some(Ok(WsMessage::Pong(payload)))) => pongs.push(payload.to_vec()),
                    Ok(Some(Ok(_))) => {}
                    Ok(Some(Err(error))) => panic!("server websocket read failed: {error}"),
                    Ok(None) | Err(_) => break,
                }
            }
            pongs
        });

        let store = WsReplayStore::new();
        let id = Uuid::new_v4();
        let owner = Uuid::new_v4();
        let url = format!("ws://{addr}/");
        store
            .connect(id, owner, &url, Vec::new(), false, Default::default())
            .await
            .unwrap();

        let pongs = tokio::time::timeout(std::time::Duration::from_secs(2), server)
            .await
            .expect("server should finish")
            .expect("server task should succeed");
        assert_eq!(pongs, vec![b"hello".to_vec()]);

        for _ in 0..20 {
            if store
                .snapshot(id)
                .await
                .is_some_and(|snapshot| snapshot.frames.len() >= 2)
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let snapshot = store.snapshot(id).await.unwrap();
        assert_eq!(snapshot.frames.len(), 2);
        assert!(matches!(snapshot.frames[0].kind, WebSocketFrameKind::Ping));
        assert!(matches!(snapshot.frames[1].kind, WebSocketFrameKind::Pong));

        store.remove(id).await;
    }

    #[tokio::test]
    async fn connect_replacement_disconnects_previous_connection() {
        let store = WsReplayStore::new();
        let id = Uuid::new_v4();
        let owner = Uuid::new_v4();
        let (tx, mut rx) = test_channel();
        let mut previous_connection = test_connection(WsReplayStatus::Connected, Some(tx));
        previous_connection.owner_session_id = owner;
        let previous = Arc::new(RwLock::new(previous_connection));
        store.connections.write().await.insert(id, previous.clone());

        store
            .connect(
                id,
                owner,
                "ws://127.0.0.1:1/",
                Vec::new(),
                false,
                Default::default(),
            )
            .await
            .unwrap();

        assert!(store.connections.read().await.contains_key(&id));
        assert_eq!(previous.read().await.status, WsReplayStatus::Disconnected);
        assert!(matches!(
            rx.recv().await,
            Some(WsReplayOutboundMessage::Close {
                recorded_index: None
            })
        ));
    }

    #[tokio::test]
    async fn connect_rejects_connection_id_owned_by_another_session() {
        let store = WsReplayStore::new();
        let id = Uuid::new_v4();
        let owner = Uuid::new_v4();
        let other_owner = Uuid::new_v4();
        let mut existing = test_connection(WsReplayStatus::Connected, None);
        existing.owner_session_id = owner;
        store
            .connections
            .write()
            .await
            .insert(id, Arc::new(RwLock::new(existing)));

        let error = store
            .connect(
                id,
                other_owner,
                "ws://127.0.0.1:1/",
                Vec::new(),
                false,
                Default::default(),
            )
            .await
            .unwrap_err();

        let owner_conflict = error
            .downcast_ref::<WsReplayOwnerConflict>()
            .expect("owner mismatch should preserve the owning session id");
        assert_eq!(owner_conflict.owner_session_id, owner);
        assert_eq!(store.belongs_to_session(id, owner).await, Some(true));
    }

    #[tokio::test]
    async fn connect_prunes_terminal_connections_before_connection_cap() {
        let store = WsReplayStore::new();
        let owner = Uuid::new_v4();
        let other_owner = Uuid::new_v4();
        let other_terminal_id = Uuid::new_v4();
        {
            let mut connections = store.connections.write().await;
            for _ in 0..MAX_WS_REPLAY_CONNECTIONS {
                let mut connection = test_connection(WsReplayStatus::Error, None);
                connection.owner_session_id = owner;
                connection.error = Some("connection refused".to_string());
                connections.insert(Uuid::new_v4(), Arc::new(RwLock::new(connection)));
            }
            let mut other_terminal = test_connection(WsReplayStatus::Error, None);
            other_terminal.owner_session_id = other_owner;
            other_terminal.error = Some("other session error".to_string());
            connections.insert(other_terminal_id, Arc::new(RwLock::new(other_terminal)));
        }

        let id = Uuid::new_v4();
        store
            .connect(
                id,
                owner,
                "ws://127.0.0.1:1/",
                Vec::new(),
                false,
                Default::default(),
            )
            .await
            .unwrap();

        assert_eq!(store.connections.read().await.len(), 2);
        assert!(store.snapshot(other_terminal_id).await.is_some());
        store.remove(id).await;
    }

    #[tokio::test]
    async fn connect_prunes_global_terminal_connections_before_connection_cap() {
        let store = WsReplayStore::new();
        let owner = Uuid::new_v4();
        let other_owner = Uuid::new_v4();
        {
            let mut connections = store.connections.write().await;
            for _ in 0..MAX_WS_REPLAY_CONNECTIONS {
                let mut connection = test_connection(WsReplayStatus::Disconnected, None);
                connection.owner_session_id = other_owner;
                connections.insert(Uuid::new_v4(), Arc::new(RwLock::new(connection)));
            }
        }

        let id = Uuid::new_v4();
        store
            .connect(
                id,
                owner,
                "ws://127.0.0.1:1/",
                Vec::new(),
                false,
                Default::default(),
            )
            .await
            .unwrap();

        let connections = store.connections.read().await;
        assert_eq!(connections.len(), 1);
        assert!(connections.contains_key(&id));
        drop(connections);
        store.remove(id).await;
    }

    #[tokio::test]
    async fn connect_rejects_when_active_connection_cap_is_full() {
        let store = WsReplayStore::new();
        let owner = Uuid::new_v4();
        {
            let mut connections = store.connections.write().await;
            for _ in 0..MAX_WS_REPLAY_CONNECTIONS {
                let mut connection = test_connection(WsReplayStatus::Connecting, None);
                connection.owner_session_id = owner;
                connections.insert(Uuid::new_v4(), Arc::new(RwLock::new(connection)));
            }
        }

        let error = store
            .connect(
                Uuid::new_v4(),
                owner,
                "ws://127.0.0.1:1/",
                Vec::new(),
                false,
                Default::default(),
            )
            .await
            .unwrap_err();

        assert!(error
            .to_string()
            .contains("too many WebSocket replay connections"));
        assert_eq!(
            store.connections.read().await.len(),
            MAX_WS_REPLAY_CONNECTIONS
        );
    }

    #[tokio::test]
    async fn remove_deletes_connection_snapshot() {
        let store = WsReplayStore::new();
        let id = Uuid::new_v4();
        let (tx, mut rx) = test_channel();
        let connection = Arc::new(RwLock::new(test_connection(
            WsReplayStatus::Connected,
            Some(tx),
        )));
        store
            .connections
            .write()
            .await
            .insert(id, connection.clone());

        store.remove(id).await;

        assert!(store.snapshot(id).await.is_none());
        assert_eq!(connection.read().await.status, WsReplayStatus::Disconnected);
        assert!(matches!(
            rx.recv().await,
            Some(WsReplayOutboundMessage::Close {
                recorded_index: None
            })
        ));
    }

    #[tokio::test]
    async fn remove_aborts_connecting_connection_task() {
        let store = WsReplayStore::new();
        let id = Uuid::new_v4();
        let (abort, _registration) = AbortHandle::new_pair();
        let mut connection = test_connection(WsReplayStatus::Connecting, None);
        connection.task_abort = Some(abort.clone());
        store
            .connections
            .write()
            .await
            .insert(id, Arc::new(RwLock::new(connection)));

        store.remove(id).await;

        assert!(abort.is_aborted());
        assert!(store.snapshot(id).await.is_none());
    }

    #[tokio::test]
    async fn disconnect_connected_connection_queues_close_before_abort_grace() {
        let store = WsReplayStore::new();
        let id = Uuid::new_v4();
        let (tx, mut rx) = test_channel();
        let (abort, _registration) = AbortHandle::new_pair();
        let mut connection_state = test_connection(WsReplayStatus::Connected, Some(tx));
        connection_state.task_abort = Some(abort.clone());
        let connection = Arc::new(RwLock::new(connection_state));
        store
            .connections
            .write()
            .await
            .insert(id, connection.clone());

        store.disconnect(id).await.unwrap();

        let close_frame = connection
            .read()
            .await
            .frames
            .iter()
            .find(|frame| matches!(frame.kind, WebSocketFrameKind::Close))
            .cloned()
            .expect("disconnect should record the client close frame before returning");
        assert!(matches!(
            rx.recv().await,
            Some(WsReplayOutboundMessage::Close {
                recorded_index: Some(index)
            }) if index == close_frame.index
        ));
        assert!(!abort.is_aborted());
    }

    #[tokio::test]
    async fn send_then_disconnect_records_outbound_frame_before_close() {
        let store = WsReplayStore::new();
        let id = Uuid::new_v4();
        let (tx, mut rx) = test_channel();
        let (abort, _registration) = AbortHandle::new_pair();
        let mut connection_state = test_connection(WsReplayStatus::Connected, Some(tx));
        connection_state.task_abort = Some(abort.clone());
        let connection = Arc::new(RwLock::new(connection_state));
        store
            .connections
            .write()
            .await
            .insert(id, connection.clone());

        store.send_text(id, "hello".to_string()).await.unwrap();
        store.disconnect(id).await.unwrap();

        let frames = connection.read().await.frames.clone();
        assert_eq!(frames.len(), 2);
        assert!(matches!(frames[0].kind, WebSocketFrameKind::Text));
        assert!(matches!(frames[1].kind, WebSocketFrameKind::Close));
        assert_eq!(frames[0].index, 0);
        assert_eq!(frames[1].index, 1);

        assert!(matches!(
            rx.recv().await,
            Some(WsReplayOutboundMessage::Message {
                msg: WsMessage::Text(text),
                recorded_index: Some(0),
            }) if text == "hello"
        ));
        assert!(matches!(
            rx.recv().await,
            Some(WsReplayOutboundMessage::Close {
                recorded_index: Some(1)
            })
        ));
        assert!(!abort.is_aborted());
    }

    #[tokio::test]
    async fn disconnect_full_queue_aborts_writer_and_drops_synthetic_close() {
        let store = WsReplayStore::new();
        let id = Uuid::new_v4();
        let (tx, mut rx) = mpsc::channel(1);
        tx.try_send(WsReplayOutboundMessage::Message {
            msg: WsMessage::Text("queued".into()),
            recorded_index: None,
        })
        .unwrap();
        let (task_abort, _task_registration) = AbortHandle::new_pair();
        let (writer_abort, _writer_registration) = AbortHandle::new_pair();
        let mut connection_state = test_connection(WsReplayStatus::Connected, Some(tx));
        connection_state.task_abort = Some(task_abort.clone());
        connection_state.writer_abort = Some(writer_abort.clone());
        let connection = Arc::new(RwLock::new(connection_state));
        store
            .connections
            .write()
            .await
            .insert(id, connection.clone());

        store.disconnect(id).await.unwrap();

        assert!(task_abort.is_aborted());
        assert!(writer_abort.is_aborted());
        assert_eq!(connection.read().await.status, WsReplayStatus::Disconnected);
        assert!(connection.read().await.frames.is_empty());
        assert!(matches!(
            rx.recv().await,
            Some(WsReplayOutboundMessage::Message {
                msg: WsMessage::Text(text),
                recorded_index: None,
            }) if text == "queued"
        ));
    }

    #[tokio::test]
    async fn remove_full_queue_aborts_writer_and_removes_connection() {
        let store = WsReplayStore::new();
        let id = Uuid::new_v4();
        let (tx, mut rx) = mpsc::channel(1);
        tx.try_send(WsReplayOutboundMessage::Message {
            msg: WsMessage::Text("queued".into()),
            recorded_index: None,
        })
        .unwrap();
        let (task_abort, _task_registration) = AbortHandle::new_pair();
        let (writer_abort, _writer_registration) = AbortHandle::new_pair();
        let mut connection_state = test_connection(WsReplayStatus::Connected, Some(tx));
        connection_state.task_abort = Some(task_abort.clone());
        connection_state.writer_abort = Some(writer_abort.clone());
        let connection = Arc::new(RwLock::new(connection_state));
        store.connections.write().await.insert(id, connection);

        store.remove(id).await;

        assert!(task_abort.is_aborted());
        assert!(writer_abort.is_aborted());
        assert!(store.snapshot(id).await.is_none());
        assert!(matches!(
            rx.recv().await,
            Some(WsReplayOutboundMessage::Message {
                msg: WsMessage::Text(text),
                recorded_index: None,
            }) if text == "queued"
        ));
    }

    #[tokio::test]
    async fn send_ping_queues_control_frame() {
        let store = WsReplayStore::new();
        let id = Uuid::new_v4();
        let (tx, mut rx) = test_channel();
        store.connections.write().await.insert(
            id,
            Arc::new(RwLock::new(test_connection(
                WsReplayStatus::Connected,
                Some(tx),
            ))),
        );

        store.send_ping(id, b"hi".to_vec()).await.unwrap();

        match rx.recv().await {
            Some(WsReplayOutboundMessage::Message {
                msg: WsMessage::Ping(payload),
                recorded_index: Some(_),
            }) => {
                assert_eq!(payload.as_ref(), b"hi")
            }
            other => panic!("expected ping frame, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn send_rejects_when_outbound_queue_is_full() {
        let store = WsReplayStore::new();
        let id = Uuid::new_v4();
        let (tx, mut rx) = mpsc::channel(1);
        tx.try_send(WsReplayOutboundMessage::Message {
            msg: WsMessage::Text("queued".into()),
            recorded_index: None,
        })
        .unwrap();
        store.connections.write().await.insert(
            id,
            Arc::new(RwLock::new(test_connection(
                WsReplayStatus::Connected,
                Some(tx),
            ))),
        );

        let error = store
            .send_text(id, "overflow".to_string())
            .await
            .unwrap_err();

        assert!(matches!(
            error.downcast_ref::<WsReplaySendError>(),
            Some(WsReplaySendError::QueueFull)
        ));
        assert!(matches!(
            rx.recv().await,
            Some(WsReplayOutboundMessage::Message {
                msg: WsMessage::Text(text),
                recorded_index: None,
            }) if text == "queued"
        ));
    }

    #[tokio::test]
    async fn disconnect_all_closes_and_removes_connections() {
        let store = WsReplayStore::new();
        let id = Uuid::new_v4();
        let (tx, mut rx) = test_channel();
        let connection = Arc::new(RwLock::new(test_connection(
            WsReplayStatus::Connected,
            Some(tx),
        )));
        store
            .connections
            .write()
            .await
            .insert(id, connection.clone());

        store.disconnect_all().await;

        assert!(store.connections.read().await.is_empty());
        assert_eq!(connection.read().await.status, WsReplayStatus::Disconnected);
        assert!(matches!(
            rx.recv().await,
            Some(WsReplayOutboundMessage::Close {
                recorded_index: None
            })
        ));
    }
}
