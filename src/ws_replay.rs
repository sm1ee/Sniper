use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result};
use chrono::Utc;
use futures_util::{SinkExt, StreamExt};
use http::{HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, RwLock};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{client::IntoClientRequest, protocol::Message as WsMessage},
};
use tracing::warn;
use uuid::Uuid;

use crate::model::{BodyEncoding, WebSocketFrameDirection, WebSocketFrameKind};

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

/// Sender half to push messages into the WebSocket.
type WsSender = mpsc::UnboundedSender<WsMessage>;

/// Internal state for a single WS replay connection.
struct WsReplayConnection {
    status: WsReplayStatus,
    frames: Vec<WsReplayFrame>,
    frame_counter: usize,
    sender: Option<WsSender>,
    error: Option<String>,
}

impl WsReplayConnection {
    fn snapshot(&self, id: Uuid) -> WsReplaySnapshot {
        WsReplaySnapshot {
            id,
            status: self.status.clone(),
            frames: self.frames.clone(),
            error: self.error.clone(),
        }
    }

    fn push_frame(&mut self, direction: WebSocketFrameDirection, msg: &WsMessage) {
        let (kind, body, encoding, size) = match msg {
            WsMessage::Text(text) => (
                WebSocketFrameKind::Text,
                text.to_string(),
                BodyEncoding::Utf8,
                text.len(),
            ),
            WsMessage::Binary(data) => {
                use base64::Engine;
                let b64 = base64::engine::general_purpose::STANDARD.encode(data.as_ref());
                (
                    WebSocketFrameKind::Binary,
                    b64,
                    BodyEncoding::Base64,
                    data.len(),
                )
            }
            WsMessage::Ping(data) => {
                use base64::Engine;
                (
                    WebSocketFrameKind::Ping,
                    base64::engine::general_purpose::STANDARD.encode(data.as_ref()),
                    BodyEncoding::Base64,
                    data.len(),
                )
            }
            WsMessage::Pong(data) => {
                use base64::Engine;
                (
                    WebSocketFrameKind::Pong,
                    base64::engine::general_purpose::STANDARD.encode(data.as_ref()),
                    BodyEncoding::Base64,
                    data.len(),
                )
            }
            WsMessage::Close(frame) => {
                let text = frame
                    .as_ref()
                    .map(|f| format!("{}: {}", f.code, f.reason))
                    .unwrap_or_default();
                let size = text.len();
                (WebSocketFrameKind::Close, text, BodyEncoding::Utf8, size)
            }
            WsMessage::Frame(_) => return,
        };

        let frame = WsReplayFrame {
            index: self.frame_counter,
            captured_at: Utc::now().to_rfc3339(),
            direction,
            kind,
            body,
            body_encoding: encoding,
            body_size: size,
        };
        self.frame_counter += 1;
        self.frames.push(frame);
    }
}

/// Manages all active WS replay connections.
pub struct WsReplayStore {
    connections: RwLock<HashMap<Uuid, Arc<RwLock<WsReplayConnection>>>>,
}

impl WsReplayStore {
    pub fn new() -> Self {
        Self {
            connections: RwLock::new(HashMap::new()),
        }
    }

    /// Connect to a WebSocket server.
    pub async fn connect(
        &self,
        id: Uuid,
        url: &str,
        extra_headers: Vec<(String, String)>,
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
                    headers.insert(n, v);
                }
            }
        }

        // Create connection entry
        let conn = Arc::new(RwLock::new(WsReplayConnection {
            status: WsReplayStatus::Connecting,
            frames: Vec::new(),
            frame_counter: 0,
            sender: None,
            error: None,
        }));
        self.connections.write().await.insert(id, conn.clone());

        // Connect in the background
        tokio::spawn(async move {
            match connect_async(request).await {
                Ok((ws_stream, _response)) => {
                    let (mut write, mut read) = ws_stream.split();
                    let (tx, mut rx) = mpsc::unbounded_channel::<WsMessage>();

                    {
                        let mut c = conn.write().await;
                        c.status = WsReplayStatus::Connected;
                        c.sender = Some(tx);
                    }

                    // Spawn writer task
                    let conn_for_writer = conn.clone();
                    let write_task = tokio::spawn(async move {
                        while let Some(msg) = rx.recv().await {
                            // Record outgoing frame
                            {
                                let mut c = conn_for_writer.write().await;
                                c.push_frame(WebSocketFrameDirection::ClientToServer, &msg);
                            }
                            if write.send(msg).await.is_err() {
                                break;
                            }
                        }
                    });

                    // Read incoming messages
                    while let Some(msg_result) = read.next().await {
                        match msg_result {
                            Ok(msg) => {
                                // Auto-respond to pings
                                if let WsMessage::Ping(data) = &msg {
                                    let mut c = conn.write().await;
                                    c.push_frame(WebSocketFrameDirection::ServerToClient, &msg);
                                    if let Some(sender) = &c.sender {
                                        let _ = sender.send(WsMessage::Pong(data.clone()));
                                    }
                                    continue;
                                }

                                let is_close = matches!(msg, WsMessage::Close(_));
                                {
                                    let mut c = conn.write().await;
                                    c.push_frame(WebSocketFrameDirection::ServerToClient, &msg);
                                }
                                if is_close {
                                    break;
                                }
                            }
                            Err(e) => {
                                warn!("ws replay read error: {}", e);
                                break;
                            }
                        }
                    }

                    // Clean up
                    write_task.abort();
                    let mut c = conn.write().await;
                    c.status = WsReplayStatus::Disconnected;
                    c.sender = None;
                }
                Err(e) => {
                    let mut c = conn.write().await;
                    c.status = WsReplayStatus::Error;
                    c.error = Some(e.to_string());
                    c.sender = None;
                }
            }
        });

        Ok(())
    }

    /// Send a text message on an existing connection.
    pub async fn send_text(&self, id: Uuid, text: String) -> Result<()> {
        let connections = self.connections.read().await;
        let conn = connections
            .get(&id)
            .context("no such WS replay connection")?;
        let c = conn.read().await;
        let sender = c.sender.as_ref().context("connection is not open")?;
        sender
            .send(WsMessage::Text(text.into()))
            .map_err(|_| anyhow::anyhow!("failed to send message"))?;
        Ok(())
    }

    /// Send a binary message on an existing connection.
    pub async fn send_binary(&self, id: Uuid, data: Vec<u8>) -> Result<()> {
        let connections = self.connections.read().await;
        let conn = connections
            .get(&id)
            .context("no such WS replay connection")?;
        let c = conn.read().await;
        let sender = c.sender.as_ref().context("connection is not open")?;
        sender
            .send(WsMessage::Binary(data.into()))
            .map_err(|_| anyhow::anyhow!("failed to send message"))?;
        Ok(())
    }

    /// Disconnect an active connection.
    pub async fn disconnect(&self, id: Uuid) -> Result<()> {
        let connections = self.connections.read().await;
        if let Some(conn) = connections.get(&id) {
            let mut c = conn.write().await;
            if let Some(sender) = c.sender.take() {
                let _ = sender.send(WsMessage::Close(None));
            }
            c.status = WsReplayStatus::Disconnected;
        }
        Ok(())
    }

    /// Get the current snapshot of a connection (status + all frames).
    pub async fn snapshot(&self, id: Uuid) -> Option<WsReplaySnapshot> {
        let connections = self.connections.read().await;
        let conn = connections.get(&id)?;
        let c = conn.read().await;
        Some(c.snapshot(id))
    }

    /// Get frames since a given index (for polling).
    pub async fn frames_since(
        &self,
        id: Uuid,
        since_index: usize,
    ) -> Option<(WsReplayStatus, Vec<WsReplayFrame>)> {
        let connections = self.connections.read().await;
        let conn = connections.get(&id)?;
        let c = conn.read().await;
        let new_frames: Vec<WsReplayFrame> = c
            .frames
            .iter()
            .filter(|f| f.index >= since_index)
            .cloned()
            .collect();
        Some((c.status.clone(), new_frames))
    }

    /// Remove a connection and its data.
    pub async fn remove(&self, id: Uuid) {
        self.disconnect(id).await.ok();
        self.connections.write().await.remove(&id);
    }
}
