use std::collections::VecDeque;

use chrono::{DateTime, Utc};
use tokio::sync::{broadcast, RwLock};
use uuid::Uuid;

use crate::model::{WebSocketFrameRecord, WebSocketSessionRecord, WebSocketSessionSummary};

pub struct WebSocketStore {
    max_entries: usize,
    max_frames_per_session: usize,
    sessions: RwLock<VecDeque<WebSocketSessionRecord>>,
    events: broadcast::Sender<WebSocketSessionSummary>,
}

impl WebSocketStore {
    pub fn new(max_entries: usize, max_frames_per_session: usize) -> Self {
        Self::from_sessions(max_entries, max_frames_per_session, Vec::new())
    }

    pub fn from_sessions(
        max_entries: usize,
        max_frames_per_session: usize,
        records: Vec<WebSocketSessionRecord>,
    ) -> Self {
        let (events, _) = broadcast::channel(max_entries.max(32));
        let mut sessions = VecDeque::with_capacity(max_entries);
        sessions.extend(records.into_iter().take(max_entries));
        Self {
            max_entries,
            max_frames_per_session,
            sessions: RwLock::new(sessions),
            events,
        }
    }

    pub async fn open(&self, session: WebSocketSessionRecord) {
        let summary = session.summary();
        let mut sessions = self.sessions.write().await;
        sessions.push_front(session);
        while sessions.len() > self.max_entries {
            sessions.pop_back();
        }
        let _ = self.events.send(summary);
    }

    pub async fn append_frame(&self, id: Uuid, frame: WebSocketFrameRecord) {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.iter_mut().find(|session| session.id == id) {
            session.frames.push(frame);
            if session.frames.len() > self.max_frames_per_session {
                let overflow = session.frames.len() - self.max_frames_per_session;
                session.frames.drain(..overflow);
            }
            let _ = self.events.send(session.summary());
        }
    }

    pub async fn close(
        &self,
        id: Uuid,
        closed_at: DateTime<Utc>,
        duration_ms: u64,
        note: Option<String>,
    ) {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.iter_mut().find(|session| session.id == id) {
            session.closed_at = Some(closed_at);
            session.duration_ms = Some(duration_ms);
            if let Some(note) = note {
                session.notes.push(note);
            }
            let _ = self.events.send(session.summary());
        }
    }

    pub async fn list(&self, limit: Option<usize>) -> Vec<WebSocketSessionSummary> {
        let sessions = self.sessions.read().await;
        sessions
            .iter()
            .take(limit.unwrap_or(self.max_entries).min(self.max_entries))
            .map(WebSocketSessionRecord::summary)
            .collect()
    }

    pub async fn get(&self, id: Uuid) -> Option<WebSocketSessionRecord> {
        self.sessions
            .read()
            .await
            .iter()
            .find(|session| session.id == id)
            .cloned()
    }

    pub async fn snapshot(&self, limit: Option<usize>) -> Vec<WebSocketSessionRecord> {
        let sessions = self.sessions.read().await;
        sessions
            .iter()
            .take(limit.unwrap_or(self.max_entries).min(self.max_entries))
            .cloned()
            .collect()
    }

    pub async fn replace_all(&self, records: Vec<WebSocketSessionRecord>) {
        let mut sessions = self.sessions.write().await;
        sessions.clear();
        sessions.extend(
            records
                .into_iter()
                .take(self.max_entries)
                .map(|mut session| {
                    if session.frames.len() > self.max_frames_per_session {
                        let overflow = session.frames.len() - self.max_frames_per_session;
                        session.frames.drain(..overflow);
                    }
                    session
                }),
        );
    }

    pub fn subscribe(&self) -> broadcast::Receiver<WebSocketSessionSummary> {
        self.events.subscribe()
    }
}
