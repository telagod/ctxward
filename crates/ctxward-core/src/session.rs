use std::{
    collections::{HashMap, HashSet},
    time::{Duration, Instant},
};

use parking_lot::Mutex;

use crate::config::SessionConfig;

#[derive(Clone, Debug)]
struct SessionEntry {
    labels: HashSet<String>,
    updated_at: Instant,
}

#[derive(Default)]
pub struct SessionStore {
    inner: Mutex<HashMap<String, SessionEntry>>,
}

impl SessionStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_and_check(
        &self,
        session_id: &str,
        labels: impl IntoIterator<Item = String>,
        config: &SessionConfig,
    ) -> bool {
        if !config.enabled || session_id.is_empty() {
            return false;
        }

        let ttl = Duration::from_secs(config.ttl_secs);
        let now = Instant::now();
        let mut guard = self.inner.lock();
        guard.retain(|_, entry| now.duration_since(entry.updated_at) <= ttl);

        if guard.len() >= config.max_entries
            && !guard.contains_key(session_id)
            && let Some(oldest_key) = guard
                .iter()
                .min_by_key(|(_, entry)| entry.updated_at)
                .map(|(key, _)| key.clone())
        {
            guard.remove(&oldest_key);
        }

        let entry = guard.entry(session_id.to_string()).or_insert(SessionEntry {
            labels: HashSet::new(),
            updated_at: now,
        });
        entry.updated_at = now;
        entry.labels.extend(labels);

        entry.labels.len() >= config.correlation_threshold
    }

    pub fn active_sessions(&self, config: &SessionConfig) -> usize {
        if !config.enabled {
            return 0;
        }
        let ttl = Duration::from_secs(config.ttl_secs);
        let now = Instant::now();
        let mut guard = self.inner.lock();
        guard.retain(|_, entry| now.duration_since(entry.updated_at) <= ttl);
        guard.len()
    }
}
