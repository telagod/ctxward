use std::{
    collections::VecDeque,
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{error, info};

#[derive(Clone)]
pub struct AuditSink {
    path: PathBuf,
    store: Arc<AuditStore>,
    sender: mpsc::UnboundedSender<AuditRecord>,
}

impl AuditSink {
    pub fn new(
        path: impl AsRef<Path>,
        emit_stdout: bool,
        store: Arc<AuditStore>,
    ) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        let (sender, mut receiver) = mpsc::unbounded_channel::<AuditRecord>();
        tokio::spawn(async move {
            let mut file = file;
            while let Some(record) = receiver.recv().await {
                match serde_json::to_string(&record) {
                    Ok(line) => {
                        if let Err(err) = writeln!(file, "{line}") {
                            error!(error = %err, "failed to write audit record");
                        }
                        if emit_stdout {
                            info!(target: "audit", "{line}");
                        }
                    }
                    Err(err) => error!(error = %err, "failed to serialize audit record"),
                }
            }
        });
        Ok(Self {
            path,
            store,
            sender,
        })
    }

    pub fn emit(&self, record: AuditRecord) {
        self.store.push(record.clone());
        let _ = self.sender.send(record);
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[derive(Default)]
pub struct AuditStore {
    inner: Mutex<AuditStoreInner>,
}

#[derive(Default)]
struct AuditStoreInner {
    capacity: usize,
    records: VecDeque<AuditRecord>,
}

impl AuditStore {
    pub fn new(capacity: usize) -> Self {
        let store = Self::default();
        store.set_capacity(capacity);
        store
    }

    pub fn set_capacity(&self, capacity: usize) {
        let mut guard = self.inner.lock();
        guard.capacity = capacity.max(1);
        while guard.records.len() > guard.capacity {
            guard.records.pop_front();
        }
    }

    pub fn push(&self, record: AuditRecord) {
        let mut guard = self.inner.lock();
        if guard.capacity == 0 {
            guard.capacity = 1000;
        }
        if guard.records.len() >= guard.capacity {
            guard.records.pop_front();
        }
        guard.records.push_back(record);
    }

    pub fn snapshot(&self) -> Vec<AuditRecord> {
        self.inner.lock().records.iter().cloned().collect()
    }

    pub fn len(&self) -> usize {
        self.inner.lock().records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn capacity(&self) -> usize {
        self.inner.lock().capacity
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditSource {
    Memory,
    File,
    Both,
}

pub fn read_recent_audit_file(
    path: impl AsRef<Path>,
    limit: usize,
) -> std::io::Result<Vec<AuditRecord>> {
    let file = match File::open(path.as_ref()) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err),
    };

    let reader = BufReader::new(file);
    let mut parsed = reader
        .lines()
        .map_while(Result::ok)
        .filter_map(|line| serde_json::from_str::<AuditRecord>(&line).ok())
        .collect::<Vec<_>>();
    if parsed.len() > limit {
        parsed.drain(0..parsed.len() - limit);
    }
    Ok(parsed)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct AuditRecord {
    pub ts: DateTime<Utc>,
    pub request_id: String,
    pub principal: String,
    pub tenant_id: String,
    pub direction: String,
    pub path: String,
    pub decision: String,
    pub policy_source: String,
    pub decision_reason: Option<String>,
    pub matched_labels: Vec<String>,
    pub matched_rules: Vec<String>,
    pub findings: Vec<AuditFinding>,
    pub session_id: Option<String>,
    pub session_escalated: bool,
    pub status_code: Option<u16>,
    pub error_stage: Option<String>,
    pub error_kind: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct AuditFinding {
    pub label: String,
    pub rule_name: String,
    pub action: String,
    pub pointer: String,
    pub severity: String,
    pub matched_sha256: String,
    pub matched_len: usize,
}
