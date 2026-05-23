use std::{
    collections::{HashMap, VecDeque},
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
};

use chrono::{DateTime, Duration, Utc};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{audit::AuditFinding, types::DecisionAction};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReviewStatus {
    Pending,
    Approved,
    Rejected,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReviewResolution {
    pub resolved_at: DateTime<Utc>,
    pub resolved_by: String,
    pub note: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReviewTicket {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub status: ReviewStatus,
    pub request_id: String,
    pub principal: String,
    pub tenant_id: String,
    pub direction: String,
    pub path: String,
    pub policy_source: String,
    pub decision_reason: Option<String>,
    pub matched_labels: Vec<String>,
    pub matched_rules: Vec<String>,
    pub findings: Vec<AuditFinding>,
    pub session_id: Option<String>,
    pub session_escalated: bool,
    pub request_sha256: String,
    pub sanitized_preview: Option<String>,
    pub post_approval_action: DecisionAction,
    pub resolution: Option<ReviewResolution>,
    #[serde(skip)]
    pub fingerprint: String,
}

#[derive(Clone)]
pub struct NewReviewTicket {
    pub request_id: String,
    pub principal: String,
    pub tenant_id: String,
    pub direction: String,
    pub path: String,
    pub policy_source: String,
    pub decision_reason: Option<String>,
    pub matched_labels: Vec<String>,
    pub matched_rules: Vec<String>,
    pub findings: Vec<AuditFinding>,
    pub session_id: Option<String>,
    pub session_escalated: bool,
    pub request_sha256: String,
    pub sanitized_preview: Option<String>,
    pub post_approval_action: DecisionAction,
    pub fingerprint: String,
}

#[derive(Clone, Debug)]
pub enum ReviewDecisionOverride {
    Approved {
        ticket_id: String,
        action: DecisionAction,
        resolved_by: String,
    },
    Rejected {
        ticket_id: String,
        resolved_by: String,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReviewFilterStatus {
    Pending,
    Approved,
    Rejected,
    All,
}

#[derive(Debug, Error)]
pub enum ReviewResolveError {
    #[error("review ticket not found")]
    NotFound,
    #[error("review ticket already resolved as {0:?}")]
    AlreadyResolved(ReviewStatus),
}

#[derive(Debug, Error)]
pub enum ReviewStoreError {
    #[error("failed to open review store {path}: {source}")]
    Open {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to append review event to {path}: {source}")]
    Append {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to serialize review event: {0}")]
    Serialize(serde_json::Error),
}

pub struct ReviewStore {
    path: PathBuf,
    inner: Mutex<ReviewStoreInner>,
}

#[derive(Default)]
struct ReviewStoreInner {
    capacity: usize,
    order: VecDeque<String>,
    tickets: HashMap<String, ReviewTicket>,
    pending_by_fingerprint: HashMap<String, String>,
    overrides_by_fingerprint: HashMap<String, StoredOverride>,
}

#[derive(Clone, Debug)]
struct StoredOverride {
    decision: ReviewDecisionOverride,
    expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ReviewEvent {
    Created {
        ticket: Box<PersistedReviewTicket>,
    },
    Resolved {
        ticket_id: String,
        status: ReviewStatus,
        resolved_by: String,
        note: Option<String>,
        resolved_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PersistedReviewTicket {
    id: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    status: ReviewStatus,
    request_id: String,
    principal: String,
    tenant_id: String,
    direction: String,
    path: String,
    policy_source: String,
    decision_reason: Option<String>,
    matched_labels: Vec<String>,
    matched_rules: Vec<String>,
    findings: Vec<AuditFinding>,
    session_id: Option<String>,
    session_escalated: bool,
    request_sha256: String,
    sanitized_preview: Option<String>,
    post_approval_action: DecisionAction,
    resolution: Option<ReviewResolution>,
    fingerprint: String,
}

impl ReviewStore {
    pub fn new(path: impl AsRef<Path>, capacity: usize) -> Result<Self, ReviewStoreError> {
        let path = path.as_ref().to_path_buf();
        let _ = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|source| ReviewStoreError::Open {
                path: path.display().to_string(),
                source,
            })?;
        let store = Self {
            path,
            inner: Mutex::new(ReviewStoreInner::default()),
        };
        {
            let mut guard = store.inner.lock();
            guard.capacity = capacity.max(1);
            store.load_existing(&mut guard);
            trim_to_capacity(&mut guard);
        }
        Ok(store)
    }

    pub fn set_capacity(&self, capacity: usize) {
        let mut guard = self.inner.lock();
        guard.capacity = capacity.max(1);
        trim_to_capacity(&mut guard);
    }

    pub fn upsert_pending(
        &self,
        new_ticket: NewReviewTicket,
    ) -> Result<ReviewTicket, ReviewStoreError> {
        let now = Utc::now();
        let mut guard = self.inner.lock();
        prune_expired_overrides(&mut guard, now);

        if let Some(ticket_id) = guard.pending_by_fingerprint.get(&new_ticket.fingerprint)
            && let Some(ticket) = guard.tickets.get(ticket_id)
        {
            return Ok(ticket.clone());
        }

        let id = uuid::Uuid::new_v4().to_string();
        let ticket = ReviewTicket {
            id: id.clone(),
            created_at: now,
            updated_at: now,
            status: ReviewStatus::Pending,
            request_id: new_ticket.request_id,
            principal: new_ticket.principal,
            tenant_id: new_ticket.tenant_id,
            direction: new_ticket.direction,
            path: new_ticket.path,
            policy_source: new_ticket.policy_source,
            decision_reason: new_ticket.decision_reason,
            matched_labels: new_ticket.matched_labels,
            matched_rules: new_ticket.matched_rules,
            findings: new_ticket.findings,
            session_id: new_ticket.session_id,
            session_escalated: new_ticket.session_escalated,
            request_sha256: new_ticket.request_sha256,
            sanitized_preview: new_ticket.sanitized_preview,
            post_approval_action: new_ticket.post_approval_action,
            resolution: None,
            fingerprint: new_ticket.fingerprint.clone(),
        };
        append_review_event(
            &self.path,
            &ReviewEvent::Created {
                ticket: Box::new(PersistedReviewTicket::from_ticket(&ticket)),
            },
        )?;
        guard
            .pending_by_fingerprint
            .insert(new_ticket.fingerprint, id.clone());
        guard.order.push_back(id.clone());
        guard.tickets.insert(id, ticket.clone());
        trim_to_capacity(&mut guard);
        Ok(ticket)
    }

    pub fn lookup_override(&self, fingerprint: &str) -> Option<ReviewDecisionOverride> {
        let now = Utc::now();
        let mut guard = self.inner.lock();
        prune_expired_overrides(&mut guard, now);
        guard
            .overrides_by_fingerprint
            .get(fingerprint)
            .map(|stored| stored.decision.clone())
    }

    pub fn get(&self, id: &str) -> Option<ReviewTicket> {
        let now = Utc::now();
        let mut guard = self.inner.lock();
        prune_expired_overrides(&mut guard, now);
        guard.tickets.get(id).cloned()
    }

    pub fn resolve(
        &self,
        id: &str,
        status: ReviewStatus,
        resolved_by: String,
        note: Option<String>,
        ttl_secs: u64,
    ) -> Result<ReviewTicket, ReviewResolveError> {
        let now = Utc::now();
        let mut guard = self.inner.lock();
        prune_expired_overrides(&mut guard, now);
        let (fingerprint, resolved_ticket, expires_at) = {
            let ticket = guard
                .tickets
                .get_mut(id)
                .ok_or(ReviewResolveError::NotFound)?;

            if ticket.status != ReviewStatus::Pending {
                return Err(ReviewResolveError::AlreadyResolved(ticket.status));
            }

            let expires_at = now + Duration::seconds(ttl_secs as i64);
            ticket.status = status;
            ticket.updated_at = now;
            ticket.resolution = Some(ReviewResolution {
                resolved_at: now,
                resolved_by: resolved_by.clone(),
                note: note.clone(),
                expires_at: Some(expires_at),
            });
            (ticket.fingerprint.clone(), ticket.clone(), expires_at)
        };

        append_review_event(
            &self.path,
            &ReviewEvent::Resolved {
                ticket_id: id.to_string(),
                status,
                resolved_by: resolved_by.clone(),
                note: note.clone(),
                resolved_at: now,
                expires_at,
            },
        )
        .map_err(|err| match err {
            ReviewStoreError::Open { .. }
            | ReviewStoreError::Append { .. }
            | ReviewStoreError::Serialize(_) => ReviewResolveError::NotFound,
        })?;

        guard.pending_by_fingerprint.remove(&fingerprint);
        let override_decision = match status {
            ReviewStatus::Approved => ReviewDecisionOverride::Approved {
                ticket_id: resolved_ticket.id.clone(),
                action: resolved_ticket.post_approval_action,
                resolved_by,
            },
            ReviewStatus::Rejected => ReviewDecisionOverride::Rejected {
                ticket_id: resolved_ticket.id.clone(),
                resolved_by,
            },
            ReviewStatus::Pending => unreachable!("pending cannot resolve pending ticket"),
        };
        guard.overrides_by_fingerprint.insert(
            fingerprint,
            StoredOverride {
                decision: override_decision,
                expires_at,
            },
        );
        Ok(resolved_ticket)
    }

    pub fn list(&self, status: ReviewFilterStatus, limit: usize) -> Vec<ReviewTicket> {
        let now = Utc::now();
        let mut guard = self.inner.lock();
        prune_expired_overrides(&mut guard, now);
        guard
            .order
            .iter()
            .rev()
            .filter_map(|id| guard.tickets.get(id))
            .filter(|ticket| match status {
                ReviewFilterStatus::Pending => ticket.status == ReviewStatus::Pending,
                ReviewFilterStatus::Approved => ticket.status == ReviewStatus::Approved,
                ReviewFilterStatus::Rejected => ticket.status == ReviewStatus::Rejected,
                ReviewFilterStatus::All => true,
            })
            .take(limit)
            .cloned()
            .collect()
    }

    pub fn pending_count(&self) -> usize {
        let now = Utc::now();
        let mut guard = self.inner.lock();
        prune_expired_overrides(&mut guard, now);
        guard
            .tickets
            .values()
            .filter(|ticket| ticket.status == ReviewStatus::Pending)
            .count()
    }

    fn load_existing(&self, inner: &mut ReviewStoreInner) {
        let file = match File::open(&self.path) {
            Ok(file) => file,
            Err(_) => return,
        };
        let reader = BufReader::new(file);
        for line in reader.lines().map_while(Result::ok) {
            let Ok(event) = serde_json::from_str::<ReviewEvent>(&line) else {
                continue;
            };
            apply_review_event(inner, event);
        }
        let now = Utc::now();
        prune_expired_overrides(inner, now);
    }
}

impl PersistedReviewTicket {
    fn from_ticket(ticket: &ReviewTicket) -> Self {
        Self {
            id: ticket.id.clone(),
            created_at: ticket.created_at,
            updated_at: ticket.updated_at,
            status: ticket.status,
            request_id: ticket.request_id.clone(),
            principal: ticket.principal.clone(),
            tenant_id: ticket.tenant_id.clone(),
            direction: ticket.direction.clone(),
            path: ticket.path.clone(),
            policy_source: ticket.policy_source.clone(),
            decision_reason: ticket.decision_reason.clone(),
            matched_labels: ticket.matched_labels.clone(),
            matched_rules: ticket.matched_rules.clone(),
            findings: ticket.findings.clone(),
            session_id: ticket.session_id.clone(),
            session_escalated: ticket.session_escalated,
            request_sha256: ticket.request_sha256.clone(),
            sanitized_preview: ticket.sanitized_preview.clone(),
            post_approval_action: ticket.post_approval_action,
            resolution: ticket.resolution.clone(),
            fingerprint: ticket.fingerprint.clone(),
        }
    }

    fn into_ticket(self) -> ReviewTicket {
        ReviewTicket {
            id: self.id,
            created_at: self.created_at,
            updated_at: self.updated_at,
            status: self.status,
            request_id: self.request_id,
            principal: self.principal,
            tenant_id: self.tenant_id,
            direction: self.direction,
            path: self.path,
            policy_source: self.policy_source,
            decision_reason: self.decision_reason,
            matched_labels: self.matched_labels,
            matched_rules: self.matched_rules,
            findings: self.findings,
            session_id: self.session_id,
            session_escalated: self.session_escalated,
            request_sha256: self.request_sha256,
            sanitized_preview: self.sanitized_preview,
            post_approval_action: self.post_approval_action,
            resolution: self.resolution,
            fingerprint: self.fingerprint,
        }
    }
}

fn append_review_event(path: &Path, event: &ReviewEvent) -> Result<(), ReviewStoreError> {
    let line = serde_json::to_string(event).map_err(ReviewStoreError::Serialize)?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|source| ReviewStoreError::Append {
            path: path.display().to_string(),
            source,
        })?;
    writeln!(file, "{line}").map_err(|source| ReviewStoreError::Append {
        path: path.display().to_string(),
        source,
    })?;
    Ok(())
}

fn apply_review_event(inner: &mut ReviewStoreInner, event: ReviewEvent) {
    match event {
        ReviewEvent::Created { ticket } => {
            let ticket = ticket.into_ticket();
            inner.order.push_back(ticket.id.clone());
            if ticket.status == ReviewStatus::Pending {
                inner
                    .pending_by_fingerprint
                    .insert(ticket.fingerprint.clone(), ticket.id.clone());
            }
            inner.tickets.insert(ticket.id.clone(), ticket);
        }
        ReviewEvent::Resolved {
            ticket_id,
            status,
            resolved_by,
            note,
            resolved_at,
            expires_at,
        } => {
            if let Some(ticket) = inner.tickets.get_mut(&ticket_id) {
                ticket.status = status;
                ticket.updated_at = resolved_at;
                ticket.resolution = Some(ReviewResolution {
                    resolved_at,
                    resolved_by: resolved_by.clone(),
                    note,
                    expires_at: Some(expires_at),
                });
                inner.pending_by_fingerprint.remove(&ticket.fingerprint);
                let override_decision = match status {
                    ReviewStatus::Approved => ReviewDecisionOverride::Approved {
                        ticket_id: ticket.id.clone(),
                        action: ticket.post_approval_action,
                        resolved_by,
                    },
                    ReviewStatus::Rejected => ReviewDecisionOverride::Rejected {
                        ticket_id: ticket.id.clone(),
                        resolved_by,
                    },
                    ReviewStatus::Pending => return,
                };
                inner.overrides_by_fingerprint.insert(
                    ticket.fingerprint.clone(),
                    StoredOverride {
                        decision: override_decision,
                        expires_at,
                    },
                );
            }
        }
    }
}

fn prune_expired_overrides(inner: &mut ReviewStoreInner, now: DateTime<Utc>) {
    inner
        .overrides_by_fingerprint
        .retain(|_, override_entry| override_entry.expires_at > now);
}

fn trim_to_capacity(inner: &mut ReviewStoreInner) {
    while inner.order.len() > inner.capacity {
        let Some(id) = inner.order.pop_front() else {
            break;
        };
        if let Some(ticket) = inner.tickets.remove(&id) {
            inner.pending_by_fingerprint.remove(&ticket.fingerprint);
            inner.overrides_by_fingerprint.remove(&ticket.fingerprint);
        }
    }
}
