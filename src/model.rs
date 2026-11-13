//! Platform state: cases, provider orders and claims. Persisted as one JSON snapshot.

use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::evidence::{BlockKind, Evidence, Proposal};
use crate::leak::trace::Trace;
use crate::simulator::{Courts, MatchInfo, Provider};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseStatus {
    /// Verification failed (not this match's signal, or a licensee on its own domain): no block requested.
    Dismissed,
    /// Waiting for the judge on duty.
    PendingJudge,
    Approved,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sighting {
    pub detection_id: String,
    pub minute: f64,
    pub received_at: String,
    pub detection_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decision {
    pub judge_id: String,
    pub judge_name: String,
    pub court_id: String,
    pub approved: bool,
    pub measure: Option<BlockKind>,
    pub reason: Option<String>,
    pub minute: f64,
    pub at: String,
    /// HMAC of the decision text with the judge's key (see `crypto::decision_message`).
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Case {
    pub id: String,
    pub created_at: String,
    pub created_min: f64,
    pub stream_key: String,
    pub evidence: Evidence,
    /// Proposed measure; `None` for dismissed cases.
    pub proposal: Option<Proposal>,
    /// SHA-256 over the canonical case core (id, creation time, evidence, proposal).
    pub case_hash: String,
    /// Earlier cases for the same pirate site (the stream changed server).
    pub related_cases: Vec<String>,
    /// Later detections of the same stream on the same server.
    pub sightings: Vec<Sighting>,
    pub status: CaseStatus,
    pub assigned_judge: Option<String>,
    pub decision: Option<Decision>,
}

impl Case {
    pub fn host(&self) -> &str {
        &self.evidence.server.host
    }

    pub fn ip(&self) -> &str {
        &self.evidence.server.ip
    }

    pub fn first_detection_min(&self) -> f64 {
        self.evidence.detection.get("minuto").and_then(serde_json::Value::as_f64).unwrap_or(self.created_min)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderStatus {
    /// A retry or replacement that needs the signature of the judge on duty.
    AwaitingSignature,
    Signed,
    Sending,
    Received,
    Applied,
    /// The provider failed to apply it; a retry was scheduled.
    Failed,
    /// The provider refused it at reception.
    Rejected,
    Expired,
    Lifted,
    /// Never sent or retried because the match was over.
    Abandoned,
}

impl OrderStatus {
    /// Orders that may still block something or still need work.
    pub fn is_open(self) -> bool {
        matches!(
            self,
            OrderStatus::AwaitingSignature
                | OrderStatus::Signed
                | OrderStatus::Sending
                | OrderStatus::Received
                | OrderStatus::Applied
        )
    }

    /// Orders the provider holds and may be applying.
    pub fn at_provider(self) -> bool {
        matches!(self, OrderStatus::Received | OrderStatus::Applied)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderPurpose {
    Original,
    Retry,
    Replacement,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiftStatus {
    Signed,
    Sending,
    Done,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiftRequest {
    pub claim_id: String,
    pub judge_id: String,
    pub signature: String,
    pub reason: String,
    pub requested_min: f64,
    pub status: LiftStatus,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderRecord {
    pub order_id: String,
    pub case_id: String,
    pub provider_id: String,
    pub kind: BlockKind,
    pub target: String,
    pub expires_min: i64,
    pub judge_id: Option<String>,
    pub court_id: Option<String>,
    pub signature: Option<String>,
    pub attempt: u32,
    pub purpose: OrderPurpose,
    pub status: OrderStatus,
    pub created_min: f64,
    pub sent_min: Option<f64>,
    pub applied_min: Option<f64>,
    pub ended_min: Option<f64>,
    pub last_error: Option<String>,
    /// POST attempts for this order id (transport errors are retried with the same id).
    pub send_attempts: u32,
    pub superseded_by: Option<String>,
    pub replaces: Option<String>,
    pub lift: Option<LiftRequest>,
    #[serde(skip)]
    pub next_send_at: Option<Instant>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimVerdict {
    /// The claimant is a legitimate site behind one of our active blocks.
    Legitimate,
    /// The claimant belongs to the pirate site itself.
    PirateSite,
    /// None of our active blocks affects the claimant.
    NoActiveBlock,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimStatus {
    PendingJudge,
    Resolved,
    Rejected,
    /// Closed without a decision: no active block affected the claimant any more.
    Closed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimDecision {
    pub judge_id: String,
    pub judge_name: String,
    pub approved: bool,
    pub reason: Option<String>,
    pub minute: f64,
    pub at: String,
    pub signature: String,
    pub lifted_orders: Vec<String>,
    pub replacement_orders: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claim {
    pub id: String,
    pub minute: f64,
    pub received_at: String,
    pub domain: String,
    pub provider_id: String,
    pub message: String,
    pub verdict: ClaimVerdict,
    pub is_licensee: bool,
    /// Our orders (any provider) whose block reaches the claimant.
    pub affected_orders: Vec<String>,
    pub cases: Vec<String>,
    pub status: ClaimStatus,
    pub assigned_judge: Option<String>,
    pub decision: Option<ClaimDecision>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Store {
    /// Short random id of this platform run, part of every order id so restarts never collide.
    pub run_id: String,
    pub match_info: Option<MatchInfo>,
    pub providers: Vec<Provider>,
    pub courts: Option<Courts>,
    pub detection_cursor: f64,
    pub claim_cursor: f64,
    pub case_seq: u64,
    pub cases: Vec<Case>,
    pub orders: Vec<OrderRecord>,
    pub claims: Vec<Claim>,
    /// Leak traces (pirate streams read for a session mark).
    #[serde(default)]
    pub traces: Vec<Trace>,
    #[serde(default)]
    pub trace_seq: u64,
    /// Detections loaded by hand or through the intake API (ids `M-0001`, ...).
    #[serde(default)]
    pub intake_seq: u64,
    /// Bumped on every change a judge might need to see.
    pub inbox_version: u64,
    #[serde(skip)]
    pub dirty: bool,
}

impl Store {
    pub fn new(run_id: String) -> Self {
        Store { run_id, detection_cursor: -1.0e9, claim_cursor: -1.0e9, ..Store::default() }
    }

    pub fn case(&self, id: &str) -> Option<&Case> {
        self.cases.iter().find(|c| c.id == id)
    }

    pub fn case_mut(&mut self, id: &str) -> Option<&mut Case> {
        self.cases.iter_mut().find(|c| c.id == id)
    }

    pub fn order(&self, id: &str) -> Option<&OrderRecord> {
        self.orders.iter().find(|o| o.order_id == id)
    }

    pub fn order_mut(&mut self, id: &str) -> Option<&mut OrderRecord> {
        self.orders.iter_mut().find(|o| o.order_id == id)
    }

    pub fn trace(&self, id: &str) -> Option<&Trace> {
        self.traces.iter().find(|t| t.id == id)
    }

    pub fn claim(&self, id: &str) -> Option<&Claim> {
        self.claims.iter().find(|c| c.id == id)
    }

    pub fn provider(&self, id: &str) -> Option<&Provider> {
        self.providers.iter().find(|p| p.id == id)
    }

    pub fn orders_of_case<'a>(&'a self, case_id: &'a str) -> impl Iterator<Item = &'a OrderRecord> + 'a {
        self.orders.iter().filter(move |o| o.case_id == case_id)
    }

    pub fn judge_name(&self, judge_id: &str) -> String {
        self.courts
            .as_ref()
            .and_then(|c| c.courts.iter().flat_map(|court| court.judges.iter()).find(|j| j.id == judge_id))
            .map(|j| j.name.clone())
            .unwrap_or_else(|| judge_id.to_string())
    }

    pub fn court_of(&self, judge_id: &str) -> Option<&crate::simulator::Court> {
        self.courts.as_ref()?.courts.iter().find(|c| c.judges.iter().any(|j| j.id == judge_id))
    }

    pub fn touch(&mut self) {
        self.dirty = true;
        self.inbox_version += 1;
    }
}
