//! NDJSON state-transition trace capture and offline TLA+ `TraceSpec` validation.
//!
//! Enabled via the `trace-spec` Cargo feature. Emits compact NDJSON records
//! matching `specs/tla/TraceSpec.tla` and validates every step against the
//! formal safety invariants of `WorkspaceLifecycle`, `RestoreBarrier`, and
//! `SyncConvergence`.

#![allow(unknown_lints, fragile_exhaustive_enum_match)] // closed internal trace enum matched exhaustively

/// One protocol state-transition event matching `specs/tla/TraceSpec.tla`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    CommitWritten(CommitWrittenData),
    CommitFault {
        point: String,
    },
    PublishIntent(PublishIntentData),
    PurgeBlob(PurgeBlobData),
    Recover {
        orphans_removed: u64,
    },
    RestorePendingSet {
        generation: u64,
    },
    ServeDenied,
    ServeAllowed,
    LedgerRejected {
        reason: String,
    },
    LedgerApplied(LedgerAppliedData),
    PushHeadAccepted {
        scope: String,
        origin: String,
        sequence: u64,
    },
    PushHeadRejected {
        scope: String,
        origin: String,
        sequence: u64,
    },
    RevocationMerged {
        token: String,
    },
    CapabilityAccepted {
        token: String,
    },
    CapabilityRejected {
        token: String,
        reason: String,
    },
    ScopeDenied {
        scope: String,
    },
    RbsrPullCompleted(RbsrPullData),
}

/// Payload for [`Event::CommitWritten`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitWrittenData {
    pub sequence: u64,
    pub generation: u64,
    pub pinned_generation: u64,
    pub blob: String,
    pub is_retention: bool,
}

/// Payload for [`Event::PublishIntent`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishIntentData {
    pub intent_sequence: u64,
    pub intent_generation: u64,
    pub outcome: String,
}

/// Payload for [`Event::PurgeBlob`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PurgeBlobData {
    pub blob: String,
    pub outcome: String,
    pub leaked_chunks: u64,
    pub is_cache_invalidated: bool,
}

/// Payload for [`Event::LedgerApplied`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerAppliedData {
    pub old_generation: u64,
    pub new_generation: u64,
    pub is_same_workspace: bool,
}

/// Payload for [`Event::RbsrPullCompleted`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RbsrPullData {
    pub scope: String,
    pub generation: u64,
    pub is_resurrected: bool,
    pub is_cross_scope: bool,
}

/// A formal invariant violation caught while checking a trace against `TraceSpec.tla`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Violation {
    pub step_index: u64,
    pub code: &'static str,
    pub detail: String,
}

impl std::fmt::Display for Violation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "trace step {} violated {}: {}",
            self.step_index, self.code, self.detail
        )
    }
}

impl std::error::Error for Violation {}

impl Event {
    /// Serialize this event into one compact NDJSON line compatible with `scripts/verify-tla.mjs`.
    pub fn to_ndjson_line(&self) -> String {
        match self {
            Event::CommitWritten(data) => format_commit_written(data),
            Event::CommitFault { point } => format!(
                "{{\"domain\":\"workspace\",\"action\":\"CommitFault\",\"point\":{}}}",
                json_string(point)
            ),
            Event::PublishIntent(data) => format!(
                "{{\"domain\":\"workspace\",\"action\":\"PublishIntent\",\"intentSeq\":{},\"intentGen\":{},\"outcome\":{}}}",
                data.intent_sequence,
                data.intent_generation,
                json_string(&data.outcome)
            ),
            Event::PurgeBlob(data) => format!(
                "{{\"domain\":\"workspace\",\"action\":\"PurgeBlob\",\"blob\":{},\"outcome\":{},\"leakedChunks\":{},\"cacheInvalidated\":{}}}",
                json_string(&data.blob),
                json_string(&data.outcome),
                data.leaked_chunks,
                data.is_cache_invalidated
            ),
            Event::Recover { orphans_removed } => format!(
                "{{\"domain\":\"workspace\",\"action\":\"Recover\",\"orphansRemoved\":{orphans_removed}}}"
            ),
            Event::RestorePendingSet { generation } => format!(
                "{{\"domain\":\"restore\",\"action\":\"RestorePendingSet\",\"gen\":{generation}}}"
            ),
            Event::ServeDenied => "{\"domain\":\"restore\",\"action\":\"ServeDenied\"}".to_owned(),
            Event::ServeAllowed => {
                "{\"domain\":\"restore\",\"action\":\"ServeAllowed\"}".to_owned()
            }
            Event::LedgerRejected { reason } => format!(
                "{{\"domain\":\"restore\",\"action\":\"LedgerRejected\",\"reason\":{}}}",
                json_string(reason)
            ),
            Event::LedgerApplied(data) => format!(
                "{{\"domain\":\"restore\",\"action\":\"LedgerApplied\",\"oldGen\":{},\"newGen\":{},\"sameWorkspace\":{}}}",
                data.old_generation, data.new_generation, data.is_same_workspace
            ),
            Event::PushHeadAccepted { .. }
            | Event::PushHeadRejected { .. }
            | Event::RevocationMerged { .. }
            | Event::CapabilityAccepted { .. }
            | Event::CapabilityRejected { .. }
            | Event::ScopeDenied { .. }
            | Event::RbsrPullCompleted(_) => format_sync_event(self),
        }
    }
}

fn format_commit_written(data: &CommitWrittenData) -> String {
    format!(
        "{{\"domain\":\"workspace\",\"action\":\"CommitWritten\",\"seq\":{},\"gen\":{},\"pinnedGen\":{},\"blob\":{},\"chunks\":[],\"isRetention\":{}}}",
        data.sequence,
        data.generation,
        data.pinned_generation,
        json_string(&data.blob),
        data.is_retention
    )
}

fn format_sync_event(event: &Event) -> String {
    match event {
        Event::PushHeadAccepted {
            scope,
            origin,
            sequence,
        } => format!(
            "{{\"domain\":\"sync\",\"action\":\"PushHeadAccepted\",\"scope\":{},\"origin\":{},\"seq\":{sequence}}}",
            json_string(scope),
            json_string(origin)
        ),
        Event::PushHeadRejected {
            scope,
            origin,
            sequence,
        } => format!(
            "{{\"domain\":\"sync\",\"action\":\"PushHeadRejected\",\"scope\":{},\"origin\":{},\"seq\":{sequence}}}",
            json_string(scope),
            json_string(origin)
        ),
        Event::RevocationMerged { token } => format!(
            "{{\"domain\":\"sync\",\"action\":\"RevocationMerged\",\"token\":{}}}",
            json_string(token)
        ),
        Event::CapabilityAccepted { token } => format!(
            "{{\"domain\":\"sync\",\"action\":\"CapabilityAccepted\",\"token\":{}}}",
            json_string(token)
        ),
        Event::CapabilityRejected { token, reason } => format!(
            "{{\"domain\":\"sync\",\"action\":\"CapabilityRejected\",\"token\":{},\"reason\":{}}}",
            json_string(token),
            json_string(reason)
        ),
        Event::ScopeDenied { scope } => format!(
            "{{\"domain\":\"sync\",\"action\":\"ScopeDenied\",\"scope\":{}}}",
            json_string(scope)
        ),
        Event::RbsrPullCompleted(data) => format!(
            "{{\"domain\":\"sync\",\"action\":\"RbsrPullCompleted\",\"scope\":{},\"generation\":{},\"resurrected\":{},\"crossScope\":{}}}",
            json_string(&data.scope),
            data.generation,
            data.is_resurrected,
            data.is_cross_scope
        ),
        Event::CommitWritten(_)
        | Event::CommitFault { .. }
        | Event::PublishIntent(_)
        | Event::PurgeBlob(_)
        | Event::Recover { .. }
        | Event::RestorePendingSet { .. }
        | Event::ServeDenied
        | Event::ServeAllowed
        | Event::LedgerRejected { .. }
        | Event::LedgerApplied(_) => String::new(),
    }
}

fn json_string(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len().saturating_add(2));
    out.push('"');
    for ch in raw.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

struct CaptureSlot {
    is_active: bool,
    events: Vec<Event>,
}

std::thread_local! {
    static CAPTURE: std::cell::RefCell<CaptureSlot> = const {
        std::cell::RefCell::new(CaptureSlot {
            is_active: false,
            events: Vec::new(),
        })
    };
}

/// Emit a protocol transition event into the current thread's active [`Session`], if any.
pub fn emit(event: Event) {
    let _is_recorded = CAPTURE
        .try_with(|slot| {
            if let Ok(mut guard) = slot.try_borrow_mut()
                && guard.is_active
            {
                guard.events.push(event);
            }
        })
        .is_ok();
}

/// Thread-scoped NDJSON trace capture guard.
pub struct Session {
    was_active: bool,
    previous_events: Vec<Event>,
}

impl Session {
    /// Start capturing `trace-spec` events emitted on the current thread.
    pub fn start() -> Self {
        let mut was_active = false;
        let mut previous_events = Vec::new();
        let _is_started = CAPTURE
            .try_with(|slot| {
                if let Ok(mut guard) = slot.try_borrow_mut() {
                    was_active = guard.is_active;
                    previous_events = std::mem::take(&mut guard.events);
                    guard.is_active = true;
                }
            })
            .is_ok();
        Self {
            was_active,
            previous_events,
        }
    }

    /// Snapshot all events captured so far in this session.
    pub fn events(&self) -> Vec<Event> {
        CAPTURE
            .try_with(|slot| {
                slot.try_borrow()
                    .map(|guard| guard.events.clone())
                    .unwrap_or_default()
            })
            .unwrap_or_default()
    }

    /// Encode all captured events as newline-delimited JSON matching `specs/tla/TraceSpec.tla`.
    pub fn to_ndjson(&self) -> String {
        let events = self.events();
        encode_ndjson(&events)
    }

    /// Validate all captured events against the `TraceSpec.tla` state machine.
    pub fn validate(&self) -> std::result::Result<u64, Violation> {
        let events = self.events();
        validate_events(&events)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _is_restored = CAPTURE
            .try_with(|slot| {
                if let Ok(mut guard) = slot.try_borrow_mut() {
                    guard.is_active = self.was_active;
                    guard.events = std::mem::take(&mut self.previous_events);
                }
            })
            .is_ok();
    }
}

/// Encode a slice of events as newline-delimited JSON.
pub fn encode_ndjson(events: &[Event]) -> String {
    let mut out = String::new();
    for event in events {
        push_event_line(&mut out, event);
    }
    out
}

fn push_event_line(out: &mut String, event: &Event) {
    out.push_str(&event.to_ndjson_line());
    out.push('\n');
}

/// Deterministic Rust mirror of `specs/tla/TraceSpec.tla` validating safety invariants offline.
#[derive(Clone, Debug)]
pub struct Validator {
    step: u64,
    ws_sequence: u64,
    ws_generation: u64,
    live_blobs: std::collections::BTreeSet<String>,
    disk_blobs: std::collections::BTreeSet<String>,
    forgotten_blobs: std::collections::BTreeSet<String>,
    is_restore_pending: bool,
    push_high_water: std::collections::BTreeMap<(String, String), u64>,
    revoked_tokens: std::collections::BTreeSet<String>,
}

impl Default for Validator {
    fn default() -> Self {
        Self::new()
    }
}

impl Validator {
    /// Construct a fresh validator at initial state.
    pub const fn new() -> Self {
        Self {
            step: 0,
            ws_sequence: 0,
            ws_generation: 0,
            live_blobs: std::collections::BTreeSet::new(),
            disk_blobs: std::collections::BTreeSet::new(),
            forgotten_blobs: std::collections::BTreeSet::new(),
            is_restore_pending: false,
            push_high_water: std::collections::BTreeMap::new(),
            revoked_tokens: std::collections::BTreeSet::new(),
        }
    }

    /// Number of events successfully checked so far.
    pub const fn checked_steps(&self) -> u64 {
        self.step
    }

    /// Apply and verify one event step against `TraceSpec.tla` invariants.
    pub fn apply(&mut self, event: &Event) -> std::result::Result<(), Violation> {
        self.step = self.step.saturating_add(1);
        match event {
            Event::CommitWritten(data) => self.apply_commit_written(data),
            Event::CommitFault { .. } => Ok(()),
            Event::PublishIntent(data) => self.apply_publish_intent(data),
            Event::PurgeBlob(data) => self.apply_purge_blob(data),
            Event::Recover { .. } => {
                self.disk_blobs = self.live_blobs.clone();
                Ok(())
            }
            Event::RestorePendingSet { generation } => {
                self.is_restore_pending = true;
                self.ws_generation = *generation;
                Ok(())
            }
            Event::ServeDenied | Event::LedgerRejected { .. } => Ok(()),
            Event::ServeAllowed => self.apply_serve_allowed(),
            Event::LedgerApplied(data) => self.apply_ledger_applied(data),
            Event::PushHeadAccepted {
                scope,
                origin,
                sequence,
            } => self.apply_push_head_accepted(scope, origin, *sequence),
            Event::PushHeadRejected { .. }
            | Event::CapabilityRejected { .. }
            | Event::ScopeDenied { .. } => Ok(()),
            Event::RevocationMerged { token } => {
                self.revoked_tokens.insert(token.clone());
                Ok(())
            }
            Event::CapabilityAccepted { token } => self.apply_capability_accepted(token),
            Event::RbsrPullCompleted(data) => self.apply_rbsr_pull(data),
        }
    }

    fn fail(&self, code: &'static str, detail: String) -> Violation {
        Violation {
            step_index: self.step,
            code,
            detail,
        }
    }

    fn apply_commit_written(
        &mut self,
        data: &CommitWrittenData,
    ) -> std::result::Result<(), Violation> {
        if self.is_restore_pending {
            return Err(self.fail(
                "commit_while_restore_pending",
                "commit wrote while restore barrier pending".to_owned(),
            ));
        }
        if data.sequence <= self.ws_sequence {
            return Err(self.fail(
                "non_monotonic_commit_sequence",
                format!("seq {} <= current {}", data.sequence, self.ws_sequence),
            ));
        }
        if !data.is_retention && data.pinned_generation != self.ws_generation {
            return Err(self.fail(
                "dropped_eligibility_generation_pinning",
                format!(
                    "pinned generation {} != current {}",
                    data.pinned_generation, self.ws_generation
                ),
            ));
        }
        if data.is_retention && data.generation <= self.ws_generation {
            return Err(self.fail(
                "retention_did_not_advance_generation",
                format!("gen {} <= current {}", data.generation, self.ws_generation),
            ));
        }
        let is_resurrected = !data.is_retention
            && !data.blob.is_empty()
            && self.forgotten_blobs.contains(&data.blob);
        if is_resurrected {
            return Err(self.fail(
                "resurrected_forgotten_blob",
                format!("blob {} was previously forgotten", data.blob),
            ));
        }
        self.ws_sequence = data.sequence;
        self.ws_generation = data.generation;
        if !data.blob.is_empty() {
            if data.is_retention {
                self.live_blobs.remove(&data.blob);
                self.forgotten_blobs.insert(data.blob.clone());
            } else {
                self.live_blobs.insert(data.blob.clone());
                self.disk_blobs.insert(data.blob.clone());
            }
        }
        Ok(())
    }

    fn apply_publish_intent(&self, data: &PublishIntentData) -> std::result::Result<(), Violation> {
        if self.is_restore_pending {
            return Err(self.fail(
                "publish_while_restore_pending",
                "publication attempted while restore barrier pending".to_owned(),
            ));
        }
        let is_stale = data.intent_sequence != self.ws_sequence
            || data.intent_generation != self.ws_generation;
        if data.outcome == "published" && is_stale {
            return Err(self.fail(
                "stale_intent_published",
                format!(
                    "published stale intent ({},{}) vs ({},{})",
                    data.intent_sequence,
                    data.intent_generation,
                    self.ws_sequence,
                    self.ws_generation
                ),
            ));
        }
        Ok(())
    }

    fn apply_purge_blob(&mut self, data: &PurgeBlobData) -> std::result::Result<(), Violation> {
        if data.outcome != "purged" {
            return Ok(());
        }
        if data.leaked_chunks > 0 {
            return Err(self.fail(
                "s1_unpurged_fastcdc_chunks",
                format!(
                    "purged blob {} left {} unreferenced chunks",
                    data.blob, data.leaked_chunks
                ),
            ));
        }
        if !data.is_cache_invalidated {
            return Err(self.fail(
                "purged_blob_not_invalidated_in_cache",
                format!(
                    "purged blob {} not invalidated in SharedRecordCache",
                    data.blob
                ),
            ));
        }
        if self.live_blobs.contains(&data.blob) {
            return Err(self.fail(
                "purged_live_required_blob",
                format!("purged live required blob {}", data.blob),
            ));
        }
        self.disk_blobs.remove(&data.blob);
        Ok(())
    }

    fn apply_serve_allowed(&self) -> std::result::Result<(), Violation> {
        if self.is_restore_pending {
            return Err(self.fail(
                "served_while_restore_pending",
                "workspace served data while META_RESTORE_PENDING was active".to_owned(),
            ));
        }
        Ok(())
    }

    fn apply_ledger_applied(
        &mut self,
        data: &LedgerAppliedData,
    ) -> std::result::Result<(), Violation> {
        if !self.is_restore_pending {
            return Err(self.fail(
                "ledger_applied_when_not_pending",
                "restore ledger applied when restore barrier was not pending".to_owned(),
            ));
        }
        if !data.is_same_workspace {
            return Err(self.fail(
                "foreign_workspace_ledger_applied",
                "foreign workspace suppression ledger was applied".to_owned(),
            ));
        }
        if data.new_generation <= data.old_generation {
            return Err(self.fail(
                "restore_generation_did_not_advance",
                format!(
                    "new generation {} <= old {}",
                    data.new_generation, data.old_generation
                ),
            ));
        }
        self.is_restore_pending = false;
        self.ws_generation = data.new_generation;
        Ok(())
    }

    fn apply_push_head_accepted(
        &mut self,
        scope: &str,
        origin: &str,
        sequence: u64,
    ) -> std::result::Result<(), Violation> {
        let key = (scope.to_owned(), origin.to_owned());
        let prev = self.push_high_water.get(&key).copied().unwrap_or(0);
        if sequence <= prev {
            return Err(self.fail(
                "stale_or_rollback_push_head_accepted",
                format!("accepted seq {sequence} <= high-water {prev} for ({scope},{origin})"),
            ));
        }
        self.push_high_water.insert(key, sequence);
        Ok(())
    }

    fn apply_capability_accepted(&self, token: &str) -> std::result::Result<(), Violation> {
        if self.revoked_tokens.contains(token) {
            return Err(self.fail(
                "revoked_capability_accepted_after_merge",
                format!("accepted revoked capability token {token}"),
            ));
        }
        Ok(())
    }

    fn apply_rbsr_pull(&self, data: &RbsrPullData) -> std::result::Result<(), Violation> {
        if data.is_resurrected {
            return Err(self.fail(
                "rbsr_resurrected_forgotten_record",
                "RBSR pull resurrected a forgotten record".to_owned(),
            ));
        }
        if data.is_cross_scope {
            return Err(self.fail(
                "rbsr_cross_scope_leakage",
                "RBSR pull leaked unauthorized cross-scope data".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Validate an ordered sequence of trace events against `TraceSpec.tla`.
pub fn validate_events(events: &[Event]) -> std::result::Result<u64, Violation> {
    let mut validator = Validator::new();
    for event in events {
        validator.apply(event)?;
    }
    Ok(validator.checked_steps())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validator_accepts_valid_lifecycle_and_rejects_fault_regressions() {
        let valid = vec![
            Event::CommitWritten(CommitWrittenData {
                sequence: 1,
                generation: 0,
                pinned_generation: 0,
                blob: "b1".to_owned(),
                is_retention: false,
            }),
            Event::PublishIntent(PublishIntentData {
                intent_sequence: 1,
                intent_generation: 0,
                outcome: "published".to_owned(),
            }),
            Event::CommitWritten(CommitWrittenData {
                sequence: 2,
                generation: 1,
                pinned_generation: 0,
                blob: "b1".to_owned(),
                is_retention: true,
            }),
            Event::PurgeBlob(PurgeBlobData {
                blob: "b1".to_owned(),
                outcome: "purged".to_owned(),
                leaked_chunks: 0,
                is_cache_invalidated: true,
            }),
            Event::PushHeadAccepted {
                scope: "project:cedar".to_owned(),
                origin: "peer-a".to_owned(),
                sequence: 2,
            },
            Event::RevocationMerged {
                token: "tok-1".to_owned(),
            },
        ];
        assert_eq!(validate_events(&valid).expect("valid trace"), 6);

        let s1_bad = vec![Event::PurgeBlob(PurgeBlobData {
            blob: "b1".to_owned(),
            outcome: "purged".to_owned(),
            leaked_chunks: 1,
            is_cache_invalidated: true,
        })];
        assert_eq!(
            validate_events(&s1_bad).expect_err("catch S1").code,
            "s1_unpurged_fastcdc_chunks"
        );

        let stale_push = vec![
            Event::PushHeadAccepted {
                scope: "project:cedar".to_owned(),
                origin: "peer-a".to_owned(),
                sequence: 5,
            },
            Event::PushHeadAccepted {
                scope: "project:cedar".to_owned(),
                origin: "peer-a".to_owned(),
                sequence: 4,
            },
        ];
        assert_eq!(
            validate_events(&stale_push)
                .expect_err("catch rollback")
                .code,
            "stale_or_rollback_push_head_accepted"
        );

        let revoked_bad = vec![
            Event::RevocationMerged {
                token: "tok-1".to_owned(),
            },
            Event::CapabilityAccepted {
                token: "tok-1".to_owned(),
            },
        ];
        assert_eq!(
            validate_events(&revoked_bad)
                .expect_err("catch revoked")
                .code,
            "revoked_capability_accepted_after_merge"
        );
    }
}
