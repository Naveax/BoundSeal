#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdapterEnvelope {
    pub session_id: String,
    pub sequence: u64,
    pub action: AdapterAction,
    pub fixture_profile_sha256: String,
    pub input_sha256: String,
    pub payload_bytes: u64,
    pub labels: BTreeMap<String, String>,
}

impl AdapterEnvelope {
    pub fn new(
        session_id: impl Into<String>,
        sequence: u64,
        action: AdapterAction,
        fixture_profile_sha256: impl Into<String>,
        input_sha256: impl Into<String>,
        payload_bytes: u64,
        labels: BTreeMap<String, String>,
    ) -> Result<Self, BoundaryError> {
        let session_id = session_id.into();
        let fixture_profile_sha256 = fixture_profile_sha256.into();
        let input_sha256 = input_sha256.into();
        validate_identifier(&session_id, "adapter session")?;
        validate_sha256(&fixture_profile_sha256, "envelope fixture profile")?;
        validate_sha256(&input_sha256, "envelope input")?;
        if sequence == 0
            || payload_bytes > MAX_MESSAGE_BYTES
            || labels.len() > 32
            || labels.iter().any(|(key, value)| {
                key.is_empty()
                    || key.len() > 96
                    || value.len() > 256
                    || key.bytes().any(|byte| byte.is_ascii_control())
                    || value.bytes().any(|byte| byte == 0)
                    || reject_secret_like_text(value).is_err()
            })
        {
            return Err(BoundaryError::InvalidEnvelope(
                "sequence, payload or labels".into(),
            ));
        }
        Ok(Self {
            session_id,
            sequence,
            action,
            fixture_profile_sha256,
            input_sha256,
            payload_bytes,
            labels,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdapterResourceUsage {
    pub cpu_milliseconds: u64,
    pub peak_memory_bytes: u64,
    pub output_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdapterReceipt {
    pub session_id: String,
    pub sequence: u64,
    pub action: AdapterAction,
    pub outcome: AdapterOutcome,
    pub input_sha256: String,
    pub output_sha256: String,
    pub cumulative_messages: u64,
    pub cumulative_input_bytes: u64,
    pub cumulative_output_bytes: u64,
    pub cumulative_cpu_milliseconds: u64,
    pub peak_memory_bytes: u64,
    pub state: SessionState,
    pub audit_tail_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdapterSessionSnapshot {
    pub session_id: String,
    pub run_id: String,
    pub worker_id: String,
    pub policy_snapshot_sha256: String,
    pub manifest_sha256: String,
    pub grant_sha256: String,
    pub fixture_profile_sha256: String,
    pub limits_sha256: String,
    pub state: SessionState,
    pub message_count: u64,
    pub observation_count: u64,
    pub input_bytes: u64,
    pub output_bytes: u64,
    pub cpu_milliseconds: u64,
    pub peak_memory_bytes: u64,
    pub external_io_observed: bool,
    pub boundary_violations: u64,
    pub audit_tail_hash: String,
}

#[derive(Debug)]
pub struct AdapterSession {
    snapshot: AdapterSessionSnapshot,
    allowed_actions: BTreeSet<AdapterAction>,
    limits: AdapterResourceLimits,
    maximum_observations: u64,
    next_sequence: u64,
    expires_at_milliseconds: u64,
    audit: AdapterAuditChain,
}

impl AdapterSession {
    pub fn open(
        manifest: &AdapterManifest,
        grant: &mut AdapterGrant,
        profile: &FixtureProfile,
        now_milliseconds: u64,
    ) -> Result<Self, BoundaryError> {
        if grant.consumed
            || now_milliseconds < grant.issued_at_milliseconds
            || now_milliseconds >= grant.expires_at_milliseconds
            || grant.manifest_sha256 != manifest.manifest_sha256()
            || grant.fixture_profile_sha256 != profile.profile_sha256()
            || grant.policy_snapshot_sha256 != profile.policy_snapshot_sha256()
            || !grant.allowed_actions.is_subset(manifest.allowed_actions())
        {
            return Err(BoundaryError::GrantInactive);
        }
        grant.consumed = true;
        let session_seed = hash_serializable(&(
            &grant.grant_sha256,
            &grant.run_id,
            &grant.worker_id,
            now_milliseconds,
        ))?;
        let session_id = format!("adapter-session-{}", &session_seed[..24]);
        let limits_sha256 = manifest.limits().digest()?;
        let mut audit = AdapterAuditChain::new(grant.grant_sha256.clone())?;
        audit.append(AdapterAuditEvent {
            action: "adapter_session_opened".into(),
            subject_id: session_id.clone(),
            outcome: "open".into(),
            metadata: BTreeMap::from([
                ("manifest_sha256".into(), manifest.manifest_sha256().into()),
                ("fixture_profile_sha256".into(), profile.profile_sha256().into()),
                ("limits_sha256".into(), limits_sha256.clone()),
            ]),
        })?;
        let snapshot = AdapterSessionSnapshot {
            session_id,
            run_id: grant.run_id.clone(),
            worker_id: grant.worker_id.clone(),
            policy_snapshot_sha256: grant.policy_snapshot_sha256.clone(),
            manifest_sha256: grant.manifest_sha256.clone(),
            grant_sha256: grant.grant_sha256.clone(),
            fixture_profile_sha256: grant.fixture_profile_sha256.clone(),
            limits_sha256,
            state: SessionState::Open,
            message_count: 0,
            observation_count: 0,
            input_bytes: 0,
            output_bytes: 0,
            cpu_milliseconds: 0,
            peak_memory_bytes: 0,
            external_io_observed: false,
            boundary_violations: 0,
            audit_tail_hash: audit.tail_hash().into(),
        };
        Ok(Self {
            snapshot,
            allowed_actions: grant.allowed_actions.clone(),
            limits: manifest.limits().clone(),
            maximum_observations: profile.maximum_observations(),
            next_sequence: 1,
            expires_at_milliseconds: grant.expires_at_milliseconds,
            audit,
        })
    }

    pub fn execute(
        &mut self,
        envelope: AdapterEnvelope,
        usage: AdapterResourceUsage,
        output_sha256: impl Into<String>,
        outcome: AdapterOutcome,
        now_milliseconds: u64,
    ) -> Result<AdapterReceipt, BoundaryError> {
        let output_sha256 = output_sha256.into();
        validate_sha256(&output_sha256, "adapter output")?;
        if self.snapshot.state != SessionState::Open {
            return Err(BoundaryError::InvalidSessionTransition);
        }
        if now_milliseconds >= self.expires_at_milliseconds {
            self.fail_closed("grant_expired")?;
            return Err(BoundaryError::GrantInactive);
        }
        if envelope.session_id != self.snapshot.session_id
            || envelope.sequence != self.next_sequence
            || envelope.fixture_profile_sha256 != self.snapshot.fixture_profile_sha256
            || !self.allowed_actions.contains(&envelope.action)
        {
            return Err(BoundaryError::InvalidEnvelope(
                "session, sequence, fixture or action binding".into(),
            ));
        }
        if usage.output_bytes > self.limits.maximum_message_bytes
            || envelope.payload_bytes > self.limits.maximum_message_bytes
        {
            self.fail_closed("message_byte_limit")?;
            return Err(BoundaryError::QuotaExceeded("message bytes".into()));
        }
        let next_messages = self.snapshot.message_count.saturating_add(1);
        let next_input = self.snapshot.input_bytes.saturating_add(envelope.payload_bytes);
        let next_output = self.snapshot.output_bytes.saturating_add(usage.output_bytes);
        let next_cpu = self
            .snapshot
            .cpu_milliseconds
            .saturating_add(usage.cpu_milliseconds);
        let next_peak_memory = self.snapshot.peak_memory_bytes.max(usage.peak_memory_bytes);
        if next_messages > self.limits.maximum_messages
            || next_input.saturating_add(next_output) > self.limits.maximum_session_bytes
            || next_cpu > self.limits.maximum_cpu_milliseconds
            || next_peak_memory > self.limits.maximum_memory_bytes
        {
            self.fail_closed("session_resource_limit")?;
            return Err(BoundaryError::QuotaExceeded("session resources".into()));
        }
        match envelope.action {
            AdapterAction::Finalize if outcome != AdapterOutcome::Finalized => {
                return Err(BoundaryError::InvalidEnvelope(
                    "finalize action requires finalized outcome".into(),
                ));
            }
            AdapterAction::EmitObservation => {
                if !matches!(
                    outcome,
                    AdapterOutcome::ProducedObservation | AdapterOutcome::NoObservation
                ) {
                    return Err(BoundaryError::InvalidEnvelope(
                        "observation action outcome".into(),
                    ));
                }
                if outcome == AdapterOutcome::ProducedObservation {
                    self.snapshot.observation_count =
                        self.snapshot.observation_count.saturating_add(1);
                    if self.snapshot.observation_count > self.maximum_observations {
                        self.fail_closed("observation_limit")?;
                        return Err(BoundaryError::QuotaExceeded("observations".into()));
                    }
                }
            }
            AdapterAction::LoadFixture | AdapterAction::ExecuteReadOnly
                if outcome == AdapterOutcome::Finalized =>
            {
                return Err(BoundaryError::InvalidEnvelope(
                    "non-final action cannot finalize".into(),
                ));
            }
            _ => {}
        }
        self.snapshot.message_count = next_messages;
        self.snapshot.input_bytes = next_input;
        self.snapshot.output_bytes = next_output;
        self.snapshot.cpu_milliseconds = next_cpu;
        self.snapshot.peak_memory_bytes = next_peak_memory;
        self.next_sequence = self.next_sequence.saturating_add(1);
        if envelope.action == AdapterAction::Finalize {
            self.snapshot.state = SessionState::Completed;
        }
        self.audit.append(AdapterAuditEvent {
            action: "adapter_envelope_processed".into(),
            subject_id: self.snapshot.session_id.clone(),
            outcome: format!("{outcome:?}").to_ascii_lowercase(),
            metadata: BTreeMap::from([
                ("sequence".into(), envelope.sequence.to_string()),
                ("action".into(), format!("{:?}", envelope.action).to_ascii_lowercase()),
                ("input_sha256".into(), envelope.input_sha256.clone()),
                ("output_sha256".into(), output_sha256.clone()),
                ("payload_bytes".into(), envelope.payload_bytes.to_string()),
                ("output_bytes".into(), usage.output_bytes.to_string()),
            ]),
        })?;
        self.snapshot.audit_tail_hash = self.audit.tail_hash().into();
        Ok(AdapterReceipt {
            session_id: self.snapshot.session_id.clone(),
            sequence: envelope.sequence,
            action: envelope.action,
            outcome,
            input_sha256: envelope.input_sha256,
            output_sha256,
            cumulative_messages: self.snapshot.message_count,
            cumulative_input_bytes: self.snapshot.input_bytes,
            cumulative_output_bytes: self.snapshot.output_bytes,
            cumulative_cpu_milliseconds: self.snapshot.cpu_milliseconds,
            peak_memory_bytes: self.snapshot.peak_memory_bytes,
            state: self.snapshot.state,
            audit_tail_hash: self.snapshot.audit_tail_hash.clone(),
        })
    }

    pub fn request_cancel(&mut self) -> Result<(), BoundaryError> {
        if self.snapshot.state != SessionState::Open {
            return Err(BoundaryError::InvalidSessionTransition);
        }
        self.snapshot.state = SessionState::Cancelling;
        self.append_state_event("cancel_requested")
    }

    pub fn acknowledge_cancel(&mut self) -> Result<(), BoundaryError> {
        if self.snapshot.state != SessionState::Cancelling {
            return Err(BoundaryError::InvalidSessionTransition);
        }
        self.snapshot.state = SessionState::Cancelled;
        self.append_state_event("cancelled")
    }

    pub fn emergency_stop(&mut self) -> Result<(), BoundaryError> {
        if self.snapshot.state.is_terminal() {
            return Err(BoundaryError::InvalidSessionTransition);
        }
        self.snapshot.state = SessionState::EmergencyStopped;
        self.append_state_event("emergency_stopped")
    }

    pub fn snapshot(&self) -> &AdapterSessionSnapshot {
        &self.snapshot
    }

    pub fn limits(&self) -> &AdapterResourceLimits {
        &self.limits
    }

    pub fn audit(&self) -> &AdapterAuditChain {
        &self.audit
    }

    pub fn audit_mut(&mut self) -> &mut AdapterAuditChain {
        &mut self.audit
    }

    fn fail_closed(&mut self, reason: &str) -> Result<(), BoundaryError> {
        self.snapshot.state = SessionState::Failed;
        self.snapshot.boundary_violations = self.snapshot.boundary_violations.saturating_add(1);
        self.audit.append(AdapterAuditEvent {
            action: "adapter_session_failed_closed".into(),
            subject_id: self.snapshot.session_id.clone(),
            outcome: reason.into(),
            metadata: BTreeMap::new(),
        })?;
        self.snapshot.audit_tail_hash = self.audit.tail_hash().into();
        Ok(())
    }

    fn append_state_event(&mut self, outcome: &str) -> Result<(), BoundaryError> {
        self.audit.append(AdapterAuditEvent {
            action: "adapter_session_transition".into(),
            subject_id: self.snapshot.session_id.clone(),
            outcome: outcome.into(),
            metadata: BTreeMap::new(),
        })?;
        self.snapshot.audit_tail_hash = self.audit.tail_hash().into();
        Ok(())
    }
}
