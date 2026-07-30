impl RunMachine {
    pub fn new(
        run_id: impl Into<String>,
        policy_snapshot_sha256: impl Into<String>,
    ) -> Result<Self, PlannerError> {
        let run_id = run_id.into();
        let policy_snapshot_sha256 = policy_snapshot_sha256.into();
        validate_identifier(&run_id, "run_id")?;
        validate_sha256(&policy_snapshot_sha256, "policy snapshot")?;
        let mut audit = PlannerAuditChain::new();
        audit.append(PlannerAuditEvent {
            action: "run_created".into(),
            subject_id: run_id.clone(),
            outcome: "created".into(),
            metadata: BTreeMap::from([(
                "policy_snapshot_sha256".into(),
                policy_snapshot_sha256.clone(),
            )]),
        })?;
        Ok(Self {
            snapshot: RunSnapshot {
                run_id,
                policy_snapshot_sha256,
                state: RunState::Created,
                generation: 1,
                owner_worker_id: None,
                resume_token_sha256: None,
                audit_tail: audit.tail_hash().into(),
            },
            audit,
        })
    }

    pub fn transition(
        &mut self,
        target: RunState,
        worker_id: Option<&str>,
        resume_token: Option<&[u8]>,
    ) -> Result<RunSnapshot, PlannerError> {
        if self.snapshot.state.is_terminal() {
            return Err(PlannerError::InvalidRunTransition {
                from: self.snapshot.state,
                to: target,
            });
        }
        let valid = matches!(
            (self.snapshot.state, target),
            (RunState::Created, RunState::Validated)
                | (RunState::Validated, RunState::Running)
                | (RunState::Running, RunState::Paused)
                | (RunState::Paused, RunState::Running)
                | (RunState::Running, RunState::Cancelling)
                | (RunState::Paused, RunState::Cancelling)
                | (RunState::Cancelling, RunState::Completed)
                | (RunState::Running, RunState::Completed)
                | (RunState::Running, RunState::Failed)
                | (RunState::Paused, RunState::Failed)
                | (_, RunState::EmergencyStopped)
        );
        if !valid {
            return Err(PlannerError::InvalidRunTransition {
                from: self.snapshot.state,
                to: target,
            });
        }
        if matches!(target, RunState::Running) {
            let worker = worker_id.ok_or_else(|| {
                PlannerError::InvalidPlan("running state requires worker ownership".into())
            })?;
            validate_identifier(worker, "worker_id")?;
            if self.snapshot.state == RunState::Paused {
                let provided = resume_token.ok_or_else(|| {
                    PlannerError::InvalidPlan("resume requires a token".into())
                })?;
                let expected = self.snapshot.resume_token_sha256.as_deref().ok_or_else(|| {
                    PlannerError::InvalidPlan("paused run lacks resume token".into())
                })?;
                if hash_bytes(provided) != expected {
                    return Err(PlannerError::InvalidPlan(
                        "resume token does not match".into(),
                    ));
                }
            }
            self.snapshot.owner_worker_id = Some(worker.into());
            self.snapshot.resume_token_sha256 = None;
        } else if target == RunState::Paused {
            let token = resume_token.ok_or_else(|| {
                PlannerError::InvalidPlan("pause requires a future resume token".into())
            })?;
            self.snapshot.resume_token_sha256 = Some(hash_bytes(token));
            self.snapshot.owner_worker_id = None;
        }
        self.snapshot.state = target;
        self.snapshot.generation = self.snapshot.generation.saturating_add(1);
        self.audit.append(PlannerAuditEvent {
            action: "run_transition".into(),
            subject_id: self.snapshot.run_id.clone(),
            outcome: format!("{:?}", target).to_ascii_lowercase(),
            metadata: BTreeMap::from([(
                "generation".into(),
                self.snapshot.generation.to_string(),
            )]),
        })?;
        self.snapshot.audit_tail = self.audit.tail_hash().into();
        Ok(self.snapshot.clone())
    }

    pub fn snapshot(&self) -> &RunSnapshot {
        &self.snapshot
    }

    pub fn audit(&self) -> &PlannerAuditChain {
        &self.audit
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SecretAccessLevel {
    None,
    CookiesOnly,
    BoundHeaders,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProbeCapability {
    pub capability_id: String,
    pub module_id: String,
    pub run_id: String,
    pub worker_id: String,
    pub allowed_methods: BTreeSet<String>,
    pub allowed_endpoint_hashes: BTreeSet<String>,
    pub maximum_requests: u64,
    pub maximum_mutations: u64,
    pub secret_access: SecretAccessLevel,
    pub body_replay_allowed: bool,
    pub redirect_allowed: bool,
    pub expires_at_milliseconds: u64,
    pub revoked: bool,
    requests_used: u64,
    mutations_used: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityUseRequest {
    pub run_id: String,
    pub worker_id: String,
    pub method: String,
    pub endpoint_sha256: String,
    pub mutations: u64,
    pub requires_secret_access: SecretAccessLevel,
    pub replays_body: bool,
    pub follows_redirect: bool,
    pub now_milliseconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityUseReceipt {
    pub capability_id: String,
    pub request_number: u64,
    pub mutations_used: u64,
    pub remaining_requests: u64,
    pub remaining_mutations: u64,
    pub endpoint_sha256: String,
}

