#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkflowStepRuntime {
    pub step_id: String,
    pub state: WorkflowStepState,
    pub attempts: u8,
    pub active_lease_id: Option<String>,
    pub evidence_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkflowLease {
    pub lease_id: String,
    pub workflow_id: String,
    pub definition_sha256: String,
    pub step_id: String,
    pub worker_id: String,
    pub attempt: u8,
    pub issued_at_milliseconds: u64,
    pub expires_at_milliseconds: u64,
    pub compensation: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkflowStepReceipt {
    pub lease_id: String,
    pub step_id: String,
    pub final_state: WorkflowStepState,
    pub evidence_sha256: String,
    pub workflow_state: WorkflowState,
    pub audit_tail_hash: String,
}

#[derive(Debug)]
pub struct WorkflowEngine {
    definition: WorkflowDefinition,
    state: WorkflowState,
    steps: BTreeMap<String, WorkflowStepRuntime>,
    compensation_targets: BTreeSet<String>,
    consumed_leases: BTreeSet<String>,
    next_lease_sequence: u64,
    audit: WorkflowAuditChain,
}

impl WorkflowEngine {
    pub fn new(
        definition: WorkflowDefinition,
        audit_genesis: impl Into<String>,
    ) -> Result<Self, WorkflowError> {
        let compensation_targets = definition
            .steps
            .values()
            .filter_map(|step| step.compensation_step_id.clone())
            .collect::<BTreeSet<_>>();
        let steps = definition
            .steps
            .keys()
            .map(|step_id| {
                (
                    step_id.clone(),
                    WorkflowStepRuntime {
                        step_id: step_id.clone(),
                        state: WorkflowStepState::Pending,
                        attempts: 0,
                        active_lease_id: None,
                        evidence_sha256: None,
                    },
                )
            })
            .collect();
        Ok(Self {
            definition,
            state: WorkflowState::Created,
            steps,
            compensation_targets,
            consumed_leases: BTreeSet::new(),
            next_lease_sequence: 1,
            audit: WorkflowAuditChain::new(audit_genesis)?,
        })
    }

    pub fn start(&mut self) -> Result<(), WorkflowError> {
        if self.state != WorkflowState::Created {
            return Err(WorkflowError::InvalidWorkflowState);
        }
        self.state = WorkflowState::Running;
        self.record_state("workflow_started", "running")?;
        Ok(())
    }

    pub fn pause(&mut self) -> Result<(), WorkflowError> {
        if self.state != WorkflowState::Running
            || self
                .steps
                .values()
                .any(|runtime| runtime.state == WorkflowStepState::Leased)
        {
            return Err(WorkflowError::InvalidWorkflowState);
        }
        self.state = WorkflowState::Paused;
        self.record_state("workflow_paused", "paused")?;
        Ok(())
    }

    pub fn resume(&mut self) -> Result<(), WorkflowError> {
        if self.state != WorkflowState::Paused {
            return Err(WorkflowError::InvalidWorkflowState);
        }
        self.state = WorkflowState::Running;
        self.record_state("workflow_resumed", "running")?;
        Ok(())
    }

    pub fn cancel(&mut self) -> Result<(), WorkflowError> {
        if !matches!(self.state, WorkflowState::Running | WorkflowState::Paused) {
            return Err(WorkflowError::InvalidWorkflowState);
        }
        if self
            .steps
            .values()
            .any(|runtime| runtime.state == WorkflowStepState::Leased)
        {
            return Err(WorkflowError::InvalidWorkflowState);
        }
        self.state = WorkflowState::Cancelling;
        for (step_id, runtime) in &mut self.steps {
            if self.compensation_targets.contains(step_id) {
                continue;
            }
            match runtime.state {
                WorkflowStepState::Pending => runtime.state = WorkflowStepState::Skipped,
                WorkflowStepState::Succeeded => {
                    if let Some(compensation_step_id) = self.definition.steps[step_id]
                        .compensation_step_id
                        .as_deref()
                    {
                        self.steps
                            .get_mut(compensation_step_id)
                            .expect("compensation runtime")
                            .state = WorkflowStepState::Compensating;
                    }
                }
                _ => {}
            }
        }
        self.record_state("workflow_cancel_requested", "cancelling")?;
        self.advance_terminal_state()?;
        Ok(())
    }

    pub fn emergency_stop(&mut self) -> Result<(), WorkflowError> {
        if self.state.is_terminal() {
            return Err(WorkflowError::InvalidWorkflowState);
        }
        self.state = WorkflowState::EmergencyStopped;
        for runtime in self.steps.values_mut() {
            if matches!(
                runtime.state,
                WorkflowStepState::Pending
                    | WorkflowStepState::Leased
                    | WorkflowStepState::Compensating
            ) {
                runtime.state = WorkflowStepState::Skipped;
                runtime.active_lease_id = None;
            }
        }
        self.record_state("workflow_emergency_stopped", "emergency_stopped")?;
        Ok(())
    }

    pub fn lease_next(
        &mut self,
        worker_id: impl Into<String>,
        now_milliseconds: u64,
        lease_duration_milliseconds: u64,
    ) -> Result<Option<WorkflowLease>, WorkflowError> {
        if !matches!(self.state, WorkflowState::Running | WorkflowState::Cancelling)
            || lease_duration_milliseconds == 0
            || lease_duration_milliseconds > 60_000
        {
            return Err(WorkflowError::InvalidWorkflowState);
        }
        let worker_id = worker_id.into();
        validate_identifier(&worker_id, "worker_id")?;
        let mut selected = None;
        for step_id in &self.definition.topological_order {
            let runtime = &self.steps[step_id];
            let is_compensation = runtime.state == WorkflowStepState::Compensating;
            let normal_candidate = self.state == WorkflowState::Running
                && runtime.state == WorkflowStepState::Pending
                && !self.compensation_targets.contains(step_id)
                && self.definition.steps[step_id]
                    .dependencies
                    .iter()
                    .all(|dependency| {
                        self.steps[dependency].state == WorkflowStepState::Succeeded
                    });
            let compensation_candidate =
                self.state == WorkflowState::Cancelling && is_compensation;
            if normal_candidate || compensation_candidate {
                selected = Some((step_id.clone(), compensation_candidate));
                break;
            }
        }
        let Some((step_id, compensation)) = selected else {
            self.advance_terminal_state()?;
            return Ok(None);
        };
        let runtime = self.steps.get_mut(&step_id).expect("selected workflow step");
        if runtime.attempts >= MAX_STEP_ATTEMPTS {
            return Err(WorkflowError::StepNotReady);
        }
        let lease_id = format!("workflow-lease-{:020}", self.next_lease_sequence);
        self.next_lease_sequence = self.next_lease_sequence.saturating_add(1);
        runtime.attempts = runtime.attempts.saturating_add(1);
        runtime.state = WorkflowStepState::Leased;
        runtime.active_lease_id = Some(lease_id.clone());
        let expires_at_milliseconds = now_milliseconds
            .checked_add(lease_duration_milliseconds)
            .ok_or(WorkflowError::InvalidLease)?;
        let lease = WorkflowLease {
            lease_id: lease_id.clone(),
            workflow_id: self.definition.workflow_id.clone(),
            definition_sha256: self.definition.definition_sha256.clone(),
            step_id: step_id.clone(),
            worker_id,
            attempt: runtime.attempts,
            issued_at_milliseconds: now_milliseconds,
            expires_at_milliseconds,
            compensation,
        };
        self.audit.append(WorkflowAuditEvent {
            action: "workflow_step_leased".into(),
            subject_id: step_id,
            outcome: if compensation {
                "compensation_leased".into()
            } else {
                "leased".into()
            },
            metadata: BTreeMap::from([("lease_id".into(), lease_id)]),
        })?;
        Ok(Some(lease))
    }

    pub fn complete(
        &mut self,
        lease: &WorkflowLease,
        now_milliseconds: u64,
        evidence_sha256: impl Into<String>,
    ) -> Result<WorkflowStepReceipt, WorkflowError> {
        let evidence_sha256 = evidence_sha256.into();
        validate_sha256(&evidence_sha256, "workflow step evidence")?;
        self.validate_lease(lease, now_milliseconds)?;
        let runtime = self
            .steps
            .get_mut(&lease.step_id)
            .ok_or(WorkflowError::InvalidLease)?;
        runtime.state = if lease.compensation {
            WorkflowStepState::Compensated
        } else {
            WorkflowStepState::Succeeded
        };
        runtime.active_lease_id = None;
        runtime.evidence_sha256 = Some(evidence_sha256.clone());
        self.consumed_leases.insert(lease.lease_id.clone());
        self.audit.append(WorkflowAuditEvent {
            action: "workflow_step_completed".into(),
            subject_id: lease.step_id.clone(),
            outcome: format!("{:?}", runtime.state).to_ascii_lowercase(),
            metadata: BTreeMap::from([("evidence_sha256".into(), evidence_sha256.clone())]),
        })?;
        self.advance_terminal_state()?;
        Ok(WorkflowStepReceipt {
            lease_id: lease.lease_id.clone(),
            step_id: lease.step_id.clone(),
            final_state: runtime.state,
            evidence_sha256,
            workflow_state: self.state,
            audit_tail_hash: self.audit.tail_hash().into(),
        })
    }

    pub fn fail(
        &mut self,
        lease: &WorkflowLease,
        now_milliseconds: u64,
        evidence_sha256: impl Into<String>,
    ) -> Result<WorkflowStepReceipt, WorkflowError> {
        let evidence_sha256 = evidence_sha256.into();
        validate_sha256(&evidence_sha256, "workflow failure evidence")?;
        self.validate_lease(lease, now_milliseconds)?;
        let runtime = self
            .steps
            .get_mut(&lease.step_id)
            .ok_or(WorkflowError::InvalidLease)?;
        runtime.state = WorkflowStepState::Failed;
        runtime.active_lease_id = None;
        runtime.evidence_sha256 = Some(evidence_sha256.clone());
        self.consumed_leases.insert(lease.lease_id.clone());
        if lease.compensation {
            self.state = WorkflowState::Failed;
        } else if let Some(compensation_step_id) = self.definition.steps[&lease.step_id]
            .compensation_step_id
            .clone()
        {
            self.state = WorkflowState::Cancelling;
            self.steps
                .get_mut(&compensation_step_id)
                .expect("compensation runtime")
                .state = WorkflowStepState::Compensating;
        } else {
            self.state = WorkflowState::Failed;
        }
        self.audit.append(WorkflowAuditEvent {
            action: "workflow_step_failed".into(),
            subject_id: lease.step_id.clone(),
            outcome: "failed".into(),
            metadata: BTreeMap::from([("evidence_sha256".into(), evidence_sha256.clone())]),
        })?;
        Ok(WorkflowStepReceipt {
            lease_id: lease.lease_id.clone(),
            step_id: lease.step_id.clone(),
            final_state: WorkflowStepState::Failed,
            evidence_sha256,
            workflow_state: self.state,
            audit_tail_hash: self.audit.tail_hash().into(),
        })
    }

    pub fn state(&self) -> WorkflowState {
        self.state
    }

    pub fn step_runtime(&self, step_id: &str) -> Option<&WorkflowStepRuntime> {
        self.steps.get(step_id)
    }

    pub fn definition(&self) -> &WorkflowDefinition {
        &self.definition
    }

    pub fn audit(&self) -> &WorkflowAuditChain {
        &self.audit
    }

    fn validate_lease(
        &self,
        lease: &WorkflowLease,
        now_milliseconds: u64,
    ) -> Result<(), WorkflowError> {
        if lease.workflow_id != self.definition.workflow_id
            || lease.definition_sha256 != self.definition.definition_sha256
            || now_milliseconds >= lease.expires_at_milliseconds
            || self.consumed_leases.contains(&lease.lease_id)
            || self
                .steps
                .get(&lease.step_id)
                .and_then(|runtime| runtime.active_lease_id.as_deref())
                != Some(lease.lease_id.as_str())
        {
            return Err(WorkflowError::InvalidLease);
        }
        Ok(())
    }

    fn advance_terminal_state(&mut self) -> Result<(), WorkflowError> {
        if self.state == WorkflowState::Running {
            let all_normal_succeeded = self.steps.iter().all(|(step_id, runtime)| {
                self.compensation_targets.contains(step_id)
                    || runtime.state == WorkflowStepState::Succeeded
            });
            if all_normal_succeeded {
                self.state = WorkflowState::Completed;
                self.record_state("workflow_completed", "completed")?;
            }
        } else if self.state == WorkflowState::Cancelling {
            let compensation_outstanding = self.compensation_targets.iter().any(|step_id| {
                matches!(
                    self.steps[step_id].state,
                    WorkflowStepState::Compensating | WorkflowStepState::Leased
                )
            });
            if !compensation_outstanding {
                self.state = WorkflowState::Failed;
                self.record_state("workflow_cancelled", "compensated_and_stopped")?;
            }
        }
        Ok(())
    }

    fn record_state(&mut self, action: &str, outcome: &str) -> Result<(), WorkflowError> {
        self.audit.append(WorkflowAuditEvent {
            action: action.into(),
            subject_id: self.definition.workflow_id.clone(),
            outcome: outcome.into(),
            metadata: BTreeMap::new(),
        })?;
        Ok(())
    }
}
