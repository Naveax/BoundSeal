#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReplayObservation {
    pub sequence: u64,
    pub input_id: String,
    pub input_sha256: String,
    pub output_sha256: String,
    pub metadata_sha256: String,
    pub virtual_tick: u64,
    pub outcome: ReplayStepOutcome,
    pub applied_fault_ids: BTreeSet<String>,
    pub observation_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReplayTrace {
    pub bundle_sha256: String,
    pub fault_plan_sha256: String,
    pub observations: Vec<ReplayObservation>,
    pub trace_sha256: String,
}

impl ReplayTrace {
    pub fn verify(&self) -> Result<(), ReplayError> {
        let expected = hash_serializable(&(
            &self.bundle_sha256,
            &self.fault_plan_sha256,
            &self.observations,
        ))?;
        if expected != self.trace_sha256 {
            return Err(ReplayError::InvalidTransition);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReplayCheckpoint {
    pub checkpoint_id: String,
    pub engine_id: String,
    pub bundle_sha256: String,
    pub fault_plan_sha256: String,
    pub next_sequence: u64,
    pub virtual_tick: u64,
    pub seed_counter: u64,
    pub observation_prefix_sha256: String,
    pub source_audit_tail_hash: String,
    pub checkpoint_sha256: String,
}

impl ReplayCheckpoint {
    pub fn verify(&self) -> Result<(), ReplayError> {
        let expected = hash_serializable(&(
            &self.checkpoint_id,
            &self.engine_id,
            &self.bundle_sha256,
            &self.fault_plan_sha256,
            self.next_sequence,
            self.virtual_tick,
            self.seed_counter,
            &self.observation_prefix_sha256,
            &self.source_audit_tail_hash,
        ))?;
        if expected != self.checkpoint_sha256 {
            return Err(ReplayError::InvalidTransition);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReplayReceipt {
    pub engine_id: String,
    pub policy_snapshot_sha256: String,
    pub bundle_sha256: String,
    pub fault_plan_sha256: String,
    pub trace_sha256: String,
    pub result_sha256: String,
    pub observation_count: u64,
    pub final_virtual_tick: u64,
    pub state: ReplayState,
    pub replay_audit_tail_hash: String,
    pub receipt_sha256: String,
}

impl ReplayReceipt {
    pub fn verify(&self) -> Result<(), ReplayError> {
        let expected = hash_serializable(&(
            &self.engine_id,
            &self.policy_snapshot_sha256,
            &self.bundle_sha256,
            &self.fault_plan_sha256,
            &self.trace_sha256,
            &self.result_sha256,
            self.observation_count,
            self.final_virtual_tick,
            self.state,
            &self.replay_audit_tail_hash,
        ))?;
        if expected != self.receipt_sha256 || self.state != ReplayState::Completed {
            return Err(ReplayError::CertificationDenied(
                "replay receipt digest or terminal state".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct ReplayEngine {
    engine_id: String,
    bundle: ReplayBundle,
    fault_plan: FaultPlan,
    clock: VirtualClock,
    seed: DeterministicSeed,
    state: ReplayState,
    next_sequence: u64,
    observations: Vec<ReplayObservation>,
    audit: ReplayAuditChain,
}

impl ReplayEngine {
    pub fn new(
        engine_id: impl Into<String>,
        bundle: ReplayBundle,
        fault_plan: FaultPlan,
        audit_genesis: impl Into<String>,
    ) -> Result<Self, ReplayError> {
        let engine_id = engine_id.into();
        validate_identifier(&engine_id, "replay engine")?;
        bundle.verify()?;
        fault_plan.verify()?;
        if fault_plan.bundle_sha256 != bundle.bundle_sha256 {
            return Err(ReplayError::InvalidFaultPlan(
                "fault plan is bound to another replay bundle".into(),
            ));
        }
        Ok(Self {
            engine_id,
            clock: VirtualClock::new(bundle.initial_tick, MAX_VIRTUAL_TICK)?,
            seed: DeterministicSeed::new(bundle.seed_sha256.clone())?,
            bundle,
            fault_plan,
            state: ReplayState::Created,
            next_sequence: 1,
            observations: Vec::new(),
            audit: ReplayAuditChain::new(audit_genesis)?,
        })
    }

    pub fn resume(
        engine_id: impl Into<String>,
        bundle: ReplayBundle,
        fault_plan: FaultPlan,
        checkpoint: &ReplayCheckpoint,
        observation_prefix: Vec<ReplayObservation>,
    ) -> Result<Self, ReplayError> {
        checkpoint.verify()?;
        let engine_id = engine_id.into();
        validate_identifier(&engine_id, "replay engine")?;
        bundle.verify()?;
        fault_plan.verify()?;
        if checkpoint.engine_id != engine_id
            || checkpoint.bundle_sha256 != bundle.bundle_sha256
            || checkpoint.fault_plan_sha256 != fault_plan.plan_sha256
            || checkpoint.observation_prefix_sha256 != hash_serializable(&observation_prefix)?
            || checkpoint.next_sequence != observation_prefix.len() as u64 + 1
            || checkpoint.virtual_tick < bundle.initial_tick
        {
            return Err(ReplayError::InvalidTransition);
        }
        let mut clock = VirtualClock::new(bundle.initial_tick, MAX_VIRTUAL_TICK)?;
        clock.current_tick = checkpoint.virtual_tick;
        let mut seed = DeterministicSeed::new(bundle.seed_sha256.clone())?;
        seed.counter = checkpoint.seed_counter;
        let mut audit = ReplayAuditChain::new(checkpoint.checkpoint_sha256.clone())?;
        audit.append(ReplayAuditEvent {
            action: "replay_resumed".into(),
            subject_id: engine_id.clone(),
            outcome: "running".into(),
            metadata: BTreeMap::from([(
                "checkpoint_sha256".into(),
                checkpoint.checkpoint_sha256.clone(),
            )]),
        })?;
        Ok(Self {
            engine_id,
            bundle,
            fault_plan,
            clock,
            seed,
            state: ReplayState::Running,
            next_sequence: checkpoint.next_sequence,
            observations: observation_prefix,
            audit,
        })
    }

    pub fn start(&mut self) -> Result<(), ReplayError> {
        if self.state != ReplayState::Created {
            return Err(ReplayError::InvalidTransition);
        }
        self.state = ReplayState::Running;
        self.audit.append(ReplayAuditEvent {
            action: "replay_started".into(),
            subject_id: self.engine_id.clone(),
            outcome: "running".into(),
            metadata: BTreeMap::from([
                ("bundle_sha256".into(), self.bundle.bundle_sha256.clone()),
                ("fault_plan_sha256".into(), self.fault_plan.plan_sha256.clone()),
            ]),
        })?;
        Ok(())
    }

    pub fn step(
        &mut self,
        sequence: u64,
        output_sha256: impl Into<String>,
        metadata_sha256: impl Into<String>,
        elapsed_ticks: u64,
    ) -> Result<ReplayObservation, ReplayError> {
        if self.state != ReplayState::Running || sequence != self.next_sequence {
            return Err(if self.state == ReplayState::Running {
                ReplayError::SequenceMismatch
            } else {
                ReplayError::InvalidTransition
            });
        }
        let input = self
            .bundle
            .inputs
            .get(sequence.saturating_sub(1) as usize)
            .cloned()
            .ok_or(ReplayError::SequenceMismatch)?;
        let input_id = input.input_id.clone();
        let input_sha256 = input.content_sha256.clone();
        let output_sha256 = output_sha256.into();
        let metadata_sha256 = metadata_sha256.into();
        validate_sha256(&output_sha256, "replay output")?;
        validate_sha256(&metadata_sha256, "replay metadata")?;
        if elapsed_ticks > MAX_FAULT_MAGNITUDE {
            return Err(ReplayError::InvalidClock);
        }
        let rules = self
            .fault_plan
            .rules_at(sequence)
            .cloned()
            .collect::<Vec<_>>();
        let applied_fault_ids = rules
            .iter()
            .map(|rule| rule.rule_id.clone())
            .collect::<BTreeSet<_>>();
        let kinds = rules.iter().map(|rule| rule.kind).collect::<BTreeSet<_>>();
        let extra_ticks = rules.iter().try_fold(0_u64, |total, rule| {
            total.checked_add(rule.magnitude).ok_or(ReplayError::InvalidClock)
        })?;
        let jitter = if rules.is_empty() {
            0
        } else {
            self.seed.next_u64() % (rules.len() as u64 + 1)
        };
        let virtual_tick = self.clock.advance(
            elapsed_ticks
                .checked_add(extra_ticks)
                .and_then(|value| value.checked_add(jitter))
                .ok_or(ReplayError::InvalidClock)?,
        )?;
        let outcome = if kinds.contains(&FaultKind::Reset) {
            ReplayStepOutcome::Reset
        } else if kinds.contains(&FaultKind::Timeout) {
            ReplayStepOutcome::TimedOut
        } else if kinds.contains(&FaultKind::Truncate) {
            ReplayStepOutcome::Truncated
        } else if kinds.contains(&FaultKind::Backpressure) {
            ReplayStepOutcome::Backpressured
        } else {
            ReplayStepOutcome::Observed
        };
        let effective_output_sha256 = if matches!(
            outcome,
            ReplayStepOutcome::Observed | ReplayStepOutcome::Backpressured
        ) {
            output_sha256
        } else {
            hash_serializable(&(input_sha256.as_str(), outcome, &applied_fault_ids, sequence))?
        };
        let observation_sha256 = hash_serializable(&(
            sequence,
            &input_id,
            &input_sha256,
            &effective_output_sha256,
            &metadata_sha256,
            virtual_tick,
            outcome,
            &applied_fault_ids,
        ))?;
        let observation = ReplayObservation {
            sequence,
            input_id,
            input_sha256: input_sha256.clone(),
            output_sha256: effective_output_sha256.clone(),
            metadata_sha256: metadata_sha256.clone(),
            virtual_tick,
            outcome,
            applied_fault_ids,
            observation_sha256: observation_sha256.clone(),
        };
        self.observations.push(observation.clone());
        self.next_sequence = self.next_sequence.saturating_add(1);
        self.audit.append(ReplayAuditEvent {
            action: "replay_step".into(),
            subject_id: self.engine_id.clone(),
            outcome: format!("{outcome:?}").to_ascii_lowercase(),
            metadata: BTreeMap::from([
                ("sequence".into(), sequence.to_string()),
                ("input_sha256".into(), input_sha256),
                ("output_sha256".into(), effective_output_sha256),
                ("metadata_sha256".into(), metadata_sha256),
                ("virtual_tick".into(), virtual_tick.to_string()),
                ("observation_sha256".into(), observation_sha256),
            ]),
        })?;
        Ok(observation)
    }

    pub fn checkpoint(&mut self) -> Result<ReplayCheckpoint, ReplayError> {
        if self.state != ReplayState::Running {
            return Err(ReplayError::InvalidTransition);
        }
        let observation_prefix_sha256 = hash_serializable(&self.observations)?;
        let source_audit_tail_hash = self.audit.tail_hash().to_string();
        let checkpoint_id = format!(
            "replay-checkpoint-{}",
            &hash_serializable(&(
                &self.engine_id,
                &self.bundle.bundle_sha256,
                self.next_sequence,
                &observation_prefix_sha256,
                &source_audit_tail_hash,
            ))?[..24]
        );
        let checkpoint_sha256 = hash_serializable(&(
            &checkpoint_id,
            &self.engine_id,
            &self.bundle.bundle_sha256,
            &self.fault_plan.plan_sha256,
            self.next_sequence,
            self.clock.current_tick(),
            self.seed.counter(),
            &observation_prefix_sha256,
            &source_audit_tail_hash,
        ))?;
        let checkpoint = ReplayCheckpoint {
            checkpoint_id: checkpoint_id.clone(),
            engine_id: self.engine_id.clone(),
            bundle_sha256: self.bundle.bundle_sha256.clone(),
            fault_plan_sha256: self.fault_plan.plan_sha256.clone(),
            next_sequence: self.next_sequence,
            virtual_tick: self.clock.current_tick(),
            seed_counter: self.seed.counter(),
            observation_prefix_sha256,
            source_audit_tail_hash,
            checkpoint_sha256: checkpoint_sha256.clone(),
        };
        self.audit.append(ReplayAuditEvent {
            action: "replay_checkpoint_created".into(),
            subject_id: checkpoint_id,
            outcome: "created".into(),
            metadata: BTreeMap::from([("checkpoint_sha256".into(), checkpoint_sha256)]),
        })?;
        Ok(checkpoint)
    }

    pub fn finish(&mut self) -> Result<(ReplayTrace, ReplayReceipt), ReplayError> {
        if self.state != ReplayState::Running
            || self.next_sequence != self.bundle.inputs.len() as u64 + 1
        {
            return Err(ReplayError::InvalidTransition);
        }
        self.state = ReplayState::Completed;
        let trace_sha256 = hash_serializable(&(
            &self.bundle.bundle_sha256,
            &self.fault_plan.plan_sha256,
            &self.observations,
        ))?;
        let trace = ReplayTrace {
            bundle_sha256: self.bundle.bundle_sha256.clone(),
            fault_plan_sha256: self.fault_plan.plan_sha256.clone(),
            observations: self.observations.clone(),
            trace_sha256: trace_sha256.clone(),
        };
        trace.verify()?;
        let result_sha256 = hash_serializable(&(
            &trace_sha256,
            &self.bundle.expected_observation_sha256,
            self.clock.current_tick(),
        ))?;
        self.audit.append(ReplayAuditEvent {
            action: "replay_completed".into(),
            subject_id: self.engine_id.clone(),
            outcome: "completed".into(),
            metadata: BTreeMap::from([
                ("trace_sha256".into(), trace_sha256.clone()),
                ("result_sha256".into(), result_sha256.clone()),
            ]),
        })?;
        let replay_audit_tail_hash = self.audit.tail_hash().to_string();
        let receipt_sha256 = hash_serializable(&(
            &self.engine_id,
            &self.bundle.policy_snapshot_sha256,
            &self.bundle.bundle_sha256,
            &self.fault_plan.plan_sha256,
            &trace_sha256,
            &result_sha256,
            self.observations.len() as u64,
            self.clock.current_tick(),
            self.state,
            &replay_audit_tail_hash,
        ))?;
        let receipt = ReplayReceipt {
            engine_id: self.engine_id.clone(),
            policy_snapshot_sha256: self.bundle.policy_snapshot_sha256.clone(),
            bundle_sha256: self.bundle.bundle_sha256.clone(),
            fault_plan_sha256: self.fault_plan.plan_sha256.clone(),
            trace_sha256,
            result_sha256,
            observation_count: self.observations.len() as u64,
            final_virtual_tick: self.clock.current_tick(),
            state: self.state,
            replay_audit_tail_hash,
            receipt_sha256,
        };
        receipt.verify()?;
        Ok((trace, receipt))
    }

    pub fn cancel(&mut self) -> Result<(), ReplayError> {
        self.terminal_transition(ReplayState::Cancelled, "cancelled")
    }

    pub fn emergency_stop(&mut self) -> Result<(), ReplayError> {
        if self.state.is_terminal() {
            return Err(ReplayError::InvalidTransition);
        }
        self.terminal_transition(ReplayState::EmergencyStopped, "emergency_stopped")
    }

    pub fn state(&self) -> ReplayState {
        self.state
    }

    pub fn observations(&self) -> &[ReplayObservation] {
        &self.observations
    }

    pub fn audit(&self) -> &ReplayAuditChain {
        &self.audit
    }

    pub fn audit_mut(&mut self) -> &mut ReplayAuditChain {
        &mut self.audit
    }

    fn terminal_transition(
        &mut self,
        target: ReplayState,
        outcome: &str,
    ) -> Result<(), ReplayError> {
        if self.state != ReplayState::Running {
            return Err(ReplayError::InvalidTransition);
        }
        self.state = target;
        self.audit.append(ReplayAuditEvent {
            action: "replay_terminal_transition".into(),
            subject_id: self.engine_id.clone(),
            outcome: outcome.into(),
            metadata: BTreeMap::new(),
        })?;
        Ok(())
    }
}
