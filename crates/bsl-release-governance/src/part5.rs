#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RolloutStage {
    pub stage_id: String,
    pub percentage: u8,
    pub observation_window_ticks: u64,
    pub expected_health_sha256: String,
}

impl RolloutStage {
    pub fn new(
        stage_id: impl Into<String>,
        percentage: u8,
        observation_window_ticks: u64,
        expected_health_sha256: impl Into<String>,
    ) -> Result<Self, ReleaseError> {
        let stage_id = stage_id.into();
        let expected_health_sha256 = expected_health_sha256.into();
        validate_identifier(&stage_id, "rollout stage")?;
        validate_sha256(&expected_health_sha256, "rollout health")?;
        if percentage == 0 || percentage > 100 || observation_window_ticks == 0 {
            return Err(ReleaseError::InvalidRolloutTransition);
        }
        Ok(Self {
            stage_id,
            percentage,
            observation_window_ticks,
            expected_health_sha256,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RolloutPlan {
    pub plan_id: String,
    pub policy_snapshot_sha256: String,
    pub artifact_attestation_sha256: String,
    pub baseline_manifest_root_sha256: String,
    pub stages: Vec<RolloutStage>,
    pub rollback_required: bool,
    pub plan_sha256: String,
}

impl RolloutPlan {
    pub fn new(
        plan_id: impl Into<String>,
        attestation: &ArtifactAttestation,
        stages: Vec<RolloutStage>,
    ) -> Result<Self, ReleaseError> {
        attestation.verify()?;
        let plan_id = plan_id.into();
        validate_identifier(&plan_id, "rollout plan")?;
        if stages.is_empty()
            || stages.len() > MAX_ROLLOUT_STAGES
            || stages.last().map(|stage| stage.percentage) != Some(100)
            || stages
                .windows(2)
                .any(|pair| pair[0].percentage >= pair[1].percentage)
        {
            return Err(ReleaseError::InvalidRolloutTransition);
        }
        let unique = stages
            .iter()
            .map(|stage| stage.stage_id.as_str())
            .collect::<BTreeSet<_>>();
        if unique.len() != stages.len() {
            return Err(ReleaseError::InvalidRolloutTransition);
        }
        let rollback_required = true;
        let plan_sha256 = hash_serializable(&(
            &plan_id,
            &attestation.policy_snapshot_sha256,
            &attestation.attestation_sha256,
            &attestation.manifest_root_sha256,
            &stages,
            rollback_required,
        ))?;
        Ok(Self {
            plan_id,
            policy_snapshot_sha256: attestation.policy_snapshot_sha256.clone(),
            artifact_attestation_sha256: attestation.attestation_sha256.clone(),
            baseline_manifest_root_sha256: attestation.manifest_root_sha256.clone(),
            stages,
            rollback_required,
            plan_sha256,
        })
    }

    pub fn verify(&self) -> Result<(), ReleaseError> {
        let expected = hash_serializable(&(
            &self.plan_id,
            &self.policy_snapshot_sha256,
            &self.artifact_attestation_sha256,
            &self.baseline_manifest_root_sha256,
            &self.stages,
            self.rollback_required,
        ))?;
        if expected != self.plan_sha256
            || !self.rollback_required
            || self.stages.is_empty()
            || self.stages.last().map(|stage| stage.percentage) != Some(100)
            || self
                .stages
                .windows(2)
                .any(|pair| pair[0].percentage >= pair[1].percentage)
        {
            return Err(ReleaseError::InvalidRolloutTransition);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RollbackDrillCertificate {
    pub certificate_id: String,
    pub rollout_plan_sha256: String,
    pub artifact_attestation_sha256: String,
    pub rollback_from_stage_id: String,
    pub restored_manifest_root_sha256: String,
    pub evidence_sha256: String,
    pub rollout_audit_tail_hash: String,
    pub certificate_sha256: String,
}

impl RollbackDrillCertificate {
    pub fn verify(&self) -> Result<(), ReleaseError> {
        let expected = hash_serializable(&(
            &self.certificate_id,
            &self.rollout_plan_sha256,
            &self.artifact_attestation_sha256,
            &self.rollback_from_stage_id,
            &self.restored_manifest_root_sha256,
            &self.evidence_sha256,
            &self.rollout_audit_tail_hash,
        ))?;
        if expected != self.certificate_sha256 {
            return Err(ReleaseError::CertificationDenied(
                "rollback drill certificate digest".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RolloutSimulationReceipt {
    pub rollout_plan_sha256: String,
    pub artifact_attestation_sha256: String,
    pub validated_stage_ids: BTreeSet<String>,
    pub rollback_certificate_sha256: String,
    pub final_state: RolloutState,
    pub rollout_audit_tail_hash: String,
    pub receipt_sha256: String,
}

impl RolloutSimulationReceipt {
    pub fn verify(&self) -> Result<(), ReleaseError> {
        let expected = hash_serializable(&(
            &self.rollout_plan_sha256,
            &self.artifact_attestation_sha256,
            &self.validated_stage_ids,
            &self.rollback_certificate_sha256,
            self.final_state,
            &self.rollout_audit_tail_hash,
        ))?;
        if expected != self.receipt_sha256 || self.final_state != RolloutState::Completed {
            return Err(ReleaseError::CertificationDenied(
                "rollout receipt digest or final state".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct RolloutDrill {
    plan: RolloutPlan,
    state: RolloutState,
    next_stage_index: usize,
    validated_stage_ids: BTreeSet<String>,
    rollback_from_stage_id: Option<String>,
    rollback_certificate: Option<RollbackDrillCertificate>,
    audit: ReleaseAuditChain,
}

impl RolloutDrill {
    pub fn new(
        plan: RolloutPlan,
        audit_genesis: impl Into<String>,
    ) -> Result<Self, ReleaseError> {
        plan.verify()?;
        Ok(Self {
            plan,
            state: RolloutState::Planned,
            next_stage_index: 0,
            validated_stage_ids: BTreeSet::new(),
            rollback_from_stage_id: None,
            rollback_certificate: None,
            audit: ReleaseAuditChain::new(audit_genesis)?,
        })
    }

    pub fn start(&mut self) -> Result<(), ReleaseError> {
        if self.state != RolloutState::Planned {
            return Err(ReleaseError::InvalidRolloutTransition);
        }
        self.state = RolloutState::CanaryRunning;
        self.audit.append(ReleaseAuditEvent {
            action: "rollout_simulation_started".into(),
            subject_id: self.plan.plan_id.clone(),
            outcome: "canary_running".into(),
            metadata: BTreeMap::new(),
        })?;
        Ok(())
    }

    pub fn record_stage(
        &mut self,
        stage_id: &str,
        observed_health_sha256: impl Into<String>,
        healthy: bool,
    ) -> Result<RolloutState, ReleaseError> {
        if self.state != RolloutState::CanaryRunning {
            return Err(ReleaseError::InvalidRolloutTransition);
        }
        let observed_health_sha256 = observed_health_sha256.into();
        validate_sha256(&observed_health_sha256, "observed rollout health")?;
        let stage = self
            .plan
            .stages
            .get(self.next_stage_index)
            .ok_or(ReleaseError::InvalidRolloutTransition)?;
        if stage.stage_id != stage_id {
            return Err(ReleaseError::InvalidRolloutTransition);
        }
        let accepted = healthy && observed_health_sha256 == stage.expected_health_sha256;
        self.audit.append(ReleaseAuditEvent {
            action: "rollout_stage_observed".into(),
            subject_id: stage.stage_id.clone(),
            outcome: if accepted { "accepted" } else { "rollback_required" }.into(),
            metadata: BTreeMap::from([
                ("percentage".into(), stage.percentage.to_string()),
                ("observed_health_sha256".into(), observed_health_sha256),
            ]),
        })?;
        if !accepted {
            self.rollback_from_stage_id = Some(stage.stage_id.clone());
            self.state = RolloutState::RollbackRunning;
            return Ok(self.state);
        }
        self.validated_stage_ids.insert(stage.stage_id.clone());
        self.next_stage_index += 1;
        if self.next_stage_index == self.plan.stages.len() {
            self.state = RolloutState::CanaryValidated;
        }
        Ok(self.state)
    }

    pub fn begin_rollback_drill(&mut self) -> Result<(), ReleaseError> {
        if self.state != RolloutState::CanaryValidated {
            return Err(ReleaseError::InvalidRolloutTransition);
        }
        self.rollback_from_stage_id = self
            .plan
            .stages
            .last()
            .map(|stage| stage.stage_id.clone());
        self.state = RolloutState::RollbackRunning;
        self.audit.append(ReleaseAuditEvent {
            action: "rollback_drill_started".into(),
            subject_id: self.plan.plan_id.clone(),
            outcome: "rollback_running".into(),
            metadata: BTreeMap::new(),
        })?;
        Ok(())
    }

    pub fn complete_rollback(
        &mut self,
        restored_manifest_root_sha256: impl Into<String>,
        evidence_sha256: impl Into<String>,
    ) -> Result<RollbackDrillCertificate, ReleaseError> {
        if self.state != RolloutState::RollbackRunning {
            return Err(ReleaseError::InvalidRolloutTransition);
        }
        let restored_manifest_root_sha256 = restored_manifest_root_sha256.into();
        let evidence_sha256 = evidence_sha256.into();
        validate_sha256(&restored_manifest_root_sha256, "restored manifest")?;
        validate_sha256(&evidence_sha256, "rollback evidence")?;
        if restored_manifest_root_sha256 != self.plan.baseline_manifest_root_sha256 {
            self.state = RolloutState::Failed;
            return Err(ReleaseError::CertificationDenied(
                "rollback did not restore baseline manifest".into(),
            ));
        }
        let rollback_from_stage_id = self
            .rollback_from_stage_id
            .clone()
            .ok_or(ReleaseError::InvalidRolloutTransition)?;
        self.state = RolloutState::RolledBack;
        self.audit.append(ReleaseAuditEvent {
            action: "rollback_drill_completed".into(),
            subject_id: self.plan.plan_id.clone(),
            outcome: "rolled_back".into(),
            metadata: BTreeMap::from([
                ("rollback_from_stage_id".into(), rollback_from_stage_id.clone()),
                (
                    "restored_manifest_root_sha256".into(),
                    restored_manifest_root_sha256.clone(),
                ),
                ("evidence_sha256".into(), evidence_sha256.clone()),
            ]),
        })?;
        let seed = hash_serializable(&(
            &self.plan.plan_sha256,
            &self.plan.artifact_attestation_sha256,
            &rollback_from_stage_id,
            &restored_manifest_root_sha256,
            &evidence_sha256,
            self.audit.tail_hash(),
        ))?;
        let certificate_id = format!("rollback-drill-{}", &seed[..24]);
        let certificate_sha256 = hash_serializable(&(
            &certificate_id,
            &self.plan.plan_sha256,
            &self.plan.artifact_attestation_sha256,
            &rollback_from_stage_id,
            &restored_manifest_root_sha256,
            &evidence_sha256,
            self.audit.tail_hash(),
        ))?;
        let certificate = RollbackDrillCertificate {
            certificate_id,
            rollout_plan_sha256: self.plan.plan_sha256.clone(),
            artifact_attestation_sha256: self.plan.artifact_attestation_sha256.clone(),
            rollback_from_stage_id,
            restored_manifest_root_sha256,
            evidence_sha256,
            rollout_audit_tail_hash: self.audit.tail_hash().into(),
            certificate_sha256,
        };
        certificate.verify()?;
        self.rollback_certificate = Some(certificate.clone());
        Ok(certificate)
    }

    pub fn finalize(&mut self) -> Result<RolloutSimulationReceipt, ReleaseError> {
        if self.state != RolloutState::RolledBack || self.rollback_certificate.is_none() {
            return Err(ReleaseError::InvalidRolloutTransition);
        }
        self.state = RolloutState::Completed;
        let rollback_certificate = self
            .rollback_certificate
            .as_ref()
            .expect("rollback certificate present");
        self.audit.append(ReleaseAuditEvent {
            action: "rollout_simulation_completed".into(),
            subject_id: self.plan.plan_id.clone(),
            outcome: "completed".into(),
            metadata: BTreeMap::from([(
                "rollback_certificate_sha256".into(),
                rollback_certificate.certificate_sha256.clone(),
            )]),
        })?;
        let receipt_sha256 = hash_serializable(&(
            &self.plan.plan_sha256,
            &self.plan.artifact_attestation_sha256,
            &self.validated_stage_ids,
            &rollback_certificate.certificate_sha256,
            self.state,
            self.audit.tail_hash(),
        ))?;
        let receipt = RolloutSimulationReceipt {
            rollout_plan_sha256: self.plan.plan_sha256.clone(),
            artifact_attestation_sha256: self.plan.artifact_attestation_sha256.clone(),
            validated_stage_ids: self.validated_stage_ids.clone(),
            rollback_certificate_sha256: rollback_certificate.certificate_sha256.clone(),
            final_state: self.state,
            rollout_audit_tail_hash: self.audit.tail_hash().into(),
            receipt_sha256,
        };
        receipt.verify()?;
        Ok(receipt)
    }

    pub fn state(&self) -> RolloutState {
        self.state
    }

    pub fn audit(&self) -> &ReleaseAuditChain {
        &self.audit
    }
}
