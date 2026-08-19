#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OracleVote {
    pub oracle_id: String,
    pub decision: OracleDecision,
    pub evidence_sha256: String,
    pub repeatable_delta_sha256: Option<String>,
    pub policy_snapshot_sha256: String,
    pub validation_audit_tail_hash: String,
}

impl OracleVote {
    pub fn validate(&self) -> Result<(), WorkflowError> {
        validate_identifier(&self.oracle_id, "oracle_id")?;
        validate_sha256(&self.evidence_sha256, "oracle evidence")?;
        validate_sha256(&self.policy_snapshot_sha256, "oracle policy snapshot")?;
        validate_sha256(
            &self.validation_audit_tail_hash,
            "oracle validation audit tail",
        )?;
        if let Some(delta) = &self.repeatable_delta_sha256 {
            validate_sha256(delta, "oracle repeatable delta")?;
        }
        if self.decision == OracleDecision::Confirmed
            && self.repeatable_delta_sha256.is_none()
        {
            return Err(WorkflowError::InvalidOracleQuorum);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OracleQuorumResult {
    pub quorum_id: String,
    pub decision: QuorumDecision,
    pub vote_count: usize,
    pub confirmed_votes: usize,
    pub rejected_votes: usize,
    pub inconclusive_votes: usize,
    pub policy_snapshot_sha256: String,
    pub consensus_delta_sha256: Option<String>,
    pub evidence_sha256: String,
}

#[derive(Debug, Clone)]
pub struct OracleCoordinator {
    coordinator_id: String,
    required_votes: usize,
    maximum_votes: usize,
}

impl OracleCoordinator {
    pub fn new(
        coordinator_id: impl Into<String>,
        required_votes: usize,
        maximum_votes: usize,
    ) -> Result<Self, WorkflowError> {
        let coordinator_id = coordinator_id.into();
        validate_identifier(&coordinator_id, "coordinator_id")?;
        if required_votes == 0
            || maximum_votes < required_votes
            || maximum_votes > MAX_ORACLE_VOTES
        {
            return Err(WorkflowError::InvalidOracleQuorum);
        }
        Ok(Self {
            coordinator_id,
            required_votes,
            maximum_votes,
        })
    }

    pub fn evaluate(
        &self,
        policy_snapshot_sha256: impl Into<String>,
        votes: &[OracleVote],
    ) -> Result<OracleQuorumResult, WorkflowError> {
        let policy_snapshot_sha256 = policy_snapshot_sha256.into();
        validate_sha256(&policy_snapshot_sha256, "quorum policy snapshot")?;
        if votes.len() < self.required_votes || votes.len() > self.maximum_votes {
            return Err(WorkflowError::InvalidOracleQuorum);
        }
        let mut oracle_ids = BTreeSet::new();
        let mut confirmed_votes = 0usize;
        let mut rejected_votes = 0usize;
        let mut inconclusive_votes = 0usize;
        let mut confirmed_deltas = BTreeSet::new();
        for vote in votes {
            vote.validate()?;
            if vote.policy_snapshot_sha256 != policy_snapshot_sha256
                || !oracle_ids.insert(vote.oracle_id.clone())
            {
                return Err(WorkflowError::InvalidOracleQuorum);
            }
            match vote.decision {
                OracleDecision::Confirmed => {
                    confirmed_votes += 1;
                    confirmed_deltas.insert(
                        vote.repeatable_delta_sha256
                            .clone()
                            .ok_or(WorkflowError::InvalidOracleQuorum)?,
                    );
                }
                OracleDecision::Rejected => rejected_votes += 1,
                OracleDecision::Inconclusive => inconclusive_votes += 1,
            }
        }
        let decision = if confirmed_deltas.len() > 1 {
            QuorumDecision::Drift
        } else if confirmed_votes >= self.required_votes {
            QuorumDecision::Confirmed
        } else if rejected_votes >= self.required_votes {
            QuorumDecision::Rejected
        } else {
            QuorumDecision::Inconclusive
        };
        let consensus_delta_sha256 = if confirmed_deltas.len() == 1 {
            confirmed_deltas.iter().next().cloned()
        } else {
            None
        };
        let evidence_sha256 = hash_serializable(&(
            &self.coordinator_id,
            &policy_snapshot_sha256,
            votes,
            decision,
        ))?;
        let quorum_id = format!("quorum-{}", &evidence_sha256[..24]);
        Ok(OracleQuorumResult {
            quorum_id,
            decision,
            vote_count: votes.len(),
            confirmed_votes,
            rejected_votes,
            inconclusive_votes,
            policy_snapshot_sha256,
            consensus_delta_sha256,
            evidence_sha256,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertificationInput {
    pub run_id: String,
    pub policy_snapshot_sha256: String,
    pub workflow_id: String,
    pub workflow_definition_sha256: String,
    pub workflow_state: WorkflowState,
    pub workflow_audit_tail_hash: String,
    pub validation_audit_tail_hash: String,
    pub knowledge_audit_tail_hash: String,
    pub export_manifest_root_sha256: String,
    pub quorum: OracleQuorumResult,
    pub unresolved_cleanup_objects: usize,
    pub failed_steps: usize,
    pub all_audits_verified: bool,
    pub policy_drift_detected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunCertificate {
    pub certificate_id: String,
    pub run_id: String,
    pub workflow_id: String,
    pub policy_snapshot_sha256: String,
    pub workflow_definition_sha256: String,
    pub quorum_id: String,
    pub quorum_decision: QuorumDecision,
    pub export_manifest_root_sha256: String,
    pub audit_roots_sha256: String,
    pub certificate_sha256: String,
    pub safe_boundary: String,
}

#[derive(Debug)]
pub struct RunCertificationAuthority {
    authority_id: String,
    audit: WorkflowAuditChain,
}

impl RunCertificationAuthority {
    pub fn new(
        authority_id: impl Into<String>,
        audit_genesis: impl Into<String>,
    ) -> Result<Self, WorkflowError> {
        let authority_id = authority_id.into();
        validate_identifier(&authority_id, "certification authority")?;
        Ok(Self {
            authority_id,
            audit: WorkflowAuditChain::new(audit_genesis)?,
        })
    }

    pub fn certify(
        &mut self,
        input: CertificationInput,
    ) -> Result<RunCertificate, WorkflowError> {
        validate_identifier(&input.run_id, "certification run")?;
        validate_identifier(&input.workflow_id, "certification workflow")?;
        for (name, value) in [
            ("policy snapshot", &input.policy_snapshot_sha256),
            ("workflow definition", &input.workflow_definition_sha256),
            ("workflow audit", &input.workflow_audit_tail_hash),
            ("validation audit", &input.validation_audit_tail_hash),
            ("knowledge audit", &input.knowledge_audit_tail_hash),
            ("export manifest", &input.export_manifest_root_sha256),
        ] {
            validate_sha256(value, name)?;
        }
        if input.workflow_state != WorkflowState::Completed
            || input.unresolved_cleanup_objects != 0
            || input.failed_steps != 0
            || !input.all_audits_verified
            || input.policy_drift_detected
            || input.quorum.policy_snapshot_sha256 != input.policy_snapshot_sha256
            || matches!(
                input.quorum.decision,
                QuorumDecision::Inconclusive | QuorumDecision::Drift
            )
        {
            return Err(WorkflowError::CertificationDenied(
                "workflow, cleanup, audit, policy or quorum closure".into(),
            ));
        }
        let audit_roots_sha256 = hash_serializable(&(
            &input.workflow_audit_tail_hash,
            &input.validation_audit_tail_hash,
            &input.knowledge_audit_tail_hash,
        ))?;
        let certificate_sha256 = hash_serializable(&(
            &self.authority_id,
            &input.run_id,
            &input.workflow_id,
            &input.policy_snapshot_sha256,
            &input.workflow_definition_sha256,
            &input.quorum.quorum_id,
            input.quorum.decision,
            &input.export_manifest_root_sha256,
            &audit_roots_sha256,
        ))?;
        let certificate_id = format!("run-certificate-{}", &certificate_sha256[..24]);
        self.audit.append(WorkflowAuditEvent {
            action: "run_certified".into(),
            subject_id: input.run_id.clone(),
            outcome: "closed_with_verified_boundaries".into(),
            metadata: BTreeMap::from([
                ("certificate_sha256".into(), certificate_sha256.clone()),
                ("quorum_id".into(), input.quorum.quorum_id.clone()),
            ]),
        })?;
        Ok(RunCertificate {
            certificate_id,
            run_id: input.run_id,
            workflow_id: input.workflow_id,
            policy_snapshot_sha256: input.policy_snapshot_sha256,
            workflow_definition_sha256: input.workflow_definition_sha256,
            quorum_id: input.quorum.quorum_id,
            quorum_decision: input.quorum.decision,
            export_manifest_root_sha256: input.export_manifest_root_sha256,
            audit_roots_sha256,
            certificate_sha256,
            safe_boundary: "networkless_typed_actions_inert_mutations_owned_cleanup_only".into(),
        })
    }

    pub fn audit(&self) -> &WorkflowAuditChain {
        &self.audit
    }
}
