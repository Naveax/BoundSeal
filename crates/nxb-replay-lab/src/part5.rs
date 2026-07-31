#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReplayComparison {
    pub comparison_id: String,
    pub baseline_trace_sha256: String,
    pub candidate_trace_sha256: String,
    pub class: DriftClass,
    pub changed_sequences: BTreeSet<u64>,
    pub comparison_sha256: String,
}

impl ReplayComparison {
    pub fn verify(&self) -> Result<(), ReplayError> {
        let expected = hash_serializable(&(
            &self.comparison_id,
            &self.baseline_trace_sha256,
            &self.candidate_trace_sha256,
            self.class,
            &self.changed_sequences,
        ))?;
        if expected != self.comparison_sha256 {
            return Err(ReplayError::InvalidComparison(
                "comparison digest mismatch".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct ReplayDriftComparator;

impl ReplayDriftComparator {
    pub fn compare(
        &self,
        baseline: &ReplayTrace,
        candidate: &ReplayTrace,
    ) -> Result<ReplayComparison, ReplayError> {
        baseline.verify()?;
        candidate.verify()?;
        let mut changed_sequences = BTreeSet::new();
        let class = if baseline.bundle_sha256 != candidate.bundle_sha256 {
            DriftClass::InputDrift
        } else if baseline.fault_plan_sha256 != candidate.fault_plan_sha256 {
            DriftClass::FaultPlanDrift
        } else {
            let maximum = baseline.observations.len().max(candidate.observations.len());
            let mut semantic = false;
            let mut timing = false;
            for index in 0..maximum {
                match (
                    baseline.observations.get(index),
                    candidate.observations.get(index),
                ) {
                    (Some(left), Some(right)) => {
                        if left.sequence != right.sequence
                            || left.input_sha256 != right.input_sha256
                            || left.output_sha256 != right.output_sha256
                            || left.metadata_sha256 != right.metadata_sha256
                            || left.outcome != right.outcome
                            || left.applied_fault_ids != right.applied_fault_ids
                        {
                            semantic = true;
                            changed_sequences.insert(left.sequence.max(right.sequence));
                        } else if left.virtual_tick != right.virtual_tick {
                            timing = true;
                            changed_sequences.insert(left.sequence);
                        }
                    }
                    (Some(observation), None) | (None, Some(observation)) => {
                        semantic = true;
                        changed_sequences.insert(observation.sequence);
                    }
                    (None, None) => {}
                }
            }
            if semantic {
                DriftClass::SemanticDrift
            } else if timing {
                DriftClass::TimingDrift
            } else {
                DriftClass::Exact
            }
        };
        let seed = hash_serializable(&(
            &baseline.trace_sha256,
            &candidate.trace_sha256,
            class,
            &changed_sequences,
        ))?;
        let comparison_id = format!("replay-comparison-{}", &seed[..24]);
        let comparison_sha256 = hash_serializable(&(
            &comparison_id,
            &baseline.trace_sha256,
            &candidate.trace_sha256,
            class,
            &changed_sequences,
        ))?;
        let comparison = ReplayComparison {
            comparison_id,
            baseline_trace_sha256: baseline.trace_sha256.clone(),
            candidate_trace_sha256: candidate.trace_sha256.clone(),
            class,
            changed_sequences,
            comparison_sha256,
        };
        comparison.verify()?;
        Ok(comparison)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReproducibilityCertificate {
    pub certificate_id: String,
    pub authority_id: String,
    pub policy_snapshot_sha256: String,
    pub bundle_sha256: String,
    pub fault_plan_sha256: String,
    pub trace_sha256: String,
    pub result_sha256: String,
    pub engine_ids: BTreeSet<String>,
    pub receipt_sha256: BTreeSet<String>,
    pub quorum: usize,
    pub authority_audit_tail_hash: String,
    pub certificate_sha256: String,
}

impl ReproducibilityCertificate {
    pub fn verify(&self) -> Result<(), ReplayError> {
        for (name, value) in [
            ("reproducibility policy", self.policy_snapshot_sha256.as_str()),
            ("reproducibility bundle", self.bundle_sha256.as_str()),
            ("reproducibility plan", self.fault_plan_sha256.as_str()),
            ("reproducibility trace", self.trace_sha256.as_str()),
            ("reproducibility result", self.result_sha256.as_str()),
            (
                "reproducibility authority audit",
                self.authority_audit_tail_hash.as_str(),
            ),
            ("reproducibility certificate", self.certificate_sha256.as_str()),
        ] {
            validate_sha256(value, name)?;
        }
        if self.quorum < 2
            || self.engine_ids.len() < self.quorum
            || self.receipt_sha256.len() < self.quorum
        {
            return Err(ReplayError::CertificationDenied(
                "reproducibility quorum".into(),
            ));
        }
        let expected = hash_serializable(&(
            &self.certificate_id,
            &self.authority_id,
            &self.policy_snapshot_sha256,
            &self.bundle_sha256,
            &self.fault_plan_sha256,
            &self.trace_sha256,
            &self.result_sha256,
            &self.engine_ids,
            &self.receipt_sha256,
            self.quorum,
            &self.authority_audit_tail_hash,
        ))?;
        if expected != self.certificate_sha256 {
            return Err(ReplayError::CertificationDenied(
                "reproducibility certificate digest".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct ReproducibilityAuthority {
    authority_id: String,
    policy_snapshot_sha256: String,
    required_quorum: usize,
    audit: ReplayAuditChain,
}

impl ReproducibilityAuthority {
    pub fn new(
        authority_id: impl Into<String>,
        policy_snapshot_sha256: impl Into<String>,
        required_quorum: usize,
        audit_genesis: impl Into<String>,
    ) -> Result<Self, ReplayError> {
        let authority_id = authority_id.into();
        let policy_snapshot_sha256 = policy_snapshot_sha256.into();
        validate_identifier(&authority_id, "reproducibility authority")?;
        validate_sha256(&policy_snapshot_sha256, "reproducibility policy")?;
        if !(2..=MAX_REPRODUCIBILITY_RECEIPTS).contains(&required_quorum) {
            return Err(ReplayError::CertificationDenied(
                "required replay quorum".into(),
            ));
        }
        Ok(Self {
            authority_id,
            policy_snapshot_sha256,
            required_quorum,
            audit: ReplayAuditChain::new(audit_genesis)?,
        })
    }

    pub fn certify(
        &mut self,
        receipts: &[ReplayReceipt],
    ) -> Result<ReproducibilityCertificate, ReplayError> {
        if receipts.len() < self.required_quorum
            || receipts.len() > MAX_REPRODUCIBILITY_RECEIPTS
        {
            return Err(ReplayError::CertificationDenied(
                "replay receipt count".into(),
            ));
        }
        for receipt in receipts {
            receipt.verify()?;
        }
        let first = receipts
            .first()
            .ok_or_else(|| ReplayError::CertificationDenied("missing receipts".into()))?;
        let engine_ids = receipts
            .iter()
            .map(|receipt| receipt.engine_id.clone())
            .collect::<BTreeSet<_>>();
        let receipt_sha256 = receipts
            .iter()
            .map(|receipt| receipt.receipt_sha256.clone())
            .collect::<BTreeSet<_>>();
        if engine_ids.len() != receipts.len()
            || receipt_sha256.len() != receipts.len()
            || first.policy_snapshot_sha256 != self.policy_snapshot_sha256
            || receipts.iter().any(|receipt| {
                receipt.policy_snapshot_sha256 != first.policy_snapshot_sha256
                    || receipt.bundle_sha256 != first.bundle_sha256
                    || receipt.fault_plan_sha256 != first.fault_plan_sha256
                    || receipt.trace_sha256 != first.trace_sha256
                    || receipt.result_sha256 != first.result_sha256
                    || receipt.observation_count != first.observation_count
                    || receipt.final_virtual_tick != first.final_virtual_tick
            })
        {
            return Err(ReplayError::CertificationDenied(
                "receipt identity, policy or deterministic result mismatch".into(),
            ));
        }
        let seed = hash_serializable(&(
            &self.authority_id,
            &self.policy_snapshot_sha256,
            &first.bundle_sha256,
            &first.fault_plan_sha256,
            &first.trace_sha256,
            &first.result_sha256,
            &engine_ids,
            &receipt_sha256,
            self.required_quorum,
        ))?;
        let certificate_id = format!("reproducibility-{}", &seed[..24]);
        self.audit.append(ReplayAuditEvent {
            action: "reproducibility_quorum_accepted".into(),
            subject_id: certificate_id.clone(),
            outcome: "accepted".into(),
            metadata: BTreeMap::from([
                ("bundle_sha256".into(), first.bundle_sha256.clone()),
                ("trace_sha256".into(), first.trace_sha256.clone()),
                ("quorum".into(), self.required_quorum.to_string()),
            ]),
        })?;
        let certificate_sha256 = hash_serializable(&(
            &certificate_id,
            &self.authority_id,
            &self.policy_snapshot_sha256,
            &first.bundle_sha256,
            &first.fault_plan_sha256,
            &first.trace_sha256,
            &first.result_sha256,
            &engine_ids,
            &receipt_sha256,
            self.required_quorum,
            self.audit.tail_hash(),
        ))?;
        let certificate = ReproducibilityCertificate {
            certificate_id,
            authority_id: self.authority_id.clone(),
            policy_snapshot_sha256: self.policy_snapshot_sha256.clone(),
            bundle_sha256: first.bundle_sha256.clone(),
            fault_plan_sha256: first.fault_plan_sha256.clone(),
            trace_sha256: first.trace_sha256.clone(),
            result_sha256: first.result_sha256.clone(),
            engine_ids,
            receipt_sha256,
            quorum: self.required_quorum,
            authority_audit_tail_hash: self.audit.tail_hash().into(),
            certificate_sha256,
        };
        certificate.verify()?;
        Ok(certificate)
    }

    pub fn audit(&self) -> &ReplayAuditChain {
        &self.audit
    }
}
