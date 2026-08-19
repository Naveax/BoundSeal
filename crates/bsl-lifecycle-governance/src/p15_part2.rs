impl EvidenceSamplePlan {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        plan_id: impl Into<String>,
        final_assurance: &FinalAssuranceCertificate,
        roadmap: &RoadmapClosureCertificate,
        maintenance: &MaintenanceReleaseCertificate,
        continuity: &ContinuityCertificate,
        deterministic_seed_sha256: impl Into<String>,
        sample_count: u32,
    ) -> Result<Self, LifecycleError> {
        final_assurance
            .verify()
            .map_err(|error| LifecycleError::InvalidClosure(error.to_string()))?;
        roadmap
            .verify()
            .map_err(|error| LifecycleError::InvalidClosure(error.to_string()))?;
        maintenance.verify()?;
        continuity.verify()?;
        let plan_id = plan_id.into();
        let deterministic_seed_sha256 = deterministic_seed_sha256.into();
        validate_identifier(&plan_id, "evidence sample plan")?;
        validate_sha256(&deterministic_seed_sha256, "evidence sample seed")?;
        if roadmap.final_assurance_certificate_sha256 != final_assurance.certificate_sha256
            || maintenance.baseline_final_assurance_sha256 != final_assurance.certificate_sha256
            || maintenance.baseline_roadmap_closure_sha256 != roadmap.closure_sha256
            || continuity.maintenance_release_certificate_sha256 != maintenance.certificate_sha256
            || continuity.policy_snapshot_sha256 != final_assurance.policy_snapshot_sha256
            || sample_count == 0
            || sample_count > MAX_EVIDENCE_SAMPLES
        {
            return Err(LifecycleError::InvalidClosure(
                "evidence sample certificate binding or count".into(),
            ));
        }
        let trusted_evidence_roots = BTreeMap::from([
            (
                EvidenceClass::FinalAssurance,
                final_assurance.certificate_sha256.clone(),
            ),
            (
                EvidenceClass::RoadmapClosure,
                roadmap.closure_sha256.clone(),
            ),
            (
                EvidenceClass::MaintenanceRelease,
                maintenance.certificate_sha256.clone(),
            ),
            (
                EvidenceClass::Continuity,
                continuity.certificate_sha256.clone(),
            ),
            (
                EvidenceClass::AuditTail,
                continuity.authority_audit_tail_hash.clone(),
            ),
            (
                EvidenceClass::FreezeManifest,
                final_assurance.freeze_manifest_sha256.clone(),
            ),
        ]);
        let selected_classes = mandatory_evidence_classes();
        let policy_snapshot_sha256 = final_assurance.policy_snapshot_sha256.clone();
        let plan_sha256 = hash_serializable(&(
            &plan_id,
            &policy_snapshot_sha256,
            &trusted_evidence_roots,
            &selected_classes,
            &deterministic_seed_sha256,
            sample_count,
        ))?;
        Ok(Self {
            plan_id,
            policy_snapshot_sha256,
            trusted_evidence_roots,
            selected_classes,
            deterministic_seed_sha256,
            sample_count,
            plan_sha256,
        })
    }

    pub fn verify(&self) -> Result<(), LifecycleError> {
        validate_identifier(&self.plan_id, "evidence sample plan")?;
        validate_sha256(&self.policy_snapshot_sha256, "evidence sample policy")?;
        validate_sha256(&self.deterministic_seed_sha256, "evidence sample seed")?;
        validate_sha256(&self.plan_sha256, "evidence sample plan digest")?;
        if self.selected_classes != mandatory_evidence_classes()
            || self.trusted_evidence_roots.len() != mandatory_evidence_classes().len()
            || self.sample_count == 0
            || self.sample_count > MAX_EVIDENCE_SAMPLES
            || self.trusted_evidence_roots.iter().any(|(class, root)| {
                !self.selected_classes.contains(class)
                    || validate_sha256(root, "trusted evidence root").is_err()
            })
        {
            return Err(LifecycleError::InvalidClosure(
                "evidence sample plan coverage".into(),
            ));
        }
        let expected = hash_serializable(&(
            &self.plan_id,
            &self.policy_snapshot_sha256,
            &self.trusted_evidence_roots,
            &self.selected_classes,
            &self.deterministic_seed_sha256,
            self.sample_count,
        ))?;
        if expected != self.plan_sha256 {
            return Err(LifecycleError::InvalidClosure(
                "evidence sample plan digest".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IndependentVerificationReceipt {
    pub receipt_id: String,
    pub verifier_manifest_sha256: String,
    pub organization_root_sha256: String,
    pub implementation_root_sha256: String,
    pub sample_plan_sha256: String,
    pub result_root_sha256: String,
    pub finding_count: u32,
    pub external_io_observed: bool,
    pub receipt_sha256: String,
}
