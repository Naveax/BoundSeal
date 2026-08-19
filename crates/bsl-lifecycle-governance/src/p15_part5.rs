impl DecommissionPlan {
    pub fn new(
        plan_id: impl Into<String>,
        final_assurance: &FinalAssuranceCertificate,
        roadmap: &RoadmapClosureCertificate,
        maintenance: &MaintenanceReleaseCertificate,
        continuity: &ContinuityCertificate,
        ordered_steps: Vec<DecommissionStep>,
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
        validate_identifier(&plan_id, "decommission plan")?;
        if roadmap.final_assurance_certificate_sha256 != final_assurance.certificate_sha256
            || maintenance.baseline_final_assurance_sha256 != final_assurance.certificate_sha256
            || maintenance.baseline_roadmap_closure_sha256 != roadmap.closure_sha256
            || continuity.maintenance_release_certificate_sha256 != maintenance.certificate_sha256
            || continuity.policy_snapshot_sha256 != final_assurance.policy_snapshot_sha256
            || ordered_steps != canonical_decommission_steps()
        {
            return Err(LifecycleError::InvalidClosure(
                "decommission certificate binding or step sequence".into(),
            ));
        }
        let policy_snapshot_sha256 = final_assurance.policy_snapshot_sha256.clone();
        let final_assurance_certificate_sha256 = final_assurance.certificate_sha256.clone();
        let roadmap_closure_sha256 = roadmap.closure_sha256.clone();
        let maintenance_release_certificate_sha256 = maintenance.certificate_sha256.clone();
        let continuity_certificate_sha256 = continuity.certificate_sha256.clone();
        let plan_sha256 = hash_serializable(&(
            &plan_id,
            &policy_snapshot_sha256,
            &final_assurance_certificate_sha256,
            &roadmap_closure_sha256,
            &maintenance_release_certificate_sha256,
            &continuity_certificate_sha256,
            &ordered_steps,
        ))?;
        Ok(Self {
            plan_id,
            policy_snapshot_sha256,
            final_assurance_certificate_sha256,
            roadmap_closure_sha256,
            maintenance_release_certificate_sha256,
            continuity_certificate_sha256,
            ordered_steps,
            plan_sha256,
        })
    }

    pub fn canonical(
        plan_id: impl Into<String>,
        final_assurance: &FinalAssuranceCertificate,
        roadmap: &RoadmapClosureCertificate,
        maintenance: &MaintenanceReleaseCertificate,
        continuity: &ContinuityCertificate,
    ) -> Result<Self, LifecycleError> {
        Self::new(
            plan_id,
            final_assurance,
            roadmap,
            maintenance,
            continuity,
            canonical_decommission_steps(),
        )
    }

    pub fn verify(&self) -> Result<(), LifecycleError> {
        validate_identifier(&self.plan_id, "decommission plan")?;
        for (name, value) in [
            ("decommission policy", self.policy_snapshot_sha256.as_str()),
            (
                "decommission final assurance",
                self.final_assurance_certificate_sha256.as_str(),
            ),
            ("decommission roadmap", self.roadmap_closure_sha256.as_str()),
            (
                "decommission maintenance",
                self.maintenance_release_certificate_sha256.as_str(),
            ),
            (
                "decommission continuity",
                self.continuity_certificate_sha256.as_str(),
            ),
            ("decommission plan", self.plan_sha256.as_str()),
        ] {
            validate_sha256(value, name)?;
        }
        if self.ordered_steps != canonical_decommission_steps() {
            return Err(LifecycleError::InvalidClosure(
                "decommission step sequence".into(),
            ));
        }
        let expected = hash_serializable(&(
            &self.plan_id,
            &self.policy_snapshot_sha256,
            &self.final_assurance_certificate_sha256,
            &self.roadmap_closure_sha256,
            &self.maintenance_release_certificate_sha256,
            &self.continuity_certificate_sha256,
            &self.ordered_steps,
        ))?;
        if expected != self.plan_sha256 {
            return Err(LifecycleError::InvalidClosure(
                "decommission plan digest".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TombstoneCertificate {
    pub certificate_id: String,
    pub decommission_plan_sha256: String,
    pub continuity_certificate_sha256: String,
    pub step_receipts: BTreeMap<DecommissionStep, String>,
    pub live_grant_count: u64,
    pub live_secret_count: u64,
    pub live_session_count: u64,
    pub tombstone_root_sha256: String,
    pub authority_audit_tail_hash: String,
    pub certificate_sha256: String,
}
