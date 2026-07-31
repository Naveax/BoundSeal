impl PatchAdmissionPlan {
    pub fn new(
        plan_id: impl Into<String>,
        identity: &MaintenanceIdentity,
        proposal: &ChangeProposal,
        assessment: &ImpactAssessment,
        window: &MaintenanceWindow,
        ordered_steps: Vec<MaintenanceStep>,
    ) -> Result<Self, LifecycleError> {
        identity.verify()?;
        proposal.verify()?;
        assessment.verify()?;
        window.verify()?;
        let plan_id = plan_id.into();
        validate_identifier(&plan_id, "patch admission plan")?;
        if proposal.maintenance_identity_sha256 != identity.identity_sha256
            || assessment.proposal_sha256 != proposal.proposal_sha256
            || window.proposal_sha256 != proposal.proposal_sha256
            || ordered_steps != canonical_maintenance_steps()
        {
            return Err(LifecycleError::InvalidMaintenance(
                "patch admission binding or canonical steps".into(),
            ));
        }
        let maintenance_identity_sha256 = identity.identity_sha256.clone();
        let proposal_sha256 = proposal.proposal_sha256.clone();
        let assessment_sha256 = assessment.assessment_sha256.clone();
        let window_sha256 = window.window_sha256.clone();
        let plan_sha256 = hash_serializable(&(
            &plan_id,
            &maintenance_identity_sha256,
            &proposal_sha256,
            &assessment_sha256,
            &window_sha256,
            &ordered_steps,
        ))?;
        Ok(Self {
            plan_id,
            maintenance_identity_sha256,
            proposal_sha256,
            assessment_sha256,
            window_sha256,
            ordered_steps,
            plan_sha256,
        })
    }

    pub fn canonical(
        plan_id: impl Into<String>,
        identity: &MaintenanceIdentity,
        proposal: &ChangeProposal,
        assessment: &ImpactAssessment,
        window: &MaintenanceWindow,
    ) -> Result<Self, LifecycleError> {
        Self::new(
            plan_id,
            identity,
            proposal,
            assessment,
            window,
            canonical_maintenance_steps(),
        )
    }

    pub fn verify(&self) -> Result<(), LifecycleError> {
        validate_identifier(&self.plan_id, "patch admission plan")?;
        for (name, value) in [
            (
                "maintenance identity",
                self.maintenance_identity_sha256.as_str(),
            ),
            ("proposal", self.proposal_sha256.as_str()),
            ("assessment", self.assessment_sha256.as_str()),
            ("window", self.window_sha256.as_str()),
            ("plan", self.plan_sha256.as_str()),
        ] {
            validate_sha256(value, name)?;
        }
        if self.ordered_steps != canonical_maintenance_steps() {
            return Err(LifecycleError::InvalidMaintenance(
                "patch admission step sequence".into(),
            ));
        }
        let expected = hash_serializable(&(
            &self.plan_id,
            &self.maintenance_identity_sha256,
            &self.proposal_sha256,
            &self.assessment_sha256,
            &self.window_sha256,
            &self.ordered_steps,
        ))?;
        if expected != self.plan_sha256 {
            return Err(LifecycleError::InvalidMaintenance(
                "patch admission digest".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MaintenanceReleaseCertificate {
    pub certificate_id: String,
    pub policy_snapshot_sha256: String,
    pub baseline_final_assurance_sha256: String,
    pub baseline_roadmap_closure_sha256: String,
    pub proposal_sha256: String,
    pub assessment_sha256: String,
    pub window_sha256: String,
    pub admission_plan_sha256: String,
    pub regression_root_sha256: String,
    pub rollback_rehearsal_root_sha256: String,
    pub result_root_sha256: String,
    pub authority_audit_tail_hash: String,
    pub certificate_sha256: String,
}
