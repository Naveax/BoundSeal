impl MaintenanceWindow {
    pub fn new(
        window_id: impl Into<String>,
        proposal: &ChangeProposal,
        start_tick: u64,
        end_tick: u64,
        maximum_operations: u64,
        approver_organization_roots: BTreeSet<String>,
    ) -> Result<Self, LifecycleError> {
        proposal.verify()?;
        let window_id = window_id.into();
        validate_identifier(&window_id, "maintenance window")?;
        let duration = end_tick
            .checked_sub(start_tick)
            .ok_or_else(|| LifecycleError::InvalidMaintenance("window ordering".into()))?;
        if duration == 0
            || duration > MAX_MAINTENANCE_DURATION_TICKS
            || maximum_operations == 0
            || maximum_operations > MAX_MAINTENANCE_OPERATIONS
            || approver_organization_roots.len() < 2
            || approver_organization_roots.len() > 16
            || approver_organization_roots
                .iter()
                .any(|root| validate_sha256(root, "approver organization").is_err())
        {
            return Err(LifecycleError::InvalidMaintenance(
                "maintenance window bounds or approvals".into(),
            ));
        }
        let proposal_sha256 = proposal.proposal_sha256.clone();
        let window_sha256 = hash_serializable(&(
            &window_id,
            &proposal_sha256,
            start_tick,
            end_tick,
            maximum_operations,
            &approver_organization_roots,
        ))?;
        Ok(Self {
            window_id,
            proposal_sha256,
            start_tick,
            end_tick,
            maximum_operations,
            approver_organization_roots,
            window_sha256,
        })
    }

    pub fn verify(&self) -> Result<(), LifecycleError> {
        validate_identifier(&self.window_id, "maintenance window")?;
        validate_sha256(&self.proposal_sha256, "maintenance proposal")?;
        validate_sha256(&self.window_sha256, "maintenance window digest")?;
        let duration = self
            .end_tick
            .checked_sub(self.start_tick)
            .ok_or_else(|| LifecycleError::InvalidMaintenance("window ordering".into()))?;
        if duration == 0
            || duration > MAX_MAINTENANCE_DURATION_TICKS
            || self.maximum_operations == 0
            || self.maximum_operations > MAX_MAINTENANCE_OPERATIONS
            || self.approver_organization_roots.len() < 2
        {
            return Err(LifecycleError::InvalidMaintenance(
                "maintenance window bounds".into(),
            ));
        }
        for root in &self.approver_organization_roots {
            validate_sha256(root, "approver organization")?;
        }
        let expected = hash_serializable(&(
            &self.window_id,
            &self.proposal_sha256,
            self.start_tick,
            self.end_tick,
            self.maximum_operations,
            &self.approver_organization_roots,
        ))?;
        if expected != self.window_sha256 {
            return Err(LifecycleError::InvalidMaintenance(
                "maintenance window digest".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum MaintenanceStep {
    ValidateBaseline,
    ApplyMetadataPatch,
    RunRegression,
    ReissueAssurance,
    ValidateRollback,
    SealMaintenance,
}

fn canonical_maintenance_steps() -> Vec<MaintenanceStep> {
    vec![
        MaintenanceStep::ValidateBaseline,
        MaintenanceStep::ApplyMetadataPatch,
        MaintenanceStep::RunRegression,
        MaintenanceStep::ReissueAssurance,
        MaintenanceStep::ValidateRollback,
        MaintenanceStep::SealMaintenance,
    ]
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PatchAdmissionPlan {
    pub plan_id: String,
    pub maintenance_identity_sha256: String,
    pub proposal_sha256: String,
    pub assessment_sha256: String,
    pub window_sha256: String,
    pub ordered_steps: Vec<MaintenanceStep>,
    pub plan_sha256: String,
}
