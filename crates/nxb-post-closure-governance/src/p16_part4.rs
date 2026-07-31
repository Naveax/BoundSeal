#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum CutoverStep {
    FreezeBaseline,
    VerifyCompatibility,
    ImportMetadata,
    ValidateSuccessor,
    RevokePredecessor,
    SealLineage,
}

pub fn canonical_cutover_steps() -> Vec<CutoverStep> {
    vec![
        CutoverStep::FreezeBaseline,
        CutoverStep::VerifyCompatibility,
        CutoverStep::ImportMetadata,
        CutoverStep::ValidateSuccessor,
        CutoverStep::RevokePredecessor,
        CutoverStep::SealLineage,
    ]
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CutoverPlan {
    pub plan_id: String,
    pub successor_identity_sha256: String,
    pub compatibility_envelope_sha256: String,
    pub transfer_manifest_sha256: String,
    pub start_tick: u64,
    pub end_tick: u64,
    pub approval_organization_roots: BTreeSet<String>,
    pub steps: Vec<CutoverStep>,
    pub rollback_root_sha256: String,
    pub plan_sha256: String,
}

impl CutoverPlan {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        plan_id: impl Into<String>,
        identity: &SuccessorIdentity,
        envelope: &CompatibilityEnvelope,
        transfer: &StateTransferManifest,
        start_tick: u64,
        end_tick: u64,
        approval_organization_roots: BTreeSet<String>,
        rollback_root_sha256: impl Into<String>,
    ) -> Result<Self, PostClosureError> {
        identity.verify()?;
        envelope.verify()?;
        transfer.verify()?;
        let plan_id = plan_id.into();
        let rollback_root_sha256 = rollback_root_sha256.into();
        validate_identifier(&plan_id, "cutover plan")?;
        validate_sha256(&rollback_root_sha256, "cutover rollback root")?;
        if envelope.successor_identity_sha256 != identity.identity_sha256
            || transfer.compatibility_envelope_sha256 != envelope.envelope_sha256
            || end_tick <= start_tick
            || end_tick - start_tick > MAX_CUTOVER_TICKS
            || approval_organization_roots.len() < 2
            || approval_organization_roots.len() > 16
        {
            return Err(PostClosureError::InvalidSuccession(
                "cutover plan binding, window or approvals".into(),
            ));
        }
        for root in &approval_organization_roots {
            validate_sha256(root, "cutover approval organization")?;
        }
        let steps = canonical_cutover_steps();
        let successor_identity_sha256 = identity.identity_sha256.clone();
        let compatibility_envelope_sha256 = envelope.envelope_sha256.clone();
        let transfer_manifest_sha256 = transfer.manifest_sha256.clone();
        let plan_sha256 = hash_serializable(&(
            &plan_id,
            &successor_identity_sha256,
            &compatibility_envelope_sha256,
            &transfer_manifest_sha256,
            start_tick,
            end_tick,
            &approval_organization_roots,
            &steps,
            &rollback_root_sha256,
        ))?;
        Ok(Self {
            plan_id,
            successor_identity_sha256,
            compatibility_envelope_sha256,
            transfer_manifest_sha256,
            start_tick,
            end_tick,
            approval_organization_roots,
            steps,
            rollback_root_sha256,
            plan_sha256,
        })
    }

    pub fn verify(&self) -> Result<(), PostClosureError> {
        validate_identifier(&self.plan_id, "cutover plan")?;
        for (name, value) in [
            ("cutover successor", self.successor_identity_sha256.as_str()),
            (
                "cutover compatibility",
                self.compatibility_envelope_sha256.as_str(),
            ),
            ("cutover transfer", self.transfer_manifest_sha256.as_str()),
            ("cutover rollback", self.rollback_root_sha256.as_str()),
        ] {
            validate_sha256(value, name)?;
        }
        if self.end_tick <= self.start_tick
            || self.end_tick - self.start_tick > MAX_CUTOVER_TICKS
            || self.approval_organization_roots.len() < 2
            || self.approval_organization_roots.len() > 16
            || self.steps != canonical_cutover_steps()
        {
            return Err(PostClosureError::InvalidSuccession(
                "cutover plan window, approval or steps".into(),
            ));
        }
        for root in &self.approval_organization_roots {
            validate_sha256(root, "cutover approval organization")?;
        }
        let expected = hash_serializable(&(
            &self.plan_id,
            &self.successor_identity_sha256,
            &self.compatibility_envelope_sha256,
            &self.transfer_manifest_sha256,
            self.start_tick,
            self.end_tick,
            &self.approval_organization_roots,
            &self.steps,
            &self.rollback_root_sha256,
        ))?;
        if expected != self.plan_sha256 {
            return Err(PostClosureError::InvalidSuccession(
                "cutover plan digest".into(),
            ));
        }
        Ok(())
    }
}
