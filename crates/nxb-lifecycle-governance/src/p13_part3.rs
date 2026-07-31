impl ImpactAssessment {
    pub fn new(
        assessment_id: impl Into<String>,
        proposal: &ChangeProposal,
        affected_components: BTreeSet<String>,
        affected_invariants: BTreeSet<String>,
        level: ImpactLevel,
        safety_critical: bool,
    ) -> Result<Self, LifecycleError> {
        proposal.verify()?;
        let assessment_id = assessment_id.into();
        validate_identifier(&assessment_id, "impact assessment")?;
        if affected_components.is_empty()
            || affected_components.len() > MAX_COMPONENTS
            || affected_components
                .iter()
                .any(|component| !proposal.component_roots.contains_key(component))
            || affected_invariants.len() > MAX_INVARIANTS
            || affected_invariants
                .iter()
                .any(|invariant| validate_identifier(invariant, "affected invariant").is_err())
        {
            return Err(LifecycleError::InvalidMaintenance(
                "impact component or invariant set".into(),
            ));
        }
        if proposal.class == ChangeClass::SecurityPatch && !safety_critical {
            return Err(LifecycleError::InvalidMaintenance(
                "security patches require safety-critical review".into(),
            ));
        }
        if safety_critical && matches!(level, ImpactLevel::Low | ImpactLevel::Moderate) {
            return Err(LifecycleError::InvalidMaintenance(
                "safety-critical impact level is too low".into(),
            ));
        }
        let proposal_sha256 = proposal.proposal_sha256.clone();
        let assessment_sha256 = hash_serializable(&(
            &assessment_id,
            &proposal_sha256,
            &affected_components,
            &affected_invariants,
            level,
            safety_critical,
        ))?;
        Ok(Self {
            assessment_id,
            proposal_sha256,
            affected_components,
            affected_invariants,
            level,
            safety_critical,
            assessment_sha256,
        })
    }

    pub fn verify(&self) -> Result<(), LifecycleError> {
        validate_identifier(&self.assessment_id, "impact assessment")?;
        validate_sha256(&self.proposal_sha256, "impact proposal")?;
        validate_sha256(&self.assessment_sha256, "impact assessment digest")?;
        if self.affected_components.is_empty()
            || self.affected_components.len() > MAX_COMPONENTS
            || self.affected_invariants.len() > MAX_INVARIANTS
            || (self.safety_critical
                && matches!(self.level, ImpactLevel::Low | ImpactLevel::Moderate))
        {
            return Err(LifecycleError::InvalidMaintenance(
                "impact assessment bounds".into(),
            ));
        }
        for value in self
            .affected_components
            .iter()
            .chain(self.affected_invariants.iter())
        {
            validate_identifier(value, "impact subject")?;
        }
        let expected = hash_serializable(&(
            &self.assessment_id,
            &self.proposal_sha256,
            &self.affected_components,
            &self.affected_invariants,
            self.level,
            self.safety_critical,
        ))?;
        if expected != self.assessment_sha256 {
            return Err(LifecycleError::InvalidMaintenance(
                "impact assessment digest".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MaintenanceWindow {
    pub window_id: String,
    pub proposal_sha256: String,
    pub start_tick: u64,
    pub end_tick: u64,
    pub maximum_operations: u64,
    pub approver_organization_roots: BTreeSet<String>,
    pub window_sha256: String,
}
