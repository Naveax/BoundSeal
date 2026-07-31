#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MigrationCapsule {
    pub proposal_sha256: String,
    pub from_generation: u32,
    pub to_generation: u32,
    pub forward_steps: BTreeMap<String, String>,
    pub rollback_steps: BTreeMap<String, String>,
    pub pre_state_root_sha256: String,
    pub post_state_root_sha256: String,
    pub restored_state_root_sha256: String,
    pub capsule_sha256: String,
}

impl MigrationCapsule {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        proposal: &EvolutionProposal,
        from_generation: u32,
        to_generation: u32,
        forward_steps: BTreeMap<String, String>,
        rollback_steps: BTreeMap<String, String>,
        pre_state_root_sha256: impl Into<String>,
        post_state_root_sha256: impl Into<String>,
        restored_state_root_sha256: impl Into<String>,
    ) -> Result<Self, EvolutionError> {
        if to_generation != from_generation.saturating_add(1) {
            return Err(EvolutionError::InvalidEvolution(
                "migration generations are not adjacent".into(),
            ));
        }
        validate_hash_map(&forward_steps, "forward migration step", MAX_STEPS)?;
        validate_hash_map(&rollback_steps, "rollback migration step", MAX_STEPS)?;
        if forward_steps.keys().collect::<BTreeSet<_>>()
            != rollback_steps.keys().collect::<BTreeSet<_>>()
        {
            return Err(EvolutionError::InvalidEvolution(
                "forward and rollback step sets differ".into(),
            ));
        }
        let pre_state_root_sha256 = pre_state_root_sha256.into();
        let post_state_root_sha256 = post_state_root_sha256.into();
        let restored_state_root_sha256 = restored_state_root_sha256.into();
        for (name, value) in [
            ("migration pre-state", pre_state_root_sha256.as_str()),
            ("migration post-state", post_state_root_sha256.as_str()),
            (
                "migration restored state",
                restored_state_root_sha256.as_str(),
            ),
        ] {
            validate_sha256(value, name)?;
        }
        if restored_state_root_sha256 != pre_state_root_sha256
            || post_state_root_sha256 == pre_state_root_sha256
        {
            return Err(EvolutionError::InvalidEvolution(
                "migration is not exactly reversible".into(),
            ));
        }
        let proposal_sha256 = proposal.proposal_sha256.clone();
        let capsule_sha256 = hash_serializable(&(
            &proposal_sha256,
            from_generation,
            to_generation,
            &forward_steps,
            &rollback_steps,
            &pre_state_root_sha256,
            &post_state_root_sha256,
            &restored_state_root_sha256,
        ))?;
        Ok(Self {
            proposal_sha256,
            from_generation,
            to_generation,
            forward_steps,
            rollback_steps,
            pre_state_root_sha256,
            post_state_root_sha256,
            restored_state_root_sha256,
            capsule_sha256,
        })
    }

    pub fn verify(&self, proposal: &EvolutionProposal) -> Result<(), EvolutionError> {
        let expected = hash_serializable(&(
            &self.proposal_sha256,
            self.from_generation,
            self.to_generation,
            &self.forward_steps,
            &self.rollback_steps,
            &self.pre_state_root_sha256,
            &self.post_state_root_sha256,
            &self.restored_state_root_sha256,
        ))?;
        if self.proposal_sha256 != proposal.proposal_sha256
            || self.to_generation != self.from_generation.saturating_add(1)
            || self.forward_steps.keys().collect::<BTreeSet<_>>()
                != self.rollback_steps.keys().collect::<BTreeSet<_>>()
            || self.restored_state_root_sha256 != self.pre_state_root_sha256
            || expected != self.capsule_sha256
        {
            return Err(EvolutionError::InvalidEvolution(
                "migration capsule closure".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CanarySample {
    pub fixture_id: String,
    pub input_sha256: String,
    pub baseline_output_sha256: String,
    pub candidate_output_sha256: String,
    pub deterministic: bool,
    pub sample_sha256: String,
}

impl CanarySample {
    pub fn new(
        fixture_id: impl Into<String>,
        input_sha256: impl Into<String>,
        baseline_output_sha256: impl Into<String>,
        candidate_output_sha256: impl Into<String>,
        deterministic: bool,
    ) -> Result<Self, EvolutionError> {
        let fixture_id = fixture_id.into();
        let input_sha256 = input_sha256.into();
        let baseline_output_sha256 = baseline_output_sha256.into();
        let candidate_output_sha256 = candidate_output_sha256.into();
        validate_identifier(&fixture_id, "canary fixture")?;
        validate_sha256(&input_sha256, "canary input")?;
        validate_sha256(&baseline_output_sha256, "canary baseline output")?;
        validate_sha256(&candidate_output_sha256, "canary candidate output")?;
        if !deterministic {
            return Err(EvolutionError::InvalidEvolution(
                "canary sample is non-deterministic".into(),
            ));
        }
        let sample_sha256 = hash_serializable(&(
            &fixture_id,
            &input_sha256,
            &baseline_output_sha256,
            &candidate_output_sha256,
            deterministic,
        ))?;
        Ok(Self {
            fixture_id,
            input_sha256,
            baseline_output_sha256,
            candidate_output_sha256,
            deterministic,
            sample_sha256,
        })
    }

