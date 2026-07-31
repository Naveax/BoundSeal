impl CanarySample {
    pub fn verify(&self) -> Result<(), EvolutionError> {
        let expected = hash_serializable(&(
            &self.fixture_id,
            &self.input_sha256,
            &self.baseline_output_sha256,
            &self.candidate_output_sha256,
            self.deterministic,
        ))?;
        if !self.deterministic || expected != self.sample_sha256 {
            return Err(EvolutionError::InvalidEvolution(
                "canary sample is not deterministic".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CanaryMatrix {
    pub proposal_sha256: String,
    pub capsule_sha256: String,
    pub samples: BTreeMap<String, CanarySample>,
    pub required_fixture_ids: BTreeSet<String>,
    pub matrix_sha256: String,
}

impl CanaryMatrix {
    pub fn new(
        proposal: &EvolutionProposal,
        capsule: &MigrationCapsule,
        samples: Vec<CanarySample>,
        required_fixture_ids: BTreeSet<String>,
    ) -> Result<Self, EvolutionError> {
        if samples.is_empty()
            || samples.len() > MAX_CANARY_SAMPLES
            || required_fixture_ids.is_empty()
            || required_fixture_ids.len() > MAX_CANARY_SAMPLES
        {
            return Err(EvolutionError::InvalidEvolution(
                "canary sample count".into(),
            ));
        }
        let mut sample_map = BTreeMap::new();
        for sample in samples {
            sample.verify()?;
            if sample_map.insert(sample.fixture_id.clone(), sample).is_some() {
                return Err(EvolutionError::InvalidEvolution(
                    "duplicate canary fixture".into(),
                ));
            }
        }
        if sample_map.keys().cloned().collect::<BTreeSet<_>>() != required_fixture_ids {
            return Err(EvolutionError::InvalidEvolution(
                "canary fixture coverage mismatch".into(),
            ));
        }
        let proposal_sha256 = proposal.proposal_sha256.clone();
        let capsule_sha256 = capsule.capsule_sha256.clone();
        let matrix_sha256 = hash_serializable(&(
            &proposal_sha256,
            &capsule_sha256,
            &sample_map,
            &required_fixture_ids,
        ))?;
        Ok(Self {
            proposal_sha256,
            capsule_sha256,
            samples: sample_map,
            required_fixture_ids,
            matrix_sha256,
        })
    }

    pub fn verify(
        &self,
        proposal: &EvolutionProposal,
        capsule: &MigrationCapsule,
    ) -> Result<(), EvolutionError> {
        if self.proposal_sha256 != proposal.proposal_sha256
            || self.capsule_sha256 != capsule.capsule_sha256
            || self.samples.keys().cloned().collect::<BTreeSet<_>>()
                != self.required_fixture_ids
            || self.samples.values().any(|sample| sample.verify().is_err())
        {
            return Err(EvolutionError::BindingDenied(
                "canary matrix binding".into(),
            ));
        }
        let expected = hash_serializable(&(
            &self.proposal_sha256,
            &self.capsule_sha256,
            &self.samples,
            &self.required_fixture_ids,
        ))?;
        if expected != self.matrix_sha256 {
            return Err(EvolutionError::InvalidEvolution(
                "canary matrix digest mismatch".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvolutionReleaseCertificate {
    pub certificate_id: String,
    pub policy_snapshot_sha256: String,
    pub lifecycle_closure_certificate_sha256: String,
    pub baseline_sha256: String,
    pub proposal_sha256: String,
    pub impact_graph_sha256: String,
    pub migration_capsule_sha256: String,
    pub canary_matrix_sha256: String,
    pub authority_audit_tail_hash: String,
    pub certificate_sha256: String,
}

