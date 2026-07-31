#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvolutionBaseline {
    pub evolution_id: String,
    pub policy_snapshot_sha256: String,
    pub lifecycle_closure_certificate_sha256: String,
    pub tombstone_certificate_sha256: String,
    pub closed_milestones_sha256: String,
    pub baseline_sha256: String,
}

impl EvolutionBaseline {
    pub fn new(
        evolution_id: impl Into<String>,
        lifecycle: &LifecycleClosureCertificate,
    ) -> Result<Self, EvolutionError> {
        lifecycle
            .verify()
            .map_err(|error| EvolutionError::BindingDenied(error.to_string()))?;
        let evolution_id = evolution_id.into();
        validate_identifier(&evolution_id, "evolution baseline")?;
        let policy_snapshot_sha256 = lifecycle.policy_snapshot_sha256.clone();
        let lifecycle_closure_certificate_sha256 = lifecycle.certificate_sha256.clone();
        let tombstone_certificate_sha256 = lifecycle.tombstone_certificate_sha256.clone();
        let closed_milestones_sha256 = hash_serializable(&lifecycle.closed_milestones)?;
        let baseline_sha256 = hash_serializable(&(
            &evolution_id,
            &policy_snapshot_sha256,
            &lifecycle_closure_certificate_sha256,
            &tombstone_certificate_sha256,
            &closed_milestones_sha256,
        ))?;
        Ok(Self {
            evolution_id,
            policy_snapshot_sha256,
            lifecycle_closure_certificate_sha256,
            tombstone_certificate_sha256,
            closed_milestones_sha256,
            baseline_sha256,
        })
    }

    pub fn verify(&self) -> Result<(), EvolutionError> {
        validate_identifier(&self.evolution_id, "evolution baseline")?;
        for (name, value) in [
            ("evolution policy", self.policy_snapshot_sha256.as_str()),
            (
                "lifecycle closure certificate",
                self.lifecycle_closure_certificate_sha256.as_str(),
            ),
            (
                "baseline tombstone certificate",
                self.tombstone_certificate_sha256.as_str(),
            ),
            (
                "baseline milestone root",
                self.closed_milestones_sha256.as_str(),
            ),
            ("evolution baseline", self.baseline_sha256.as_str()),
        ] {
            validate_sha256(value, name)?;
        }
        let expected = hash_serializable(&(
            &self.evolution_id,
            &self.policy_snapshot_sha256,
            &self.lifecycle_closure_certificate_sha256,
            &self.tombstone_certificate_sha256,
            &self.closed_milestones_sha256,
        ))?;
        if expected != self.baseline_sha256 {
            return Err(EvolutionError::InvalidEvolution(
                "baseline digest mismatch".into(),
            ));
        }
        Ok(())
    }
}

#[derive(
    Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord,
)]
#[serde(rename_all = "snake_case")]
pub enum EvolutionClass {
    SchemaOnly,
    MetadataOnly,
    CompatibilityRepair,
    InvariantTightening,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvolutionProposal {
    pub proposal_id: String,
    pub baseline_sha256: String,
    pub policy_snapshot_sha256: String,
    pub class: EvolutionClass,
    pub component_deltas: BTreeMap<String, String>,
    pub invariant_deltas: BTreeMap<String, String>,
    pub created_tick: u64,
    pub expires_tick: u64,
    pub proposal_sha256: String,
}

