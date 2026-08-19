#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SuccessorIdentity {
    pub successor_id: String,
    pub lineage_id: String,
    pub policy_snapshot_sha256: String,
    pub baseline_lifecycle_closure_sha256: String,
    pub identity_sha256: String,
}

impl SuccessorIdentity {
    pub fn new(
        successor_id: impl Into<String>,
        lineage_id: impl Into<String>,
        lifecycle: &LifecycleClosureCertificate,
    ) -> Result<Self, PostClosureError> {
        lifecycle
            .verify()
            .map_err(|error| PostClosureError::InvalidSuccession(error.to_string()))?;
        let successor_id = successor_id.into();
        let lineage_id = lineage_id.into();
        validate_identifier(&successor_id, "successor id")?;
        validate_identifier(&lineage_id, "lineage id")?;
        let policy_snapshot_sha256 = lifecycle.policy_snapshot_sha256.clone();
        let baseline_lifecycle_closure_sha256 = lifecycle.certificate_sha256.clone();
        let identity_sha256 = hash_serializable(&(
            &successor_id,
            &lineage_id,
            &policy_snapshot_sha256,
            &baseline_lifecycle_closure_sha256,
        ))?;
        Ok(Self {
            successor_id,
            lineage_id,
            policy_snapshot_sha256,
            baseline_lifecycle_closure_sha256,
            identity_sha256,
        })
    }

    pub fn verify(&self) -> Result<(), PostClosureError> {
        validate_identifier(&self.successor_id, "successor id")?;
        validate_identifier(&self.lineage_id, "lineage id")?;
        validate_sha256(&self.policy_snapshot_sha256, "successor policy")?;
        validate_sha256(
            &self.baseline_lifecycle_closure_sha256,
            "successor lifecycle closure",
        )?;
        let expected = hash_serializable(&(
            &self.successor_id,
            &self.lineage_id,
            &self.policy_snapshot_sha256,
            &self.baseline_lifecycle_closure_sha256,
        ))?;
        if expected != self.identity_sha256 {
            return Err(PostClosureError::InvalidSuccession(
                "successor identity digest".into(),
            ));
        }
        Ok(())
    }
}
