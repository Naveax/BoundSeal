#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustEpoch {
    pub epoch_id: String,
    pub public_bundle_sha256: String,
    pub start_tick: u64,
    pub end_tick: u64,
    pub accepted_algorithms: BTreeSet<String>,
    pub private_key_count: u64,
    pub epoch_sha256: String,
}

impl TrustEpoch {
    pub fn new(
        epoch_id: impl Into<String>,
        bundle: &PublicVerificationBundle,
        start_tick: u64,
        end_tick: u64,
        accepted_algorithms: BTreeSet<String>,
        private_key_count: u64,
    ) -> Result<Self, PostClosureError> {
        bundle.verify()?;
        let epoch_id = epoch_id.into();
        validate_identifier(&epoch_id, "trust epoch")?;
        let expected_algorithms = ["sha256".to_string()].into_iter().collect::<BTreeSet<_>>();
        if end_tick <= start_tick
            || end_tick - start_tick > MAX_TRUST_EPOCH_TICKS
            || accepted_algorithms != expected_algorithms
            || private_key_count != 0
        {
            return Err(PostClosureError::InvalidProgramClosure(
                "trust epoch window, algorithm or key count".into(),
            ));
        }
        let public_bundle_sha256 = bundle.bundle_sha256.clone();
        let epoch_sha256 = hash_serializable(&(
            &epoch_id,
            &public_bundle_sha256,
            start_tick,
            end_tick,
            &accepted_algorithms,
            private_key_count,
        ))?;
        Ok(Self {
            epoch_id,
            public_bundle_sha256,
            start_tick,
            end_tick,
            accepted_algorithms,
            private_key_count,
            epoch_sha256,
        })
    }

    pub fn verify(&self) -> Result<(), PostClosureError> {
        validate_identifier(&self.epoch_id, "trust epoch")?;
        validate_sha256(&self.public_bundle_sha256, "trust epoch bundle")?;
        let expected_algorithms = ["sha256".to_string()].into_iter().collect::<BTreeSet<_>>();
        if self.end_tick <= self.start_tick
            || self.end_tick - self.start_tick > MAX_TRUST_EPOCH_TICKS
            || self.accepted_algorithms != expected_algorithms
            || self.private_key_count != 0
        {
            return Err(PostClosureError::InvalidProgramClosure(
                "trust epoch window, algorithm or key count".into(),
            ));
        }
        let expected = hash_serializable(&(
            &self.epoch_id,
            &self.public_bundle_sha256,
            self.start_tick,
            self.end_tick,
            &self.accepted_algorithms,
            self.private_key_count,
        ))?;
        if expected != self.epoch_sha256 {
            return Err(PostClosureError::InvalidProgramClosure(
                "trust epoch digest".into(),
            ));
        }
        Ok(())
    }
}
