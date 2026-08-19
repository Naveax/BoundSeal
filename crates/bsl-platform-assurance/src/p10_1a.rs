use bsl_adapter_boundary::AdapterConformanceCertificate;
use bsl_release_governance::PlatformReleaseCertificate;
use bsl_replay_lab::ReproducibilityCertificate;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlatformIntegrationIdentity {
    pub integration_id: String,
    pub run_id: String,
    pub worker_id: String,
    pub policy_snapshot_sha256: String,
    pub identity_sha256: String,
}

impl PlatformIntegrationIdentity {
    pub fn new(
        integration_id: impl Into<String>,
        run_id: impl Into<String>,
        worker_id: impl Into<String>,
        policy_snapshot_sha256: impl Into<String>,
    ) -> Result<Self, AssuranceError> {
        let integration_id = integration_id.into();
        let run_id = run_id.into();
        let worker_id = worker_id.into();
        let policy_snapshot_sha256 = policy_snapshot_sha256.into();
        validate_identifier(&integration_id, "integration id")?;
        validate_identifier(&run_id, "integration run")?;
        validate_identifier(&worker_id, "integration worker")?;
        validate_sha256(&policy_snapshot_sha256, "integration policy")?;
        let identity_sha256 = hash_serializable(&(
            &integration_id,
            &run_id,
            &worker_id,
            &policy_snapshot_sha256,
        ))?;
        Ok(Self {
            integration_id,
            run_id,
            worker_id,
            policy_snapshot_sha256,
            identity_sha256,
        })
    }

    pub fn verify(&self) -> Result<(), AssuranceError> {
        let expected = hash_serializable(&(
            &self.integration_id,
            &self.run_id,
            &self.worker_id,
            &self.policy_snapshot_sha256,
        ))?;
        if expected != self.identity_sha256 {
            return Err(AssuranceError::InvalidBinding(
                "integration identity digest".into(),
            ));
        }
        Ok(())
    }
}
