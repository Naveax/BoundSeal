#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IntegrationRunState {
    Created,
    Running,
    Completed,
    Failed,
    EmergencyStopped,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntegrationStepReceipt {
    pub sequence: u64,
    pub step: IntegrationStep,
    pub evidence_sha256: String,
    pub receipt_sha256: String,
}
impl IntegrationStepReceipt {
    pub fn verify(&self) -> Result<(), AssuranceError> {
        validate_sha256(&self.evidence_sha256, "integration evidence")?;
        let expected = hash_serializable(&(self.sequence, self.step, &self.evidence_sha256))?;
        if expected != self.receipt_sha256 {
            return Err(AssuranceError::InvalidTransition(
                "integration step receipt digest".into(),
            ));
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CrossPhaseClosureMatrix {
    pub policy_closed: bool,
    pub certificates_closed: bool,
    pub fixture_closed: bool,
    pub audit_closed: bool,
    pub determinism_closed: bool,
    pub result_closed: bool,
    pub matrix_sha256: String,
}
impl CrossPhaseClosureMatrix {
    pub fn verify(&self) -> Result<(), AssuranceError> {
        let expected = hash_serializable(&(
            self.policy_closed,
            self.certificates_closed,
            self.fixture_closed,
            self.audit_closed,
            self.determinism_closed,
            self.result_closed,
        ))?;
        if expected != self.matrix_sha256
            || ![
                self.policy_closed,
                self.certificates_closed,
                self.fixture_closed,
                self.audit_closed,
                self.determinism_closed,
                self.result_closed,
            ]
            .into_iter()
            .all(|v| v)
        {
            return Err(AssuranceError::ClosureDenied(
                "cross-phase matrix is incomplete".into(),
            ));
        }
        Ok(())
    }
}
