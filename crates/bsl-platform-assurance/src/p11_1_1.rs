#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum OperatorRole {
    Observer,
    Operator,
    Supervisor,
    SafetyOfficer,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OperatorIdentity {
    pub operator_id: String,
    pub role: OperatorRole,
    pub organization_sha256: String,
    pub identity_sha256: String,
}
impl OperatorIdentity {
    pub fn new(
        operator_id: impl Into<String>,
        role: OperatorRole,
        organization_sha256: impl Into<String>,
    ) -> Result<Self, AssuranceError> {
        let operator_id = operator_id.into();
        let organization_sha256 = organization_sha256.into();
        validate_identifier(&operator_id, "operator identity")?;
        validate_sha256(&organization_sha256, "operator organization")?;
        let identity_sha256 = hash_serializable(&(&operator_id, role, &organization_sha256))?;
        Ok(Self {
            operator_id,
            role,
            organization_sha256,
            identity_sha256,
        })
    }
    pub fn verify(&self) -> Result<(), AssuranceError> {
        let expected =
            hash_serializable(&(&self.operator_id, self.role, &self.organization_sha256))?;
        if expected != self.identity_sha256 {
            return Err(AssuranceError::ApprovalDenied(
                "operator identity digest".into(),
            ));
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum OperatorCommand {
    Pause,
    Resume,
    Cancel,
    EmergencyStop,
    AcknowledgeIncident,
    SealRun,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OperatorCommandEnvelope {
    pub sequence: u64,
    pub command: OperatorCommand,
    pub integration_certificate_sha256: String,
    pub target_id: String,
    pub nonce_sha256: String,
    pub reason_sha256: String,
    pub issued_at_milliseconds: u64,
    pub expires_at_milliseconds: u64,
    pub envelope_sha256: String,
}
