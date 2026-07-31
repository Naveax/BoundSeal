#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OperatorApproval {
    pub operator: OperatorIdentity,
    pub envelope_sha256: String,
    pub approved_at_milliseconds: u64,
    pub approval_sha256: String,
}
impl OperatorApproval {
    pub fn new(
        operator: OperatorIdentity,
        envelope: &OperatorCommandEnvelope,
        approved_at_milliseconds: u64,
    ) -> Result<Self, AssuranceError> {
        operator.verify()?;
        if approved_at_milliseconds < envelope.issued_at_milliseconds
            || approved_at_milliseconds >= envelope.expires_at_milliseconds
        {
            return Err(AssuranceError::ApprovalDenied(
                "approval outside command lifetime".into(),
            ));
        }
        let envelope_sha256 = envelope.envelope_sha256.clone();
        let approval_sha256 = hash_serializable(&(
            &operator.identity_sha256,
            &envelope_sha256,
            approved_at_milliseconds,
        ))?;
        Ok(Self {
            operator,
            envelope_sha256,
            approved_at_milliseconds,
            approval_sha256,
        })
    }
    pub fn verify(&self, envelope: &OperatorCommandEnvelope) -> Result<(), AssuranceError> {
        self.operator.verify()?;
        let expected = hash_serializable(&(
            &self.operator.identity_sha256,
            &self.envelope_sha256,
            self.approved_at_milliseconds,
        ))?;
        if self.envelope_sha256 != envelope.envelope_sha256 || expected != self.approval_sha256 {
            return Err(AssuranceError::ApprovalDenied(
                "approval envelope binding".into(),
            ));
        }
        Ok(())
    }
}
#[derive(Debug, Clone)]
pub struct ApprovalQuorum {
    approvals: BTreeMap<String, OperatorApproval>,
}
