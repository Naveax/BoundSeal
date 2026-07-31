#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OperatorControlCertificate {
    pub certificate_id: String,
    pub integration_certificate_sha256: String,
    pub final_state: OperatorControlState,
    pub command_receipt_root_sha256: String,
    pub incident_root_sha256: String,
    pub control_audit_tail_hash: String,
    pub certificate_sha256: String,
}
impl OperatorControlCertificate {
    pub fn verify(&self) -> Result<(), AssuranceError> {
        let expected = hash_serializable(&(
            &self.certificate_id,
            &self.integration_certificate_sha256,
            self.final_state,
            &self.command_receipt_root_sha256,
            &self.incident_root_sha256,
            &self.control_audit_tail_hash,
        ))?;
        if expected != self.certificate_sha256 || self.final_state != OperatorControlState::Sealed {
            return Err(AssuranceError::ClosureDenied(
                "operator control certificate".into(),
            ));
        }
        Ok(())
    }
}
#[derive(Debug)]
pub struct OperatorControlAuthority {
    authority_id: String,
    audit: AssuranceAuditChain,
}
