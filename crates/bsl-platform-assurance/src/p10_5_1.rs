#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlatformIntegrationCertificate {
    pub certificate_id: String,
    pub integration_identity_sha256: String,
    pub certificate_bundle_sha256: String,
    pub scenario_sha256: String,
    pub closure_matrix_sha256: String,
    pub integration_audit_tail_hash: String,
    pub certificate_sha256: String,
}
impl PlatformIntegrationCertificate {
    pub fn verify(&self) -> Result<(), AssuranceError> {
        for (name, value) in [
            (
                "integration identity",
                self.integration_identity_sha256.as_str(),
            ),
            (
                "certificate bundle",
                self.certificate_bundle_sha256.as_str(),
            ),
            ("integration scenario", self.scenario_sha256.as_str()),
            ("closure matrix", self.closure_matrix_sha256.as_str()),
            (
                "integration audit",
                self.integration_audit_tail_hash.as_str(),
            ),
            ("integration certificate", self.certificate_sha256.as_str()),
        ] {
            validate_sha256(value, name)?;
        }
        let expected = hash_serializable(&(
            &self.certificate_id,
            &self.integration_identity_sha256,
            &self.certificate_bundle_sha256,
            &self.scenario_sha256,
            &self.closure_matrix_sha256,
            &self.integration_audit_tail_hash,
        ))?;
        if expected != self.certificate_sha256 {
            return Err(AssuranceError::ClosureDenied(
                "integration certificate digest".into(),
            ));
        }
        Ok(())
    }
}
#[derive(Debug)]
pub struct IntegrationCertificationAuthority {
    authority_id: String,
    policy_snapshot_sha256: String,
    audit: AssuranceAuditChain,
}
