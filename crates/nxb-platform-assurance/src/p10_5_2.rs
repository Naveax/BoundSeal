impl IntegrationCertificationAuthority {
    pub fn new(
        authority_id: impl Into<String>,
        policy_snapshot_sha256: impl Into<String>,
        audit_genesis: impl Into<String>,
    ) -> Result<Self, AssuranceError> {
        let authority_id = authority_id.into();
        let policy_snapshot_sha256 = policy_snapshot_sha256.into();
        validate_identifier(&authority_id, "integration authority")?;
        validate_sha256(&policy_snapshot_sha256, "integration authority policy")?;
        Ok(Self {
            authority_id,
            policy_snapshot_sha256,
            audit: AssuranceAuditChain::new(audit_genesis)?,
        })
    }
    pub fn certify(
        &mut self,
        harness: &IntegrationHarness,
    ) -> Result<PlatformIntegrationCertificate, AssuranceError> {
        harness.audit.verify()?;
        let matrix = harness.closure_matrix()?;
        matrix.verify()?;
        if harness.identity.policy_snapshot_sha256 != self.policy_snapshot_sha256 {
            return Err(AssuranceError::ClosureDenied(
                "integration authority policy mismatch".into(),
            ));
        }
        let seed = hash_serializable(&(
            &self.authority_id,
            &harness.identity.identity_sha256,
            &harness.bundle.bundle_sha256,
            &harness.scenario.scenario_sha256,
            &matrix.matrix_sha256,
            harness.audit.tail_hash(),
        ))?;
        let certificate_id = format!("platform-integration-{}", &seed[..24]);
        self.audit.append(AssuranceAuditEvent {
            action: "platform_integration_certified".into(),
            subject_id: certificate_id.clone(),
            outcome: "certified".into(),
            metadata: BTreeMap::from([(
                "closure_matrix_sha256".into(),
                matrix.matrix_sha256.clone(),
            )]),
        })?;
        let certificate_sha256 = hash_serializable(&(
            &certificate_id,
            &harness.identity.identity_sha256,
            &harness.bundle.bundle_sha256,
            &harness.scenario.scenario_sha256,
            &matrix.matrix_sha256,
            harness.audit.tail_hash(),
        ))?;
        let certificate = PlatformIntegrationCertificate {
            certificate_id,
            integration_identity_sha256: harness.identity.identity_sha256.clone(),
            certificate_bundle_sha256: harness.bundle.bundle_sha256.clone(),
            scenario_sha256: harness.scenario.scenario_sha256.clone(),
            closure_matrix_sha256: matrix.matrix_sha256,
            integration_audit_tail_hash: harness.audit.tail_hash().into(),
            certificate_sha256,
        };
        certificate.verify()?;
        Ok(certificate)
    }
    pub fn audit(&self) -> &AssuranceAuditChain {
        &self.audit
    }
}
