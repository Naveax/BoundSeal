impl FinalAssuranceAuthority {
    #[allow(clippy::too_many_arguments)]
    pub fn certify(
        &mut self,
        release: &PlatformReleaseCertificate,
        integration: &PlatformIntegrationCertificate,
        operator: &OperatorControlCertificate,
        matrix: &AssuranceCoverageMatrix,
        freeze: &SystemFreezeManifest,
        exception_decisions: &[ExceptionDecision],
    ) -> Result<FinalAssuranceCertificate, AssuranceError> {
        release
            .verify()
            .map_err(|e| AssuranceError::ClosureDenied(e.to_string()))?;
        integration.verify()?;
        operator.verify()?;
        matrix.verify()?;
        freeze.verify()?;
        if release.policy_snapshot_sha256 != self.policy_snapshot_sha256
            || matrix.policy_snapshot_sha256 != self.policy_snapshot_sha256
            || freeze.policy_snapshot_sha256 != self.policy_snapshot_sha256
            || freeze.platform_release_certificate_sha256 != release.certificate_sha256
            || freeze.integration_certificate_sha256 != integration.certificate_sha256
            || freeze.operator_control_certificate_sha256 != operator.certificate_sha256
            || operator.integration_certificate_sha256 != integration.certificate_sha256
            || exception_decisions.iter().any(|d| d.accepted)
        {
            return Err(AssuranceError::ClosureDenied(
                "policy, certificate, freeze or exception closure".into(),
            ));
        }
        let seed = hash_serializable(&(
            &self.authority_id,
            &self.policy_snapshot_sha256,
            &release.certificate_sha256,
            &integration.certificate_sha256,
            &operator.certificate_sha256,
            &matrix.matrix_sha256,
            &freeze.freeze_sha256,
        ))?;
        let certificate_id = format!("final-assurance-{}", &seed[..24]);
        self.audit.append(AssuranceAuditEvent {
            action: "final_assurance_certified".into(),
            subject_id: certificate_id.clone(),
            outcome: "certified".into(),
            metadata: BTreeMap::from([
                (
                    "coverage_matrix_sha256".into(),
                    matrix.matrix_sha256.clone(),
                ),
                (
                    "freeze_manifest_sha256".into(),
                    freeze.freeze_sha256.clone(),
                ),
            ]),
        })?;
        let certificate_sha256 = hash_serializable(&(
            &certificate_id,
            &self.policy_snapshot_sha256,
            &release.certificate_sha256,
            &integration.certificate_sha256,
            &operator.certificate_sha256,
            &matrix.matrix_sha256,
            &freeze.freeze_sha256,
            matrix.mandatory_count(),
            self.audit.tail_hash(),
        ))?;
        let c = FinalAssuranceCertificate {
            certificate_id,
            policy_snapshot_sha256: self.policy_snapshot_sha256.clone(),
            platform_release_certificate_sha256: release.certificate_sha256.clone(),
            integration_certificate_sha256: integration.certificate_sha256.clone(),
            operator_control_certificate_sha256: operator.certificate_sha256.clone(),
            coverage_matrix_sha256: matrix.matrix_sha256.clone(),
            freeze_manifest_sha256: freeze.freeze_sha256.clone(),
            mandatory_requirement_count: matrix.mandatory_count(),
            authority_audit_tail_hash: self.audit.tail_hash().into(),
            certificate_sha256,
        };
        c.verify()?;
        Ok(c)
    }
}
