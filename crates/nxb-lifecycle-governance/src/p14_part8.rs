impl ContinuityCertificate {
    pub fn verify(&self) -> Result<(), LifecycleError> {
        validate_identifier(&self.certificate_id, "continuity certificate")?;
        for (name, value) in [
            ("continuity policy", self.policy_snapshot_sha256.as_str()),
            (
                "continuity maintenance",
                self.maintenance_release_certificate_sha256.as_str(),
            ),
            ("continuity archive", self.archive_bundle_sha256.as_str()),
            (
                "continuity retention",
                self.retention_policy_sha256.as_str(),
            ),
            (
                "continuity redaction",
                self.redaction_manifest_sha256.as_str(),
            ),
            (
                "continuity recovery plan",
                self.recovery_plan_sha256.as_str(),
            ),
            (
                "continuity recovery quorum",
                self.recovery_quorum_sha256.as_str(),
            ),
            (
                "continuity recovery result",
                self.recovery_result_root_sha256.as_str(),
            ),
            (
                "continuity authority audit",
                self.authority_audit_tail_hash.as_str(),
            ),
            ("continuity certificate", self.certificate_sha256.as_str()),
        ] {
            validate_sha256(value, name)?;
        }
        let expected = hash_serializable(&(
            &self.certificate_id,
            &self.policy_snapshot_sha256,
            &self.maintenance_release_certificate_sha256,
            &self.archive_bundle_sha256,
            &self.retention_policy_sha256,
            &self.redaction_manifest_sha256,
            &self.recovery_plan_sha256,
            &self.recovery_quorum_sha256,
            &self.recovery_result_root_sha256,
            &self.authority_audit_tail_hash,
        ))?;
        if expected != self.certificate_sha256 {
            return Err(LifecycleError::InvalidContinuity(
                "continuity certificate digest".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct ContinuityAuthority {
    authority_id: String,
    policy_snapshot_sha256: String,
    audit: LifecycleAuditChain,
}
