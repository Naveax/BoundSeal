impl MaintenanceReleaseCertificate {
    pub fn verify(&self) -> Result<(), LifecycleError> {
        for (name, value) in [
            ("maintenance policy", self.policy_snapshot_sha256.as_str()),
            (
                "maintenance baseline final",
                self.baseline_final_assurance_sha256.as_str(),
            ),
            (
                "maintenance baseline roadmap",
                self.baseline_roadmap_closure_sha256.as_str(),
            ),
            ("maintenance proposal", self.proposal_sha256.as_str()),
            ("maintenance assessment", self.assessment_sha256.as_str()),
            ("maintenance window", self.window_sha256.as_str()),
            ("maintenance plan", self.admission_plan_sha256.as_str()),
            ("regression root", self.regression_root_sha256.as_str()),
            (
                "rollback rehearsal root",
                self.rollback_rehearsal_root_sha256.as_str(),
            ),
            ("maintenance result", self.result_root_sha256.as_str()),
            (
                "maintenance authority audit",
                self.authority_audit_tail_hash.as_str(),
            ),
            ("maintenance certificate", self.certificate_sha256.as_str()),
        ] {
            validate_sha256(value, name)?;
        }
        validate_identifier(&self.certificate_id, "maintenance certificate")?;
        let expected = hash_serializable(&(
            &self.certificate_id,
            &self.policy_snapshot_sha256,
            &self.baseline_final_assurance_sha256,
            &self.baseline_roadmap_closure_sha256,
            &self.proposal_sha256,
            &self.assessment_sha256,
            &self.window_sha256,
            &self.admission_plan_sha256,
            &self.regression_root_sha256,
            &self.rollback_rehearsal_root_sha256,
            &self.result_root_sha256,
            &self.authority_audit_tail_hash,
        ))?;
        if expected != self.certificate_sha256 {
            return Err(LifecycleError::InvalidMaintenance(
                "maintenance release certificate digest".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct MaintenanceReleaseAuthority {
    authority_id: String,
    policy_snapshot_sha256: String,
    audit: LifecycleAuditChain,
}
