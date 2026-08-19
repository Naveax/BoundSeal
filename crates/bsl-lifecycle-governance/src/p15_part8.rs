impl LifecycleClosureCertificate {
    pub fn verify(&self) -> Result<(), LifecycleError> {
        validate_identifier(&self.certificate_id, "lifecycle closure certificate")?;
        for (name, value) in [
            ("lifecycle policy", self.policy_snapshot_sha256.as_str()),
            (
                "lifecycle final assurance",
                self.final_assurance_certificate_sha256.as_str(),
            ),
            ("lifecycle roadmap", self.roadmap_closure_sha256.as_str()),
            (
                "lifecycle maintenance",
                self.maintenance_release_certificate_sha256.as_str(),
            ),
            (
                "lifecycle continuity",
                self.continuity_certificate_sha256.as_str(),
            ),
            (
                "lifecycle verification quorum",
                self.independent_verification_quorum_sha256.as_str(),
            ),
            (
                "lifecycle tombstone",
                self.tombstone_certificate_sha256.as_str(),
            ),
            (
                "lifecycle authority audit",
                self.authority_audit_tail_hash.as_str(),
            ),
            ("lifecycle certificate", self.certificate_sha256.as_str()),
        ] {
            validate_sha256(value, name)?;
        }
        let expected_milestones = (0_u32..=101).collect::<BTreeSet<_>>();
        let expected = hash_serializable(&(
            &self.certificate_id,
            &self.policy_snapshot_sha256,
            &self.final_assurance_certificate_sha256,
            &self.roadmap_closure_sha256,
            &self.maintenance_release_certificate_sha256,
            &self.continuity_certificate_sha256,
            &self.independent_verification_quorum_sha256,
            &self.tombstone_certificate_sha256,
            &self.closed_milestones,
            &self.authority_audit_tail_hash,
        ))?;
        if self.closed_milestones != expected_milestones || expected != self.certificate_sha256 {
            return Err(LifecycleError::InvalidClosure(
                "lifecycle closure milestone or digest".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct LifecycleClosureAuthority {
    authority_id: String,
    policy_snapshot_sha256: String,
    audit: LifecycleAuditChain,
}
