impl EvolutionReleaseCertificate {
    pub fn verify(&self) -> Result<(), EvolutionError> {
        for (name, value) in [
            ("evolution policy", self.policy_snapshot_sha256.as_str()),
            (
                "evolution lifecycle closure",
                self.lifecycle_closure_certificate_sha256.as_str(),
            ),
            ("evolution baseline", self.baseline_sha256.as_str()),
            ("evolution proposal", self.proposal_sha256.as_str()),
            ("evolution impact graph", self.impact_graph_sha256.as_str()),
            (
                "evolution migration capsule",
                self.migration_capsule_sha256.as_str(),
            ),
            ("evolution canary matrix", self.canary_matrix_sha256.as_str()),
            (
                "evolution authority audit",
                self.authority_audit_tail_hash.as_str(),
            ),
            ("evolution release certificate", self.certificate_sha256.as_str()),
        ] {
            validate_sha256(value, name)?;
        }
        let expected = hash_serializable(&(
            &self.certificate_id,
            &self.policy_snapshot_sha256,
            &self.lifecycle_closure_certificate_sha256,
            &self.baseline_sha256,
            &self.proposal_sha256,
            &self.impact_graph_sha256,
            &self.migration_capsule_sha256,
            &self.canary_matrix_sha256,
            &self.authority_audit_tail_hash,
        ))?;
        if expected != self.certificate_sha256 {
            return Err(EvolutionError::InvalidEvolution(
                "evolution release certificate digest".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct EvolutionReleaseAuthority {
    authority_id: String,
    policy_snapshot_sha256: String,
    audit: EvolutionAuditChain,
}

