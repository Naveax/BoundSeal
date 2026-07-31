impl TombstoneCertificate {
    pub fn verify(&self) -> Result<(), LifecycleError> {
        validate_identifier(&self.certificate_id, "tombstone certificate")?;
        for (name, value) in [
            ("tombstone plan", self.decommission_plan_sha256.as_str()),
            (
                "tombstone continuity",
                self.continuity_certificate_sha256.as_str(),
            ),
            ("tombstone root", self.tombstone_root_sha256.as_str()),
            (
                "tombstone authority audit",
                self.authority_audit_tail_hash.as_str(),
            ),
            ("tombstone certificate", self.certificate_sha256.as_str()),
        ] {
            validate_sha256(value, name)?;
        }
        let expected_steps = canonical_decommission_steps()
            .into_iter()
            .collect::<BTreeSet<_>>();
        let actual_steps = self.step_receipts.keys().copied().collect::<BTreeSet<_>>();
        if actual_steps != expected_steps
            || self
                .step_receipts
                .values()
                .any(|receipt| validate_sha256(receipt, "tombstone step receipt").is_err())
            || self.live_grant_count != 0
            || self.live_secret_count != 0
            || self.live_session_count != 0
        {
            return Err(LifecycleError::InvalidClosure(
                "tombstone resource or step closure".into(),
            ));
        }
        let expected = hash_serializable(&(
            &self.certificate_id,
            &self.decommission_plan_sha256,
            &self.continuity_certificate_sha256,
            &self.step_receipts,
            self.live_grant_count,
            self.live_secret_count,
            self.live_session_count,
            &self.tombstone_root_sha256,
            &self.authority_audit_tail_hash,
        ))?;
        if expected != self.certificate_sha256 {
            return Err(LifecycleError::InvalidClosure(
                "tombstone certificate digest".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct TombstoneAuthority {
    authority_id: String,
    audit: LifecycleAuditChain,
}
