impl RecoveryQuorum {
    pub fn new(
        receipts: &[RecoveryRehearsalReceipt],
        required_quorum: usize,
    ) -> Result<Self, LifecycleError> {
        if required_quorum < 2 || receipts.len() < required_quorum || receipts.len() > 16 {
            return Err(LifecycleError::InvalidContinuity(
                "recovery quorum count".into(),
            ));
        }
        for receipt in receipts {
            receipt.verify()?;
        }
        let first = receipts
            .first()
            .ok_or_else(|| LifecycleError::InvalidContinuity("missing recovery receipt".into()))?;
        let engine_ids = receipts
            .iter()
            .map(|receipt| receipt.engine_id.clone())
            .collect::<BTreeSet<_>>();
        let organization_roots = receipts
            .iter()
            .map(|receipt| receipt.organization_root_sha256.clone())
            .collect::<BTreeSet<_>>();
        let implementation_roots = receipts
            .iter()
            .map(|receipt| receipt.implementation_root_sha256.clone())
            .collect::<BTreeSet<_>>();
        let receipt_sha256 = receipts
            .iter()
            .map(|receipt| receipt.receipt_sha256.clone())
            .collect::<BTreeSet<_>>();
        if engine_ids.len() != receipts.len()
            || organization_roots.len() != receipts.len()
            || implementation_roots.len() != receipts.len()
            || receipt_sha256.len() != receipts.len()
            || receipts.iter().any(|receipt| {
                receipt.recovery_plan_sha256 != first.recovery_plan_sha256
                    || receipt.archive_bundle_sha256 != first.archive_bundle_sha256
                    || receipt.result_root_sha256 != first.result_root_sha256
                    || !receipt.exact
            })
        {
            return Err(LifecycleError::InvalidContinuity(
                "recovery quorum diversity or result mismatch".into(),
            ));
        }
        let quorum_sha256 = hash_serializable(&(
            &first.recovery_plan_sha256,
            &first.archive_bundle_sha256,
            &first.result_root_sha256,
            &engine_ids,
            &organization_roots,
            &implementation_roots,
            &receipt_sha256,
            required_quorum,
        ))?;
        Ok(Self {
            recovery_plan_sha256: first.recovery_plan_sha256.clone(),
            archive_bundle_sha256: first.archive_bundle_sha256.clone(),
            result_root_sha256: first.result_root_sha256.clone(),
            engine_ids,
            organization_roots,
            implementation_roots,
            receipt_sha256,
            quorum: required_quorum,
            quorum_sha256,
        })
    }

    pub fn verify(&self) -> Result<(), LifecycleError> {
        for (name, value) in [
            ("recovery quorum plan", self.recovery_plan_sha256.as_str()),
            (
                "recovery quorum archive",
                self.archive_bundle_sha256.as_str(),
            ),
            ("recovery quorum result", self.result_root_sha256.as_str()),
            ("recovery quorum", self.quorum_sha256.as_str()),
        ] {
            validate_sha256(value, name)?;
        }
        if self.quorum < 2
            || self.engine_ids.len() < self.quorum
            || self.organization_roots.len() < self.quorum
            || self.implementation_roots.len() < self.quorum
            || self.receipt_sha256.len() < self.quorum
        {
            return Err(LifecycleError::InvalidContinuity(
                "recovery quorum diversity".into(),
            ));
        }
        let expected = hash_serializable(&(
            &self.recovery_plan_sha256,
            &self.archive_bundle_sha256,
            &self.result_root_sha256,
            &self.engine_ids,
            &self.organization_roots,
            &self.implementation_roots,
            &self.receipt_sha256,
            self.quorum,
        ))?;
        if expected != self.quorum_sha256 {
            return Err(LifecycleError::InvalidContinuity(
                "recovery quorum digest".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContinuityCertificate {
    pub certificate_id: String,
    pub policy_snapshot_sha256: String,
    pub maintenance_release_certificate_sha256: String,
    pub archive_bundle_sha256: String,
    pub retention_policy_sha256: String,
    pub redaction_manifest_sha256: String,
    pub recovery_plan_sha256: String,
    pub recovery_quorum_sha256: String,
    pub recovery_result_root_sha256: String,
    pub authority_audit_tail_hash: String,
    pub certificate_sha256: String,
}
