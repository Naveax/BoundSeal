impl RecoveryPlan {
    pub fn new(
        plan_id: impl Into<String>,
        archive: &ArchiveBundle,
        retention: &RetentionPolicy,
        redaction: &RedactionManifest,
        ordered_steps: Vec<RecoveryStep>,
        maximum_virtual_ticks: u64,
    ) -> Result<Self, LifecycleError> {
        archive.verify()?;
        retention.verify()?;
        redaction.verify()?;
        let plan_id = plan_id.into();
        validate_identifier(&plan_id, "recovery plan")?;
        if retention.policy_snapshot_sha256 != archive.policy_snapshot_sha256
            || redaction.archive_bundle_sha256 != archive.bundle_sha256
            || ordered_steps != canonical_recovery_steps()
            || maximum_virtual_ticks == 0
            || maximum_virtual_ticks > MAX_RECOVERY_TICKS
        {
            return Err(LifecycleError::InvalidContinuity(
                "recovery plan binding, sequence or budget".into(),
            ));
        }
        let archive_bundle_sha256 = archive.bundle_sha256.clone();
        let retention_policy_sha256 = retention.policy_sha256.clone();
        let redaction_manifest_sha256 = redaction.manifest_sha256.clone();
        let plan_sha256 = hash_serializable(&(
            &plan_id,
            &archive_bundle_sha256,
            &retention_policy_sha256,
            &redaction_manifest_sha256,
            &ordered_steps,
            maximum_virtual_ticks,
        ))?;
        Ok(Self {
            plan_id,
            archive_bundle_sha256,
            retention_policy_sha256,
            redaction_manifest_sha256,
            ordered_steps,
            maximum_virtual_ticks,
            plan_sha256,
        })
    }

    pub fn canonical(
        plan_id: impl Into<String>,
        archive: &ArchiveBundle,
        retention: &RetentionPolicy,
        redaction: &RedactionManifest,
        maximum_virtual_ticks: u64,
    ) -> Result<Self, LifecycleError> {
        Self::new(
            plan_id,
            archive,
            retention,
            redaction,
            canonical_recovery_steps(),
            maximum_virtual_ticks,
        )
    }

    pub fn verify(&self) -> Result<(), LifecycleError> {
        validate_identifier(&self.plan_id, "recovery plan")?;
        for (name, value) in [
            ("recovery archive", self.archive_bundle_sha256.as_str()),
            ("recovery retention", self.retention_policy_sha256.as_str()),
            (
                "recovery redaction",
                self.redaction_manifest_sha256.as_str(),
            ),
            ("recovery plan", self.plan_sha256.as_str()),
        ] {
            validate_sha256(value, name)?;
        }
        if self.ordered_steps != canonical_recovery_steps()
            || self.maximum_virtual_ticks == 0
            || self.maximum_virtual_ticks > MAX_RECOVERY_TICKS
        {
            return Err(LifecycleError::InvalidContinuity(
                "recovery plan sequence or budget".into(),
            ));
        }
        let expected = hash_serializable(&(
            &self.plan_id,
            &self.archive_bundle_sha256,
            &self.retention_policy_sha256,
            &self.redaction_manifest_sha256,
            &self.ordered_steps,
            self.maximum_virtual_ticks,
        ))?;
        if expected != self.plan_sha256 {
            return Err(LifecycleError::InvalidContinuity(
                "recovery plan digest".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecoveryRehearsalReceipt {
    pub receipt_id: String,
    pub engine_id: String,
    pub organization_root_sha256: String,
    pub implementation_root_sha256: String,
    pub recovery_plan_sha256: String,
    pub archive_bundle_sha256: String,
    pub result_root_sha256: String,
    pub final_virtual_tick: u64,
    pub exact: bool,
    pub receipt_sha256: String,
}
