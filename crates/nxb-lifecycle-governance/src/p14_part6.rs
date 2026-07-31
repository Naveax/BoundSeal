impl RecoveryRehearsalReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        receipt_id: impl Into<String>,
        engine_id: impl Into<String>,
        organization_root_sha256: impl Into<String>,
        implementation_root_sha256: impl Into<String>,
        plan: &RecoveryPlan,
        result_root_sha256: impl Into<String>,
        final_virtual_tick: u64,
        exact: bool,
    ) -> Result<Self, LifecycleError> {
        plan.verify()?;
        let receipt_id = receipt_id.into();
        let engine_id = engine_id.into();
        let organization_root_sha256 = organization_root_sha256.into();
        let implementation_root_sha256 = implementation_root_sha256.into();
        let result_root_sha256 = result_root_sha256.into();
        validate_identifier(&receipt_id, "recovery receipt")?;
        validate_identifier(&engine_id, "recovery engine")?;
        for (name, value) in [
            ("recovery organization", organization_root_sha256.as_str()),
            (
                "recovery implementation",
                implementation_root_sha256.as_str(),
            ),
            ("recovery result", result_root_sha256.as_str()),
        ] {
            validate_sha256(value, name)?;
        }
        if !exact || final_virtual_tick > plan.maximum_virtual_ticks {
            return Err(LifecycleError::InvalidContinuity(
                "recovery rehearsal exactness or time budget".into(),
            ));
        }
        let recovery_plan_sha256 = plan.plan_sha256.clone();
        let archive_bundle_sha256 = plan.archive_bundle_sha256.clone();
        let receipt_sha256 = hash_serializable(&(
            &receipt_id,
            &engine_id,
            &organization_root_sha256,
            &implementation_root_sha256,
            &recovery_plan_sha256,
            &archive_bundle_sha256,
            &result_root_sha256,
            final_virtual_tick,
            exact,
        ))?;
        Ok(Self {
            receipt_id,
            engine_id,
            organization_root_sha256,
            implementation_root_sha256,
            recovery_plan_sha256,
            archive_bundle_sha256,
            result_root_sha256,
            final_virtual_tick,
            exact,
            receipt_sha256,
        })
    }

    pub fn verify(&self) -> Result<(), LifecycleError> {
        validate_identifier(&self.receipt_id, "recovery receipt")?;
        validate_identifier(&self.engine_id, "recovery engine")?;
        for (name, value) in [
            (
                "recovery organization",
                self.organization_root_sha256.as_str(),
            ),
            (
                "recovery implementation",
                self.implementation_root_sha256.as_str(),
            ),
            ("recovery plan", self.recovery_plan_sha256.as_str()),
            ("recovery archive", self.archive_bundle_sha256.as_str()),
            ("recovery result", self.result_root_sha256.as_str()),
            ("recovery receipt", self.receipt_sha256.as_str()),
        ] {
            validate_sha256(value, name)?;
        }
        if !self.exact {
            return Err(LifecycleError::InvalidContinuity(
                "recovery receipt is not exact".into(),
            ));
        }
        let expected = hash_serializable(&(
            &self.receipt_id,
            &self.engine_id,
            &self.organization_root_sha256,
            &self.implementation_root_sha256,
            &self.recovery_plan_sha256,
            &self.archive_bundle_sha256,
            &self.result_root_sha256,
            self.final_virtual_tick,
            self.exact,
        ))?;
        if expected != self.receipt_sha256 {
            return Err(LifecycleError::InvalidContinuity(
                "recovery receipt digest".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecoveryQuorum {
    pub recovery_plan_sha256: String,
    pub archive_bundle_sha256: String,
    pub result_root_sha256: String,
    pub engine_ids: BTreeSet<String>,
    pub organization_roots: BTreeSet<String>,
    pub implementation_roots: BTreeSet<String>,
    pub receipt_sha256: BTreeSet<String>,
    pub quorum: usize,
    pub quorum_sha256: String,
}
