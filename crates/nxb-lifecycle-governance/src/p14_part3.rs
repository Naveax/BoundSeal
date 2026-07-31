impl RetentionPolicy {
    pub fn new(
        retention_id: impl Into<String>,
        policy_snapshot_sha256: impl Into<String>,
        minimum_days: u32,
        purge_after_days: u32,
        review_interval_days: u32,
        indefinite_retention_allowed: bool,
    ) -> Result<Self, LifecycleError> {
        let retention_id = retention_id.into();
        let policy_snapshot_sha256 = policy_snapshot_sha256.into();
        validate_identifier(&retention_id, "retention policy")?;
        validate_sha256(&policy_snapshot_sha256, "retention policy root")?;
        if minimum_days == 0
            || purge_after_days < minimum_days
            || purge_after_days > MAX_RETENTION_DAYS
            || review_interval_days == 0
            || review_interval_days > purge_after_days
            || indefinite_retention_allowed
        {
            return Err(LifecycleError::InvalidContinuity(
                "retention bounds or indefinite retention".into(),
            ));
        }
        let policy_sha256 = hash_serializable(&(
            &retention_id,
            &policy_snapshot_sha256,
            minimum_days,
            purge_after_days,
            review_interval_days,
            indefinite_retention_allowed,
        ))?;
        Ok(Self {
            retention_id,
            policy_snapshot_sha256,
            minimum_days,
            purge_after_days,
            review_interval_days,
            indefinite_retention_allowed,
            policy_sha256,
        })
    }

    pub fn verify(&self) -> Result<(), LifecycleError> {
        validate_identifier(&self.retention_id, "retention policy")?;
        validate_sha256(&self.policy_snapshot_sha256, "retention policy root")?;
        validate_sha256(&self.policy_sha256, "retention policy digest")?;
        if self.minimum_days == 0
            || self.purge_after_days < self.minimum_days
            || self.purge_after_days > MAX_RETENTION_DAYS
            || self.review_interval_days == 0
            || self.review_interval_days > self.purge_after_days
            || self.indefinite_retention_allowed
        {
            return Err(LifecycleError::InvalidContinuity(
                "retention policy bounds".into(),
            ));
        }
        let expected = hash_serializable(&(
            &self.retention_id,
            &self.policy_snapshot_sha256,
            self.minimum_days,
            self.purge_after_days,
            self.review_interval_days,
            self.indefinite_retention_allowed,
        ))?;
        if expected != self.policy_sha256 {
            return Err(LifecycleError::InvalidContinuity(
                "retention policy digest".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum RedactionDisposition {
    DigestOnly,
    MetadataOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RedactionManifest {
    pub manifest_id: String,
    pub archive_bundle_sha256: String,
    pub object_dispositions: BTreeMap<String, RedactionDisposition>,
    pub manifest_sha256: String,
}
