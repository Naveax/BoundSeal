impl ArchiveBundle {
    pub fn new(
        bundle_id: impl Into<String>,
        maintenance: &MaintenanceReleaseCertificate,
        objects: Vec<ArchiveObject>,
    ) -> Result<Self, LifecycleError> {
        maintenance.verify()?;
        let bundle_id = bundle_id.into();
        validate_identifier(&bundle_id, "archive bundle")?;
        if objects.is_empty() || objects.len() > MAX_ARCHIVE_OBJECTS {
            return Err(LifecycleError::InvalidContinuity(
                "archive object count".into(),
            ));
        }
        for object in &objects {
            object.verify()?;
        }
        let object_ids = objects
            .iter()
            .map(|object| object.object_id.clone())
            .collect::<BTreeSet<_>>();
        if object_ids.len() != objects.len() {
            return Err(LifecycleError::InvalidContinuity(
                "duplicate archive object".into(),
            ));
        }
        let total_bytes = objects
            .iter()
            .try_fold(0_u64, |total, object| total.checked_add(object.bytes))
            .ok_or_else(|| LifecycleError::InvalidContinuity("archive byte overflow".into()))?;
        if total_bytes > MAX_ARCHIVE_TOTAL_BYTES {
            return Err(LifecycleError::InvalidContinuity(
                "archive total byte budget".into(),
            ));
        }
        let policy_snapshot_sha256 = maintenance.policy_snapshot_sha256.clone();
        let maintenance_release_certificate_sha256 = maintenance.certificate_sha256.clone();
        let bundle_sha256 = hash_serializable(&(
            &bundle_id,
            &policy_snapshot_sha256,
            &maintenance_release_certificate_sha256,
            &objects,
            &object_ids,
            total_bytes,
        ))?;
        Ok(Self {
            bundle_id,
            policy_snapshot_sha256,
            maintenance_release_certificate_sha256,
            objects,
            object_ids,
            total_bytes,
            bundle_sha256,
        })
    }

    pub fn verify(&self) -> Result<(), LifecycleError> {
        validate_identifier(&self.bundle_id, "archive bundle")?;
        for (name, value) in [
            ("archive policy", self.policy_snapshot_sha256.as_str()),
            (
                "maintenance release certificate",
                self.maintenance_release_certificate_sha256.as_str(),
            ),
            ("archive bundle", self.bundle_sha256.as_str()),
        ] {
            validate_sha256(value, name)?;
        }
        if self.objects.is_empty() || self.objects.len() > MAX_ARCHIVE_OBJECTS {
            return Err(LifecycleError::InvalidContinuity(
                "archive object count".into(),
            ));
        }
        for object in &self.objects {
            object.verify()?;
        }
        let expected_ids = self
            .objects
            .iter()
            .map(|object| object.object_id.clone())
            .collect::<BTreeSet<_>>();
        let expected_bytes = self
            .objects
            .iter()
            .try_fold(0_u64, |total, object| total.checked_add(object.bytes))
            .ok_or_else(|| LifecycleError::InvalidContinuity("archive byte overflow".into()))?;
        let expected = hash_serializable(&(
            &self.bundle_id,
            &self.policy_snapshot_sha256,
            &self.maintenance_release_certificate_sha256,
            &self.objects,
            &self.object_ids,
            self.total_bytes,
        ))?;
        if expected_ids != self.object_ids
            || expected_bytes != self.total_bytes
            || self.total_bytes > MAX_ARCHIVE_TOTAL_BYTES
            || expected != self.bundle_sha256
        {
            return Err(LifecycleError::InvalidContinuity(
                "archive bundle closure".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RetentionPolicy {
    pub retention_id: String,
    pub policy_snapshot_sha256: String,
    pub minimum_days: u32,
    pub purge_after_days: u32,
    pub review_interval_days: u32,
    pub indefinite_retention_allowed: bool,
    pub policy_sha256: String,
}
