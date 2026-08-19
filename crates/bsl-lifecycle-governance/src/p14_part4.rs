impl RedactionManifest {
    pub fn new(
        manifest_id: impl Into<String>,
        archive: &ArchiveBundle,
        object_dispositions: BTreeMap<String, RedactionDisposition>,
    ) -> Result<Self, LifecycleError> {
        archive.verify()?;
        let manifest_id = manifest_id.into();
        validate_identifier(&manifest_id, "redaction manifest")?;
        let disposition_ids = object_dispositions.keys().cloned().collect::<BTreeSet<_>>();
        if disposition_ids != archive.object_ids {
            return Err(LifecycleError::InvalidContinuity(
                "redaction manifest must cover every archive object exactly".into(),
            ));
        }
        let archive_bundle_sha256 = archive.bundle_sha256.clone();
        let manifest_sha256 =
            hash_serializable(&(&manifest_id, &archive_bundle_sha256, &object_dispositions))?;
        Ok(Self {
            manifest_id,
            archive_bundle_sha256,
            object_dispositions,
            manifest_sha256,
        })
    }

    pub fn verify(&self) -> Result<(), LifecycleError> {
        validate_identifier(&self.manifest_id, "redaction manifest")?;
        validate_sha256(&self.archive_bundle_sha256, "redaction archive root")?;
        validate_sha256(&self.manifest_sha256, "redaction manifest digest")?;
        if self.object_dispositions.is_empty()
            || self.object_dispositions.len() > MAX_ARCHIVE_OBJECTS
            || self
                .object_dispositions
                .keys()
                .any(|object_id| validate_identifier(object_id, "redaction object").is_err())
        {
            return Err(LifecycleError::InvalidContinuity(
                "redaction manifest object set".into(),
            ));
        }
        let expected = hash_serializable(&(
            &self.manifest_id,
            &self.archive_bundle_sha256,
            &self.object_dispositions,
        ))?;
        if expected != self.manifest_sha256 {
            return Err(LifecycleError::InvalidContinuity(
                "redaction manifest digest".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryStep {
    ValidateArchive,
    RestoreMetadata,
    VerifyIntegrity,
    ReissueCertificates,
    ValidateContinuity,
    SealRecovery,
}

fn canonical_recovery_steps() -> Vec<RecoveryStep> {
    vec![
        RecoveryStep::ValidateArchive,
        RecoveryStep::RestoreMetadata,
        RecoveryStep::VerifyIntegrity,
        RecoveryStep::ReissueCertificates,
        RecoveryStep::ValidateContinuity,
        RecoveryStep::SealRecovery,
    ]
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecoveryPlan {
    pub plan_id: String,
    pub archive_bundle_sha256: String,
    pub retention_policy_sha256: String,
    pub redaction_manifest_sha256: String,
    pub ordered_steps: Vec<RecoveryStep>,
    pub maximum_virtual_ticks: u64,
    pub plan_sha256: String,
}
