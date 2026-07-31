#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveObjectKind {
    Certificate,
    AuditTail,
    Manifest,
    ReportIndex,
    SchemaCatalog,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArchiveObject {
    pub object_id: String,
    pub kind: ArchiveObjectKind,
    pub content_sha256: String,
    pub bytes: u64,
    pub metadata_only: bool,
    pub object_sha256: String,
}

impl ArchiveObject {
    pub fn new(
        object_id: impl Into<String>,
        kind: ArchiveObjectKind,
        content_sha256: impl Into<String>,
        bytes: u64,
        metadata_only: bool,
    ) -> Result<Self, LifecycleError> {
        let object_id = object_id.into();
        let content_sha256 = content_sha256.into();
        validate_identifier(&object_id, "archive object")?;
        validate_sha256(&content_sha256, "archive object content")?;
        if bytes == 0 || bytes > MAX_ARCHIVE_OBJECT_BYTES || !metadata_only {
            return Err(LifecycleError::InvalidContinuity(
                "archive object must be bounded metadata-only content".into(),
            ));
        }
        let object_sha256 =
            hash_serializable(&(&object_id, kind, &content_sha256, bytes, metadata_only))?;
        Ok(Self {
            object_id,
            kind,
            content_sha256,
            bytes,
            metadata_only,
            object_sha256,
        })
    }

    pub fn verify(&self) -> Result<(), LifecycleError> {
        validate_identifier(&self.object_id, "archive object")?;
        validate_sha256(&self.content_sha256, "archive object content")?;
        validate_sha256(&self.object_sha256, "archive object digest")?;
        if self.bytes == 0 || self.bytes > MAX_ARCHIVE_OBJECT_BYTES || !self.metadata_only {
            return Err(LifecycleError::InvalidContinuity(
                "archive object bounds".into(),
            ));
        }
        let expected = hash_serializable(&(
            &self.object_id,
            self.kind,
            &self.content_sha256,
            self.bytes,
            self.metadata_only,
        ))?;
        if expected != self.object_sha256 {
            return Err(LifecycleError::InvalidContinuity(
                "archive object digest".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArchiveBundle {
    pub bundle_id: String,
    pub policy_snapshot_sha256: String,
    pub maintenance_release_certificate_sha256: String,
    pub objects: Vec<ArchiveObject>,
    pub object_ids: BTreeSet<String>,
    pub total_bytes: u64,
    pub bundle_sha256: String,
}
