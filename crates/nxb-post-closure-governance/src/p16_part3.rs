#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateTransferObject {
    pub object_id: String,
    pub metadata_sha256: String,
    pub redacted_bytes: u64,
}

impl StateTransferObject {
    pub fn new(
        object_id: impl Into<String>,
        metadata_sha256: impl Into<String>,
        redacted_bytes: u64,
    ) -> Result<Self, PostClosureError> {
        let object_id = object_id.into();
        let metadata_sha256 = metadata_sha256.into();
        validate_identifier(&object_id, "transfer object")?;
        validate_sha256(&metadata_sha256, "transfer object metadata")?;
        if redacted_bytes == 0 || redacted_bytes > MAX_TRANSFER_TOTAL_BYTES {
            return Err(PostClosureError::InvalidSuccession(
                "transfer object byte count".into(),
            ));
        }
        Ok(Self {
            object_id,
            metadata_sha256,
            redacted_bytes,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateTransferManifest {
    pub manifest_id: String,
    pub compatibility_envelope_sha256: String,
    pub objects: BTreeMap<String, StateTransferObject>,
    pub redaction_manifest_sha256: String,
    pub total_redacted_bytes: u64,
    pub manifest_sha256: String,
}

impl StateTransferManifest {
    pub fn new(
        manifest_id: impl Into<String>,
        envelope: &CompatibilityEnvelope,
        objects: Vec<StateTransferObject>,
        redaction_manifest_sha256: impl Into<String>,
    ) -> Result<Self, PostClosureError> {
        envelope.verify()?;
        let manifest_id = manifest_id.into();
        let redaction_manifest_sha256 = redaction_manifest_sha256.into();
        validate_identifier(&manifest_id, "transfer manifest")?;
        validate_sha256(&redaction_manifest_sha256, "redaction manifest")?;
        if objects.is_empty() || objects.len() > MAX_TRANSFER_OBJECTS {
            return Err(PostClosureError::InvalidSuccession(
                "transfer object count".into(),
            ));
        }
        let mut by_id = BTreeMap::new();
        let mut total_redacted_bytes = 0_u64;
        for object in objects {
            validate_identifier(&object.object_id, "transfer object")?;
            validate_sha256(&object.metadata_sha256, "transfer object metadata")?;
            total_redacted_bytes = total_redacted_bytes
                .checked_add(object.redacted_bytes)
                .ok_or_else(|| {
                    PostClosureError::InvalidSuccession("transfer byte overflow".into())
                })?;
            if by_id.insert(object.object_id.clone(), object).is_some() {
                return Err(PostClosureError::InvalidSuccession(
                    "duplicate transfer object".into(),
                ));
            }
        }
        if total_redacted_bytes == 0 || total_redacted_bytes > MAX_TRANSFER_TOTAL_BYTES {
            return Err(PostClosureError::InvalidSuccession(
                "transfer total byte count".into(),
            ));
        }
        let compatibility_envelope_sha256 = envelope.envelope_sha256.clone();
        let manifest_sha256 = hash_serializable(&(
            &manifest_id,
            &compatibility_envelope_sha256,
            &by_id,
            &redaction_manifest_sha256,
            total_redacted_bytes,
        ))?;
        Ok(Self {
            manifest_id,
            compatibility_envelope_sha256,
            objects: by_id,
            redaction_manifest_sha256,
            total_redacted_bytes,
            manifest_sha256,
        })
    }

    pub fn verify(&self) -> Result<(), PostClosureError> {
        validate_identifier(&self.manifest_id, "transfer manifest")?;
        validate_sha256(
            &self.compatibility_envelope_sha256,
            "transfer compatibility envelope",
        )?;
        validate_sha256(&self.redaction_manifest_sha256, "redaction manifest")?;
        if self.objects.is_empty() || self.objects.len() > MAX_TRANSFER_OBJECTS {
            return Err(PostClosureError::InvalidSuccession(
                "transfer object count".into(),
            ));
        }
        let total = self.objects.values().try_fold(0_u64, |acc, object| {
            validate_identifier(&object.object_id, "transfer object")?;
            validate_sha256(&object.metadata_sha256, "transfer object metadata")?;
            acc.checked_add(object.redacted_bytes)
                .ok_or_else(|| PostClosureError::InvalidSuccession("transfer byte overflow".into()))
        })?;
        if total != self.total_redacted_bytes
            || total == 0
            || total > MAX_TRANSFER_TOTAL_BYTES
            || self
                .objects
                .iter()
                .any(|(key, object)| key != &object.object_id)
        {
            return Err(PostClosureError::InvalidSuccession(
                "transfer manifest accounting".into(),
            ));
        }
        let expected = hash_serializable(&(
            &self.manifest_id,
            &self.compatibility_envelope_sha256,
            &self.objects,
            &self.redaction_manifest_sha256,
            self.total_redacted_bytes,
        ))?;
        if expected != self.manifest_sha256 {
            return Err(PostClosureError::InvalidSuccession(
                "transfer manifest digest".into(),
            ));
        }
        Ok(())
    }
}
