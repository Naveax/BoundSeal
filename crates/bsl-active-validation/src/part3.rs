#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CleanupRecipe {
    pub method: String,
    pub endpoint_sha256: String,
    pub object_reference_sha256: String,
}

impl CleanupRecipe {
    pub fn new(
        method: impl Into<String>,
        endpoint_sha256: impl Into<String>,
        object_reference_sha256: impl Into<String>,
    ) -> Result<Self, ValidationError> {
        let method = method.into().to_ascii_uppercase();
        if !matches!(method.as_str(), "DELETE" | "POST" | "PATCH") {
            return Err(ValidationError::InvalidMutation(
                "cleanup method must be explicitly bounded".into(),
            ));
        }
        let endpoint_sha256 = endpoint_sha256.into();
        let object_reference_sha256 = object_reference_sha256.into();
        validate_sha256(&endpoint_sha256, "cleanup endpoint")?;
        validate_sha256(&object_reference_sha256, "object reference")?;
        Ok(Self {
            method,
            endpoint_sha256,
            object_reference_sha256,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OwnedObjectRecord {
    pub object_id: String,
    pub run_id: String,
    pub creation_mutation_id: String,
    pub creation_receipt_sha256: String,
    pub endpoint_sha256: String,
    pub created_at_milliseconds: u64,
    pub expires_at_milliseconds: u64,
    pub cleanup: CleanupRecipe,
    pub state: OwnedObjectState,
    pub cleanup_attempts: u8,
    pub last_cleanup_evidence_sha256: Option<String>,
}

#[derive(Debug)]
pub struct OwnershipLedger {
    run_id: String,
    objects: BTreeMap<String, OwnedObjectRecord>,
    audit: ValidationAuditChain,
}

impl OwnershipLedger {
    pub fn new(
        run_id: impl Into<String>,
        audit_genesis: impl Into<String>,
    ) -> Result<Self, ValidationError> {
        let run_id = run_id.into();
        validate_identifier(&run_id, "run_id")?;
        Ok(Self {
            run_id,
            objects: BTreeMap::new(),
            audit: ValidationAuditChain::new(audit_genesis)?,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn register(
        &mut self,
        object_id: impl Into<String>,
        mutation: &MutationReceipt,
        creation_receipt_sha256: impl Into<String>,
        created_at_milliseconds: u64,
        expires_at_milliseconds: u64,
        cleanup: CleanupRecipe,
    ) -> Result<&OwnedObjectRecord, ValidationError> {
        if self.objects.len() >= MAX_OWNED_OBJECTS {
            return Err(ValidationError::OwnershipLedgerFull);
        }
        let object_id = object_id.into();
        validate_identifier(&object_id, "object_id")?;
        let creation_receipt_sha256 = creation_receipt_sha256.into();
        validate_sha256(&creation_receipt_sha256, "creation receipt")?;
        if self.objects.contains_key(&object_id)
            || created_at_milliseconds >= expires_at_milliseconds
            || cleanup.endpoint_sha256 != mutation.endpoint_sha256
        {
            return Err(ValidationError::InvalidMutation(
                "owned-object registration".into(),
            ));
        }
        let record = OwnedObjectRecord {
            object_id: object_id.clone(),
            run_id: self.run_id.clone(),
            creation_mutation_id: mutation.mutation_id.clone(),
            creation_receipt_sha256,
            endpoint_sha256: mutation.endpoint_sha256.clone(),
            created_at_milliseconds,
            expires_at_milliseconds,
            cleanup,
            state: OwnedObjectState::Registered,
            cleanup_attempts: 0,
            last_cleanup_evidence_sha256: None,
        };
        self.objects.insert(object_id.clone(), record);
        self.audit.append(ValidationAuditEvent {
            action: "owned_object_registered".into(),
            subject_id: object_id.clone(),
            outcome: "registered".into(),
            metadata: BTreeMap::from([(
                "endpoint_sha256".into(),
                mutation.endpoint_sha256.clone(),
            )]),
        })?;
        Ok(self.objects.get(&object_id).expect("registered object"))
    }

    pub fn authorize_write(
        &self,
        object_id: &str,
        now_milliseconds: u64,
    ) -> Result<&OwnedObjectRecord, ValidationError> {
        let record = self
            .objects
            .get(object_id)
            .ok_or(ValidationError::UnknownOwnedObject)?;
        if record.run_id != self.run_id
            || record.state != OwnedObjectState::Registered
            || now_milliseconds >= record.expires_at_milliseconds
        {
            return Err(ValidationError::InvalidOwnedObjectState);
        }
        Ok(record)
    }

    pub fn begin_cleanup(
        &mut self,
        object_id: &str,
    ) -> Result<CleanupRecipe, ValidationError> {
        let record = self
            .objects
            .get_mut(object_id)
            .ok_or(ValidationError::UnknownOwnedObject)?;
        if !matches!(
            record.state,
            OwnedObjectState::Registered | OwnedObjectState::CleanupFailed
        ) || record.cleanup_attempts >= 3
        {
            return Err(ValidationError::InvalidOwnedObjectState);
        }
        record.state = OwnedObjectState::CleanupPending;
        record.cleanup_attempts = record.cleanup_attempts.saturating_add(1);
        self.audit.append(ValidationAuditEvent {
            action: "cleanup_started".into(),
            subject_id: object_id.into(),
            outcome: "pending".into(),
            metadata: BTreeMap::from([(
                "attempt".into(),
                record.cleanup_attempts.to_string(),
            )]),
        })?;
        Ok(record.cleanup.clone())
    }

    pub fn complete_cleanup(
        &mut self,
        object_id: &str,
        evidence_sha256: impl Into<String>,
    ) -> Result<&OwnedObjectRecord, ValidationError> {
        let evidence_sha256 = evidence_sha256.into();
        validate_sha256(&evidence_sha256, "cleanup evidence")?;
        let record = self
            .objects
            .get_mut(object_id)
            .ok_or(ValidationError::UnknownOwnedObject)?;
        if record.state != OwnedObjectState::CleanupPending {
            return Err(ValidationError::InvalidOwnedObjectState);
        }
        record.state = OwnedObjectState::Cleaned;
        record.last_cleanup_evidence_sha256 = Some(evidence_sha256.clone());
        self.audit.append(ValidationAuditEvent {
            action: "cleanup_completed".into(),
            subject_id: object_id.into(),
            outcome: "cleaned".into(),
            metadata: BTreeMap::from([("evidence_sha256".into(), evidence_sha256)]),
        })?;
        Ok(record)
    }

    pub fn fail_cleanup(
        &mut self,
        object_id: &str,
        evidence_sha256: impl Into<String>,
    ) -> Result<&OwnedObjectRecord, ValidationError> {
        let evidence_sha256 = evidence_sha256.into();
        validate_sha256(&evidence_sha256, "cleanup failure evidence")?;
        let record = self
            .objects
            .get_mut(object_id)
            .ok_or(ValidationError::UnknownOwnedObject)?;
        if record.state != OwnedObjectState::CleanupPending {
            return Err(ValidationError::InvalidOwnedObjectState);
        }
        record.state = OwnedObjectState::CleanupFailed;
        record.last_cleanup_evidence_sha256 = Some(evidence_sha256.clone());
        self.audit.append(ValidationAuditEvent {
            action: "cleanup_failed".into(),
            subject_id: object_id.into(),
            outcome: "run_must_stop".into(),
            metadata: BTreeMap::from([("evidence_sha256".into(), evidence_sha256)]),
        })?;
        Ok(record)
    }

    pub fn unresolved_objects(&self) -> Vec<&OwnedObjectRecord> {
        self.objects
            .values()
            .filter(|record| record.state != OwnedObjectState::Cleaned)
            .collect()
    }

    pub fn objects(&self) -> &BTreeMap<String, OwnedObjectRecord> {
        &self.objects
    }

    pub fn audit(&self) -> &ValidationAuditChain {
        &self.audit
    }
}
