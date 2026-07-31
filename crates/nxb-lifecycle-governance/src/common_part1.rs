#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum LifecycleError {
    #[error("identifier is invalid: {0}")]
    InvalidIdentifier(String),
    #[error("SHA-256 field is invalid: {0}")]
    InvalidSha256(String),
    #[error("policy or certificate binding is invalid: {0}")]
    BindingDenied(String),
    #[error("maintenance contract is invalid: {0}")]
    InvalidMaintenance(String),
    #[error("archive or recovery contract is invalid: {0}")]
    InvalidContinuity(String),
    #[error("verification or decommission contract is invalid: {0}")]
    InvalidClosure(String),
    #[error("audit serialization failed: {0}")]
    AuditSerialization(String),
    #[error("audit sequence mismatch at record {0}")]
    AuditSequenceMismatch(usize),
    #[error("audit previous hash mismatch at record {0}")]
    AuditPreviousHashMismatch(usize),
    #[error("audit record hash mismatch at record {0}")]
    AuditRecordHashMismatch(usize),
    #[error("audit tail hash mismatch")]
    AuditTailMismatch,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LifecycleAuditEvent {
    pub action: String,
    pub subject_id: String,
    pub outcome: String,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LifecycleAuditRecord {
    pub sequence: u64,
    pub previous_hash: String,
    pub event: LifecycleAuditEvent,
    pub record_hash: String,
}

#[derive(Debug, Clone)]
pub struct LifecycleAuditChain {
    genesis_hash: String,
    records: Vec<LifecycleAuditRecord>,
    tail_hash: String,
}

impl LifecycleAuditChain {
    pub fn new(genesis_hash: impl Into<String>) -> Result<Self, LifecycleError> {
        let genesis_hash = genesis_hash.into();
        validate_sha256(&genesis_hash, "audit genesis")?;
        Ok(Self {
            tail_hash: genesis_hash.clone(),
            genesis_hash,
            records: Vec::new(),
        })
    }

    pub fn append(
        &mut self,
        event: LifecycleAuditEvent,
    ) -> Result<&LifecycleAuditRecord, LifecycleError> {
        validate_identifier(&event.action, "audit action")?;
        validate_identifier(&event.subject_id, "audit subject")?;
        validate_identifier(&event.outcome, "audit outcome")?;
        for (key, value) in &event.metadata {
            validate_identifier(key, "audit metadata key")?;
            if value.len() > 512 || contains_secret_like_text(value) {
                return Err(LifecycleError::AuditSerialization(
                    "audit metadata is oversized or secret-like".into(),
                ));
            }
        }
        let sequence = self.records.len() as u64 + 1;
        let previous_hash = self.tail_hash.clone();
        let record_hash = hash_serializable(&(sequence, &previous_hash, &event))?;
        self.records.push(LifecycleAuditRecord {
            sequence,
            previous_hash,
            event,
            record_hash: record_hash.clone(),
        });
        self.tail_hash = record_hash;
        Ok(self.records.last().expect("audit append"))
    }

    pub fn tail_hash(&self) -> &str {
        &self.tail_hash
    }

    pub fn records(&self) -> &[LifecycleAuditRecord] {
        &self.records
    }

    pub fn records_mut(&mut self) -> &mut [LifecycleAuditRecord] {
        &mut self.records
    }

    pub fn verify(&self) -> Result<(), LifecycleError> {
        let mut previous_hash = self.genesis_hash.clone();
        for (index, record) in self.records.iter().enumerate() {
            if record.sequence != index as u64 + 1 {
                return Err(LifecycleError::AuditSequenceMismatch(index));
            }
            if record.previous_hash != previous_hash {
                return Err(LifecycleError::AuditPreviousHashMismatch(index));
            }
            let expected =
                hash_serializable(&(record.sequence, &record.previous_hash, &record.event))?;
            if record.record_hash != expected {
                return Err(LifecycleError::AuditRecordHashMismatch(index));
            }
            previous_hash = expected;
        }
        if previous_hash != self.tail_hash {
            return Err(LifecycleError::AuditTailMismatch);
        }
        Ok(())
    }
}

pub(crate) fn validate_identifier(value: &str, name: &str) -> Result<(), LifecycleError> {
    if value.is_empty()
        || value.len() > 192
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(LifecycleError::InvalidIdentifier(name.into()));
    }
    Ok(())
}

pub(crate) fn validate_sha256(value: &str, name: &str) -> Result<(), LifecycleError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(LifecycleError::InvalidSha256(name.into()));
    }
    Ok(())
}
