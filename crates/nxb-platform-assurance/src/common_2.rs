impl AssuranceAuditChain {
    pub fn new(genesis_hash: impl Into<String>) -> Result<Self, AssuranceError> {
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
        event: AssuranceAuditEvent,
    ) -> Result<&AssuranceAuditRecord, AssuranceError> {
        if self.records.len() >= MAX_AUDIT_RECORDS {
            return Err(AssuranceError::InvalidTransition(
                "audit record ceiling".into(),
            ));
        }
        let sequence = self.records.len() as u64 + 1;
        let previous_hash = self.tail_hash.clone();
        let record_hash = hash_serializable(&(sequence, &previous_hash, &event))?;
        self.records.push(AssuranceAuditRecord {
            sequence,
            previous_hash,
            event,
            record_hash: record_hash.clone(),
        });
        self.tail_hash = record_hash;
        Ok(self.records.last().expect("audit record appended"))
    }
    pub fn verify(&self) -> Result<(), AssuranceError> {
        let mut previous_hash = self.genesis_hash.clone();
        for (index, record) in self.records.iter().enumerate() {
            if record.sequence != index as u64 + 1 {
                return Err(AssuranceError::AuditSequenceMismatch(index));
            }
            if record.previous_hash != previous_hash {
                return Err(AssuranceError::AuditPreviousHashMismatch(index));
            }
            let expected =
                hash_serializable(&(record.sequence, &record.previous_hash, &record.event))?;
            if expected != record.record_hash {
                return Err(AssuranceError::AuditRecordHashMismatch(index));
            }
            previous_hash = expected;
        }
        if previous_hash != self.tail_hash {
            return Err(AssuranceError::AuditTailMismatch);
        }
        Ok(())
    }
    pub fn tail_hash(&self) -> &str {
        &self.tail_hash
    }
    pub fn records(&self) -> &[AssuranceAuditRecord] {
        &self.records
    }
    pub fn records_mut(&mut self) -> &mut [AssuranceAuditRecord] {
        &mut self.records
    }
}

pub(crate) fn validate_identifier(value: &str, name: &str) -> Result<(), AssuranceError> {
    if value.is_empty()
        || value.len() > 192
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(AssuranceError::InvalidIdentifier(name.into()));
    }
    Ok(())
}
pub(crate) fn validate_sha256(value: &str, name: &str) -> Result<(), AssuranceError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(AssuranceError::InvalidSha256(name.into()));
    }
    Ok(())
}
pub(crate) fn hash_serializable<T: Serialize>(value: &T) -> Result<String, AssuranceError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| AssuranceError::Serialization(error.to_string()))?;
    Ok(lower_hex(&Sha256::digest(bytes)))
}
