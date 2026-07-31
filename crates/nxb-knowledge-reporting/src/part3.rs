#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceInput {
    pub class: EvidenceClass,
    pub subject_id: String,
    pub summary: String,
    pub metadata: BTreeMap<String, String>,
    pub provenance_sha256: String,
    pub policy_snapshot_sha256: String,
    pub redaction_count: u32,
    pub redaction_verified: bool,
}

impl EvidenceInput {
    pub fn validate(&self) -> Result<(), KnowledgeError> {
        validate_identifier(&self.subject_id, "evidence subject")?;
        validate_sha256(&self.provenance_sha256, "evidence provenance")?;
        validate_sha256(&self.policy_snapshot_sha256, "evidence policy snapshot")?;
        if self.summary.is_empty()
            || self.summary.len() > MAX_EVIDENCE_SUMMARY_BYTES
            || self.summary.bytes().any(|byte| byte == 0)
            || self.metadata.len() > MAX_EVIDENCE_METADATA
            || !self.redaction_verified
        {
            return Err(KnowledgeError::InvalidEvidence(
                "summary, metadata or redaction verification".into(),
            ));
        }
        for (key, value) in &self.metadata {
            if key.is_empty()
                || key.len() > 128
                || value.len() > 2048
                || key.bytes().any(|byte| byte.is_ascii_control())
                || value.bytes().any(|byte| byte == 0)
            {
                return Err(KnowledgeError::InvalidEvidence(
                    "evidence metadata bounds".into(),
                ));
            }
            let normalized_key = key.to_ascii_lowercase();
            if normalized_key.contains("authorization")
                || normalized_key.contains("cookie_value")
                || normalized_key.contains("password")
                || normalized_key.contains("secret")
                || normalized_key.contains("token_value")
            {
                return Err(KnowledgeError::InvalidEvidence(
                    "secret-bearing metadata key".into(),
                ));
            }
        }
        reject_secret_like_text(&self.summary)?;
        for value in self.metadata.values() {
            reject_secret_like_text(value)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceRecord {
    pub evidence_id: String,
    pub class: EvidenceClass,
    pub subject_id: String,
    pub summary: String,
    pub metadata: BTreeMap<String, String>,
    pub provenance_sha256: String,
    pub policy_snapshot_sha256: String,
    pub redaction_count: u32,
    pub content_sha256: String,
    pub serialized_bytes: usize,
    pub audit_tail_hash: String,
}

#[derive(Debug)]
pub struct EvidenceStore {
    policy_snapshot_sha256: String,
    records: BTreeMap<String, EvidenceRecord>,
    content_index: BTreeMap<String, String>,
    audit: KnowledgeAuditChain,
}

impl EvidenceStore {
    pub fn new(
        policy_snapshot_sha256: impl Into<String>,
        audit_genesis: impl Into<String>,
    ) -> Result<Self, KnowledgeError> {
        let policy_snapshot_sha256 = policy_snapshot_sha256.into();
        validate_sha256(&policy_snapshot_sha256, "evidence-store policy snapshot")?;
        Ok(Self {
            policy_snapshot_sha256,
            records: BTreeMap::new(),
            content_index: BTreeMap::new(),
            audit: KnowledgeAuditChain::new(audit_genesis)?,
        })
    }

    pub fn insert(&mut self, input: EvidenceInput) -> Result<&EvidenceRecord, KnowledgeError> {
        if self.records.len() >= MAX_EVIDENCE_RECORDS {
            return Err(KnowledgeError::EvidenceLimit);
        }
        input.validate()?;
        if input.policy_snapshot_sha256 != self.policy_snapshot_sha256 {
            return Err(KnowledgeError::InvalidEvidence(
                "policy snapshot drift".into(),
            ));
        }
        let serialized = serde_json::to_vec(&input)
            .map_err(|error| KnowledgeError::ReportSerialization(error.to_string()))?;
        if serialized.len() > MAX_EVIDENCE_SUMMARY_BYTES + 256 * 1024 {
            return Err(KnowledgeError::InvalidEvidence(
                "serialized evidence exceeds bound".into(),
            ));
        }
        let content_sha256 = hash_bytes(&serialized);
        if let Some(existing_id) = self.content_index.get(&content_sha256) {
            return Ok(self.records.get(existing_id).expect("evidence content index"));
        }
        let evidence_id = format!("evidence-{}", &content_sha256[..24]);
        self.audit.append(KnowledgeAuditEvent {
            action: "evidence_inserted".into(),
            subject_id: evidence_id.clone(),
            outcome: "redacted_content_addressed".into(),
            metadata: BTreeMap::from([
                ("content_sha256".into(), content_sha256.clone()),
                ("serialized_bytes".into(), serialized.len().to_string()),
                ("redaction_count".into(), input.redaction_count.to_string()),
            ]),
        })?;
        let record = EvidenceRecord {
            evidence_id: evidence_id.clone(),
            class: input.class,
            subject_id: input.subject_id,
            summary: input.summary,
            metadata: input.metadata,
            provenance_sha256: input.provenance_sha256,
            policy_snapshot_sha256: input.policy_snapshot_sha256,
            redaction_count: input.redaction_count,
            content_sha256: content_sha256.clone(),
            serialized_bytes: serialized.len(),
            audit_tail_hash: self.audit.tail_hash().into(),
        };
        self.content_index.insert(content_sha256, evidence_id.clone());
        self.records.insert(evidence_id.clone(), record);
        Ok(self.records.get(&evidence_id).expect("evidence inserted"))
    }

    pub fn get(&self, evidence_id: &str) -> Option<&EvidenceRecord> {
        self.records.get(evidence_id)
    }

    pub fn records(&self) -> &BTreeMap<String, EvidenceRecord> {
        &self.records
    }

    pub fn audit(&self) -> &KnowledgeAuditChain {
        &self.audit
    }
}

fn reject_secret_like_text(value: &str) -> Result<(), KnowledgeError> {
    let lower = value.to_ascii_lowercase();
    for forbidden in [
        "authorization: bearer ",
        "proxy-authorization:",
        "cookie:",
        "set-cookie:",
        "password=",
        "client_secret=",
        "access_token=",
        "refresh_token=",
        "api_key=",
    ] {
        if lower.contains(forbidden) {
            return Err(KnowledgeError::InvalidEvidence(
                "secret-like material was not redacted".into(),
            ));
        }
    }
    Ok(())
}
