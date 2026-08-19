#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindingEnvelope {
    pub finding_id: String,
    pub source_finding_id: String,
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub origin: String,
    pub endpoint_sha256: String,
    pub evidence_sha256: String,
    pub policy_snapshot_sha256: String,
    pub validated: bool,
    pub summary: String,
    pub metadata: BTreeMap<String, String>,
}

impl FindingEnvelope {
    pub fn from_passive(
        finding: &Finding,
        policy_snapshot_sha256: impl Into<String>,
    ) -> Result<Self, KnowledgeError> {
        validate_finding_fields(
            &finding.finding_id,
            &finding.rule_id,
            &finding.origin,
            &finding.endpoint_sha256,
            &finding.evidence_sha256,
            &finding.summary,
        )?;
        let policy_snapshot_sha256 = policy_snapshot_sha256.into();
        validate_sha256(&policy_snapshot_sha256, "passive finding policy snapshot")?;
        Ok(Self {
            finding_id: finding.finding_id.clone(),
            source_finding_id: finding.finding_id.clone(),
            rule_id: finding.rule_id.clone(),
            title: finding.title.clone(),
            severity: finding.severity,
            confidence: finding.confidence,
            origin: finding.origin.clone(),
            endpoint_sha256: finding.endpoint_sha256.clone(),
            evidence_sha256: finding.evidence_sha256.clone(),
            policy_snapshot_sha256,
            validated: false,
            summary: finding.summary.clone(),
            metadata: finding.metadata.clone(),
        })
    }

    pub fn from_validated(
        finding: &ValidatedFinding,
        policy_snapshot_sha256: impl Into<String>,
        title: impl Into<String>,
        severity: Severity,
        confidence: Confidence,
        metadata: BTreeMap<String, String>,
    ) -> Result<Self, KnowledgeError> {
        if finding.state != PromotionState::Validated {
            return Err(KnowledgeError::FindingNotReportable);
        }
        validate_finding_fields(
            &finding.finding_id,
            &finding.rule_id,
            &finding.origin,
            &finding.endpoint_sha256,
            &finding.oracle_evidence_sha256,
            &finding.summary,
        )?;
        let policy_snapshot_sha256 = policy_snapshot_sha256.into();
        validate_sha256(&policy_snapshot_sha256, "validated finding policy snapshot")?;
        let title = title.into();
        if title.is_empty() || title.len() > 512 {
            return Err(KnowledgeError::InvalidEvidence(
                "finding title".into(),
            ));
        }
        validate_labels(&metadata)?;
        Ok(Self {
            finding_id: finding.finding_id.clone(),
            source_finding_id: finding.candidate_id.clone(),
            rule_id: finding.rule_id.clone(),
            title,
            severity,
            confidence,
            origin: finding.origin.clone(),
            endpoint_sha256: finding.endpoint_sha256.clone(),
            evidence_sha256: finding.oracle_evidence_sha256.clone(),
            policy_snapshot_sha256,
            validated: true,
            summary: finding.summary.clone(),
            metadata,
        })
    }

    pub fn dedup_key_sha256(&self) -> Result<String, KnowledgeError> {
        hash_serializable(&(
            &self.rule_id,
            &self.origin,
            &self.endpoint_sha256,
            &self.policy_snapshot_sha256,
        ))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindingCluster {
    pub cluster_id: String,
    pub dedup_key_sha256: String,
    pub canonical_finding_id: String,
    pub member_finding_ids: BTreeSet<String>,
    pub severity: Severity,
    pub confidence: Confidence,
    pub validated: bool,
    pub evidence_sha256: BTreeSet<String>,
}

#[derive(Debug, Default)]
pub struct FindingDeduplicator {
    clusters: BTreeMap<String, FindingCluster>,
    finding_to_cluster: BTreeMap<String, String>,
}

impl FindingDeduplicator {
    pub fn insert(
        &mut self,
        finding: &FindingEnvelope,
    ) -> Result<&FindingCluster, KnowledgeError> {
        let dedup_key_sha256 = finding.dedup_key_sha256()?;
        if let Some(cluster_id) = self.finding_to_cluster.get(&finding.finding_id) {
            return Ok(self.clusters.get(cluster_id).expect("finding cluster index"));
        }
        let cluster_id = format!("cluster-{}", &dedup_key_sha256[..24]);
        let cluster = self
            .clusters
            .entry(cluster_id.clone())
            .or_insert_with(|| FindingCluster {
                cluster_id: cluster_id.clone(),
                dedup_key_sha256: dedup_key_sha256.clone(),
                canonical_finding_id: finding.finding_id.clone(),
                member_finding_ids: BTreeSet::new(),
                severity: finding.severity,
                confidence: finding.confidence,
                validated: finding.validated,
                evidence_sha256: BTreeSet::new(),
            });
        cluster.member_finding_ids.insert(finding.finding_id.clone());
        cluster.evidence_sha256.insert(finding.evidence_sha256.clone());
        cluster.severity = cluster.severity.max(finding.severity);
        cluster.confidence = cluster.confidence.max(finding.confidence);
        cluster.validated |= finding.validated;
        if finding.finding_id < cluster.canonical_finding_id {
            cluster.canonical_finding_id = finding.finding_id.clone();
        }
        self.finding_to_cluster
            .insert(finding.finding_id.clone(), cluster_id.clone());
        Ok(self.clusters.get(&cluster_id).expect("finding cluster"))
    }

    pub fn clusters(&self) -> &BTreeMap<String, FindingCluster> {
        &self.clusters
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindingLifecycleRecord {
    pub finding: FindingEnvelope,
    pub state: FindingState,
    pub evidence_ids: BTreeSet<String>,
    pub transition_count: u32,
    pub cleanup_clear: bool,
    pub suppression_reason_sha256: Option<String>,
    pub audit_tail_hash: String,
}

#[derive(Debug)]
pub struct FindingRegistry {
    records: BTreeMap<String, FindingLifecycleRecord>,
    audit: KnowledgeAuditChain,
}

impl FindingRegistry {
    pub fn new(audit_genesis: impl Into<String>) -> Result<Self, KnowledgeError> {
        Ok(Self {
            records: BTreeMap::new(),
            audit: KnowledgeAuditChain::new(audit_genesis)?,
        })
    }

    pub fn register(
        &mut self,
        finding: FindingEnvelope,
    ) -> Result<&FindingLifecycleRecord, KnowledgeError> {
        if self.records.contains_key(&finding.finding_id) {
            return Err(KnowledgeError::DuplicateNode);
        }
        let finding_id = finding.finding_id.clone();
        let initial_state = if finding.validated {
            FindingState::Validated
        } else {
            FindingState::Candidate
        };
        self.audit.append(KnowledgeAuditEvent {
            action: "finding_registered".into(),
            subject_id: finding_id.clone(),
            outcome: format!("{initial_state:?}").to_ascii_lowercase(),
            metadata: BTreeMap::from([(
                "policy_snapshot_sha256".into(),
                finding.policy_snapshot_sha256.clone(),
            )]),
        })?;
        self.records.insert(
            finding_id.clone(),
            FindingLifecycleRecord {
                finding,
                state: initial_state,
                evidence_ids: BTreeSet::new(),
                transition_count: 0,
                cleanup_clear: false,
                suppression_reason_sha256: None,
                audit_tail_hash: self.audit.tail_hash().into(),
            },
        );
        Ok(self.records.get(&finding_id).expect("finding registered"))
    }

    pub fn attach_evidence(
        &mut self,
        finding_id: &str,
        evidence: &EvidenceRecord,
    ) -> Result<(), KnowledgeError> {
        let record = self
            .records
            .get_mut(finding_id)
            .ok_or(KnowledgeError::UnknownNode)?;
        if evidence.policy_snapshot_sha256 != record.finding.policy_snapshot_sha256 {
            return Err(KnowledgeError::InvalidEvidence(
                "finding/evidence policy mismatch".into(),
            ));
        }
        record.evidence_ids.insert(evidence.evidence_id.clone());
        Ok(())
    }

    pub fn set_cleanup_clear(
        &mut self,
        finding_id: &str,
        cleanup_clear: bool,
    ) -> Result<(), KnowledgeError> {
        let record = self
            .records
            .get_mut(finding_id)
            .ok_or(KnowledgeError::UnknownNode)?;
        record.cleanup_clear = cleanup_clear;
        Ok(())
    }

    pub fn transition(
        &mut self,
        finding_id: &str,
        target: FindingState,
        suppression_reason: Option<&str>,
    ) -> Result<&FindingLifecycleRecord, KnowledgeError> {
        let record = self
            .records
            .get_mut(finding_id)
            .ok_or(KnowledgeError::UnknownNode)?;
        let valid = matches!(
            (record.state, target),
            (FindingState::Candidate, FindingState::Validating)
                | (FindingState::Candidate, FindingState::Suppressed)
                | (FindingState::Validating, FindingState::Validated)
                | (FindingState::Validating, FindingState::Suppressed)
                | (FindingState::Validated, FindingState::Reportable)
                | (FindingState::Validated, FindingState::Suppressed)
                | (FindingState::Reportable, FindingState::Closed)
                | (FindingState::Suppressed, FindingState::Closed)
        );
        if !valid {
            return Err(KnowledgeError::InvalidFindingTransition);
        }
        if target == FindingState::Reportable
            && (!record.finding.validated
                || record.evidence_ids.is_empty()
                || !record.cleanup_clear)
        {
            return Err(KnowledgeError::FindingNotReportable);
        }
        if target == FindingState::Suppressed {
            let reason = suppression_reason
                .filter(|value| !value.is_empty())
                .ok_or(KnowledgeError::InvalidFindingTransition)?;
            record.suppression_reason_sha256 = Some(hash_bytes(reason.as_bytes()));
        }
        record.state = target;
        record.transition_count = record.transition_count.saturating_add(1);
        self.audit.append(KnowledgeAuditEvent {
            action: "finding_transition".into(),
            subject_id: finding_id.into(),
            outcome: format!("{target:?}").to_ascii_lowercase(),
            metadata: BTreeMap::from([(
                "transition_count".into(),
                record.transition_count.to_string(),
            )]),
        })?;
        record.audit_tail_hash = self.audit.tail_hash().into();
        Ok(record)
    }

    pub fn get(&self, finding_id: &str) -> Option<&FindingLifecycleRecord> {
        self.records.get(finding_id)
    }

    pub fn records(&self) -> &BTreeMap<String, FindingLifecycleRecord> {
        &self.records
    }

    pub fn audit(&self) -> &KnowledgeAuditChain {
        &self.audit
    }
}

fn validate_finding_fields(
    finding_id: &str,
    rule_id: &str,
    origin: &str,
    endpoint_sha256: &str,
    evidence_sha256: &str,
    summary: &str,
) -> Result<(), KnowledgeError> {
    validate_identifier(finding_id, "finding_id")?;
    validate_identifier(rule_id, "rule_id")?;
    validate_sha256(endpoint_sha256, "finding endpoint")?;
    validate_sha256(evidence_sha256, "finding evidence")?;
    if origin.is_empty()
        || origin.len() > 512
        || summary.is_empty()
        || summary.len() > 2048
        || summary.bytes().any(|byte| byte == 0)
    {
        return Err(KnowledgeError::InvalidEvidence(
            "finding origin or summary".into(),
        ));
    }
    Ok(())
}
