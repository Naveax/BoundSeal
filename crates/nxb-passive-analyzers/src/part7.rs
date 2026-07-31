pub const MIN_ACCOUNTED_FINDING_BYTES: u64 = 384;
pub const MIN_ACCOUNTED_EVIDENCE_BYTES: u64 = 32;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum FindingCapacityError {
    #[error("finding resource budget is invalid: {0}")]
    InvalidBudget(String),
    #[error("finding serialization failed: {0}")]
    Serialization(String),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindingResourceBudget {
    pub memory_budget_bytes: u64,
    pub evidence_budget_bytes: u64,
    pub endpoint_budget: u64,
    pub rules_per_endpoint_upper_bound: u32,
}

impl FindingResourceBudget {
    pub fn derive(self) -> Result<DerivedFindingCapacity, FindingCapacityError> {
        if self.memory_budget_bytes < MIN_ACCOUNTED_FINDING_BYTES
            || self.evidence_budget_bytes < MIN_ACCOUNTED_EVIDENCE_BYTES
            || self.endpoint_budget == 0
            || self.rules_per_endpoint_upper_bound == 0
        {
            return Err(FindingCapacityError::InvalidBudget(
                "all budgets must support at least one finding".into(),
            ));
        }

        let memory_limited_findings =
            self.memory_budget_bytes / MIN_ACCOUNTED_FINDING_BYTES;
        let evidence_limited_findings =
            self.evidence_budget_bytes / MIN_ACCOUNTED_EVIDENCE_BYTES;
        let scope_limited_findings = self
            .endpoint_budget
            .saturating_mul(u64::from(self.rules_per_endpoint_upper_bound));
        let maximum_unique_findings = memory_limited_findings
            .min(evidence_limited_findings)
            .min(scope_limited_findings);

        if maximum_unique_findings == 0 {
            return Err(FindingCapacityError::InvalidBudget(
                "derived finding capacity is zero".into(),
            ));
        }

        Ok(DerivedFindingCapacity {
            budget: self,
            memory_limited_findings,
            evidence_limited_findings,
            scope_limited_findings,
            maximum_unique_findings,
        })
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct DerivedFindingCapacity {
    pub budget: FindingResourceBudget,
    pub memory_limited_findings: u64,
    pub evidence_limited_findings: u64,
    pub scope_limited_findings: u64,
    pub maximum_unique_findings: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingStopReason {
    DerivedCapacity,
    MemoryBudget,
    EvidenceBudget,
    EndpointBudget,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindingCapacityReceipt {
    pub accepted_unique_findings: u64,
    pub duplicate_findings: u64,
    pub distinct_endpoints: u64,
    pub accounted_memory_bytes: u64,
    pub accounted_evidence_bytes: u64,
    pub maximum_unique_findings: u64,
    pub stop_reason: Option<FindingStopReason>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingIngestOutcome {
    Accepted,
    Duplicate,
    Stopped(FindingStopReason),
}

#[derive(Debug)]
pub struct FindingAccumulator {
    capacity: DerivedFindingCapacity,
    findings: Vec<Finding>,
    finding_ids: BTreeSet<String>,
    endpoint_ids: BTreeSet<String>,
    accounted_memory_bytes: u64,
    accounted_evidence_bytes: u64,
    duplicate_findings: u64,
    stop_reason: Option<FindingStopReason>,
}

impl FindingAccumulator {
    pub fn new(capacity: DerivedFindingCapacity) -> Self {
        Self {
            capacity,
            findings: Vec::new(),
            finding_ids: BTreeSet::new(),
            endpoint_ids: BTreeSet::new(),
            accounted_memory_bytes: 0,
            accounted_evidence_bytes: 0,
            duplicate_findings: 0,
            stop_reason: None,
        }
    }

    pub fn ingest(
        &mut self,
        finding: Finding,
        evidence_bytes: u64,
    ) -> Result<FindingIngestOutcome, FindingCapacityError> {
        if let Some(reason) = self.stop_reason {
            return Ok(FindingIngestOutcome::Stopped(reason));
        }
        if self.finding_ids.contains(&finding.finding_id) {
            self.duplicate_findings = self.duplicate_findings.saturating_add(1);
            return Ok(FindingIngestOutcome::Duplicate);
        }

        let serialized_bytes = u64::try_from(
            serde_json::to_vec(&finding)
                .map_err(|error| FindingCapacityError::Serialization(error.to_string()))?
                .len(),
        )
        .unwrap_or(u64::MAX)
        .max(MIN_ACCOUNTED_FINDING_BYTES);
        let accounted_evidence = evidence_bytes.max(MIN_ACCOUNTED_EVIDENCE_BYTES);
        let next_unique = u64::try_from(self.findings.len())
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        let endpoint_is_new = !self.endpoint_ids.contains(&finding.endpoint_sha256);
        let next_endpoints = u64::try_from(self.endpoint_ids.len())
            .unwrap_or(u64::MAX)
            .saturating_add(u64::from(endpoint_is_new));

        let reason = if next_unique > self.capacity.maximum_unique_findings {
            Some(FindingStopReason::DerivedCapacity)
        } else if self
            .accounted_memory_bytes
            .saturating_add(serialized_bytes)
            > self.capacity.budget.memory_budget_bytes
        {
            Some(FindingStopReason::MemoryBudget)
        } else if self
            .accounted_evidence_bytes
            .saturating_add(accounted_evidence)
            > self.capacity.budget.evidence_budget_bytes
        {
            Some(FindingStopReason::EvidenceBudget)
        } else if next_endpoints > self.capacity.budget.endpoint_budget {
            Some(FindingStopReason::EndpointBudget)
        } else {
            None
        };

        if let Some(reason) = reason {
            self.stop_reason = Some(reason);
            return Ok(FindingIngestOutcome::Stopped(reason));
        }

        self.accounted_memory_bytes = self
            .accounted_memory_bytes
            .saturating_add(serialized_bytes);
        self.accounted_evidence_bytes = self
            .accounted_evidence_bytes
            .saturating_add(accounted_evidence);
        self.finding_ids.insert(finding.finding_id.clone());
        self.endpoint_ids.insert(finding.endpoint_sha256.clone());
        self.findings.push(finding);
        Ok(FindingIngestOutcome::Accepted)
    }

    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    pub fn into_findings(self) -> Vec<Finding> {
        self.findings
    }

    pub fn receipt(&self) -> FindingCapacityReceipt {
        FindingCapacityReceipt {
            accepted_unique_findings: u64::try_from(self.findings.len()).unwrap_or(u64::MAX),
            duplicate_findings: self.duplicate_findings,
            distinct_endpoints: u64::try_from(self.endpoint_ids.len()).unwrap_or(u64::MAX),
            accounted_memory_bytes: self.accounted_memory_bytes,
            accounted_evidence_bytes: self.accounted_evidence_bytes,
            maximum_unique_findings: self.capacity.maximum_unique_findings,
            stop_reason: self.stop_reason,
        }
    }
}
