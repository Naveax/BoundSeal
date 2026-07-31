#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ReviewFindingSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ReviewFindingState {
    Open,
    Accepted,
    Remediated,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReviewFinding {
    pub finding_id: String,
    pub evidence_id: String,
    pub severity: ReviewFindingSeverity,
    pub state: ReviewFindingState,
    pub summary_sha256: String,
    pub remediation_receipt_sha256: Option<String>,
    pub finding_sha256: String,
}

impl ReviewFinding {
    pub fn new(
        finding_id: impl Into<String>,
        evidence_id: impl Into<String>,
        severity: ReviewFindingSeverity,
        state: ReviewFindingState,
        summary_sha256: impl Into<String>,
        remediation_receipt_sha256: Option<String>,
    ) -> Result<Self, PostClosureError> {
        let finding_id = finding_id.into();
        let evidence_id = evidence_id.into();
        let summary_sha256 = summary_sha256.into();
        validate_identifier(&finding_id, "review finding")?;
        validate_identifier(&evidence_id, "review finding evidence")?;
        validate_sha256(&summary_sha256, "review finding summary")?;
        if let Some(receipt) = &remediation_receipt_sha256 {
            validate_sha256(receipt, "review finding remediation")?;
        }
        let terminal_requires_receipt = matches!(
            state,
            ReviewFindingState::Remediated | ReviewFindingState::Rejected
        );
        if terminal_requires_receipt != remediation_receipt_sha256.is_some() {
            return Err(PostClosureError::InvalidRenewal(
                "review finding remediation receipt state".into(),
            ));
        }
        let finding_sha256 = hash_serializable(&(
            &finding_id,
            &evidence_id,
            severity,
            state,
            &summary_sha256,
            &remediation_receipt_sha256,
        ))?;
        Ok(Self {
            finding_id,
            evidence_id,
            severity,
            state,
            summary_sha256,
            remediation_receipt_sha256,
            finding_sha256,
        })
    }

    pub fn verify(&self) -> Result<(), PostClosureError> {
        validate_identifier(&self.finding_id, "review finding")?;
        validate_identifier(&self.evidence_id, "review finding evidence")?;
        validate_sha256(&self.summary_sha256, "review finding summary")?;
        if let Some(receipt) = &self.remediation_receipt_sha256 {
            validate_sha256(receipt, "review finding remediation")?;
        }
        let terminal_requires_receipt = matches!(
            self.state,
            ReviewFindingState::Remediated | ReviewFindingState::Rejected
        );
        if terminal_requires_receipt != self.remediation_receipt_sha256.is_some() {
            return Err(PostClosureError::InvalidRenewal(
                "review finding remediation receipt state".into(),
            ));
        }
        let expected = hash_serializable(&(
            &self.finding_id,
            &self.evidence_id,
            self.severity,
            self.state,
            &self.summary_sha256,
            &self.remediation_receipt_sha256,
        ))?;
        if expected != self.finding_sha256 {
            return Err(PostClosureError::InvalidRenewal(
                "review finding digest".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReviewFindingLedger {
    pub ledger_id: String,
    pub assignment_matrix_sha256: String,
    pub findings: BTreeMap<String, ReviewFinding>,
    pub ledger_sha256: String,
}

impl ReviewFindingLedger {
    pub fn new(
        ledger_id: impl Into<String>,
        matrix: &ReviewAssignmentMatrix,
        findings: Vec<ReviewFinding>,
    ) -> Result<Self, PostClosureError> {
        matrix.verify()?;
        let ledger_id = ledger_id.into();
        validate_identifier(&ledger_id, "review finding ledger")?;
        if findings.len() > MAX_FINDINGS {
            return Err(PostClosureError::InvalidRenewal(
                "review finding count".into(),
            ));
        }
        let mut by_id = BTreeMap::new();
        for finding in findings {
            finding.verify()?;
            if !matrix.assignments.contains_key(&finding.evidence_id) {
                return Err(PostClosureError::InvalidRenewal(
                    "finding evidence outside assignment matrix".into(),
                ));
            }
            if by_id.insert(finding.finding_id.clone(), finding).is_some() {
                return Err(PostClosureError::InvalidRenewal(
                    "duplicate review finding".into(),
                ));
            }
        }
        let assignment_matrix_sha256 = matrix.matrix_sha256.clone();
        let ledger_sha256 = hash_serializable(&(&ledger_id, &assignment_matrix_sha256, &by_id))?;
        Ok(Self {
            ledger_id,
            assignment_matrix_sha256,
            findings: by_id,
            ledger_sha256,
        })
    }

    pub fn verify(&self) -> Result<(), PostClosureError> {
        validate_identifier(&self.ledger_id, "review finding ledger")?;
        validate_sha256(
            &self.assignment_matrix_sha256,
            "review finding assignment matrix",
        )?;
        if self.findings.len() > MAX_FINDINGS {
            return Err(PostClosureError::InvalidRenewal(
                "review finding count".into(),
            ));
        }
        for (key, finding) in &self.findings {
            finding.verify()?;
            if key != &finding.finding_id {
                return Err(PostClosureError::InvalidRenewal(
                    "review finding ledger key".into(),
                ));
            }
        }
        let expected = hash_serializable(&(
            &self.ledger_id,
            &self.assignment_matrix_sha256,
            &self.findings,
        ))?;
        if expected != self.ledger_sha256 {
            return Err(PostClosureError::InvalidRenewal(
                "review finding ledger digest".into(),
            ));
        }
        Ok(())
    }
}
