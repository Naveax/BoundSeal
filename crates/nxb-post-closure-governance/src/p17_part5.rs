#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemediationClosure {
    pub closure_id: String,
    pub finding_ledger_sha256: String,
    pub terminal_finding_ids: BTreeSet<String>,
    pub open_finding_count: u64,
    pub critical_unremediated_count: u64,
    pub closure_sha256: String,
}

impl RemediationClosure {
    pub fn new(
        closure_id: impl Into<String>,
        ledger: &ReviewFindingLedger,
    ) -> Result<Self, PostClosureError> {
        ledger.verify()?;
        let closure_id = closure_id.into();
        validate_identifier(&closure_id, "remediation closure")?;
        let terminal_finding_ids = ledger
            .findings
            .values()
            .filter(|finding| {
                matches!(
                    finding.state,
                    ReviewFindingState::Remediated | ReviewFindingState::Rejected
                )
            })
            .map(|finding| finding.finding_id.clone())
            .collect::<BTreeSet<_>>();
        let open_finding_count = ledger
            .findings
            .values()
            .filter(|finding| {
                matches!(
                    finding.state,
                    ReviewFindingState::Open | ReviewFindingState::Accepted
                )
            })
            .count() as u64;
        let critical_unremediated_count = ledger
            .findings
            .values()
            .filter(|finding| {
                finding.severity == ReviewFindingSeverity::Critical
                    && finding.state != ReviewFindingState::Remediated
            })
            .count() as u64;
        if open_finding_count != 0
            || critical_unremediated_count != 0
            || terminal_finding_ids.len() != ledger.findings.len()
        {
            return Err(PostClosureError::InvalidRenewal(
                "remediation closure has unresolved findings".into(),
            ));
        }
        let finding_ledger_sha256 = ledger.ledger_sha256.clone();
        let closure_sha256 = hash_serializable(&(
            &closure_id,
            &finding_ledger_sha256,
            &terminal_finding_ids,
            open_finding_count,
            critical_unremediated_count,
        ))?;
        Ok(Self {
            closure_id,
            finding_ledger_sha256,
            terminal_finding_ids,
            open_finding_count,
            critical_unremediated_count,
            closure_sha256,
        })
    }

    pub fn verify(&self) -> Result<(), PostClosureError> {
        validate_identifier(&self.closure_id, "remediation closure")?;
        validate_sha256(&self.finding_ledger_sha256, "remediation finding ledger")?;
        if self.open_finding_count != 0 || self.critical_unremediated_count != 0 {
            return Err(PostClosureError::InvalidRenewal(
                "remediation closure has unresolved findings".into(),
            ));
        }
        let expected = hash_serializable(&(
            &self.closure_id,
            &self.finding_ledger_sha256,
            &self.terminal_finding_ids,
            self.open_finding_count,
            self.critical_unremediated_count,
        ))?;
        if expected != self.closure_sha256 {
            return Err(PostClosureError::InvalidRenewal(
                "remediation closure digest".into(),
            ));
        }
        Ok(())
    }
}
