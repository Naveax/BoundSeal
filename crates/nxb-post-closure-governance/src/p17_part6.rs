#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RenewalCertificate {
    pub certificate_id: String,
    pub policy_snapshot_sha256: String,
    pub succession_certificate_sha256: String,
    pub review_panel_sha256: String,
    pub sample_plan_sha256: String,
    pub assignment_matrix_sha256: String,
    pub finding_ledger_sha256: String,
    pub remediation_closure_sha256: String,
    pub authority_audit_tail_hash: String,
    pub certificate_sha256: String,
}

impl RenewalCertificate {
    pub fn verify(&self) -> Result<(), PostClosureError> {
        validate_identifier(&self.certificate_id, "renewal certificate")?;
        for (name, value) in [
            ("renewal policy", self.policy_snapshot_sha256.as_str()),
            (
                "renewal succession",
                self.succession_certificate_sha256.as_str(),
            ),
            ("renewal review panel", self.review_panel_sha256.as_str()),
            ("renewal sample plan", self.sample_plan_sha256.as_str()),
            (
                "renewal assignment matrix",
                self.assignment_matrix_sha256.as_str(),
            ),
            (
                "renewal finding ledger",
                self.finding_ledger_sha256.as_str(),
            ),
            (
                "renewal remediation closure",
                self.remediation_closure_sha256.as_str(),
            ),
            (
                "renewal authority audit",
                self.authority_audit_tail_hash.as_str(),
            ),
        ] {
            validate_sha256(value, name)?;
        }
        let expected = hash_serializable(&(
            &self.certificate_id,
            &self.policy_snapshot_sha256,
            &self.succession_certificate_sha256,
            &self.review_panel_sha256,
            &self.sample_plan_sha256,
            &self.assignment_matrix_sha256,
            &self.finding_ledger_sha256,
            &self.remediation_closure_sha256,
            &self.authority_audit_tail_hash,
        ))?;
        if expected != self.certificate_sha256 {
            return Err(PostClosureError::InvalidRenewal(
                "renewal certificate digest".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct RenewalAuthority {
    authority_id: String,
    policy_snapshot_sha256: String,
    audit: PostClosureAuditChain,
}

impl RenewalAuthority {
    pub fn new(
        authority_id: impl Into<String>,
        policy_snapshot_sha256: impl Into<String>,
        audit_genesis: impl Into<String>,
    ) -> Result<Self, PostClosureError> {
        let authority_id = authority_id.into();
        let policy_snapshot_sha256 = policy_snapshot_sha256.into();
        validate_identifier(&authority_id, "renewal authority")?;
        validate_sha256(&policy_snapshot_sha256, "renewal authority policy")?;
        Ok(Self {
            authority_id,
            policy_snapshot_sha256,
            audit: PostClosureAuditChain::new(audit_genesis)?,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn certify(
        &mut self,
        succession: &SuccessionCertificate,
        panel: &ReviewPanel,
        sample_plan: &EvidenceSamplePlan,
        matrix: &ReviewAssignmentMatrix,
        ledger: &ReviewFindingLedger,
        remediation: &RemediationClosure,
    ) -> Result<RenewalCertificate, PostClosureError> {
        succession.verify()?;
        panel.verify()?;
        sample_plan.verify()?;
        matrix.verify()?;
        ledger.verify()?;
        remediation.verify()?;

        let assignment_evidence_ids = matrix
            .assignments
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        let assignments_match_sources = assignment_evidence_ids == sample_plan.sample_ids
            && matrix.assignments.values().all(|assignment| {
                assignment
                    .reviewer_ids
                    .iter()
                    .all(|reviewer_id| panel.members.contains_key(reviewer_id))
                    && assignment
                        .reviewer_ids
                        .iter()
                        .map(|reviewer_id| {
                            panel.members[reviewer_id]
                                .organization_root_sha256
                                .clone()
                        })
                        .collect::<BTreeSet<_>>()
                        .len()
                        >= 2
            });
        let findings_match_assignments = ledger
            .findings
            .values()
            .all(|finding| matrix.assignments.contains_key(&finding.evidence_id));
        let expected_terminal_finding_ids = ledger
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
        let expected_open_finding_count = ledger
            .findings
            .values()
            .filter(|finding| {
                matches!(
                    finding.state,
                    ReviewFindingState::Open | ReviewFindingState::Accepted
                )
            })
            .count() as u64;
        let expected_critical_unremediated_count = ledger
            .findings
            .values()
            .filter(|finding| {
                finding.severity == ReviewFindingSeverity::Critical
                    && finding.state != ReviewFindingState::Remediated
            })
            .count() as u64;
        let remediation_matches_ledger = remediation.terminal_finding_ids
            == expected_terminal_finding_ids
            && remediation.open_finding_count == expected_open_finding_count
            && remediation.critical_unremediated_count
                == expected_critical_unremediated_count
            && remediation.terminal_finding_ids.len() == ledger.findings.len();

        if succession.policy_snapshot_sha256 != self.policy_snapshot_sha256
            || panel.succession_certificate_sha256 != succession.certificate_sha256
            || sample_plan.succession_certificate_sha256 != succession.certificate_sha256
            || matrix.panel_sha256 != panel.panel_sha256
            || matrix.sample_plan_sha256 != sample_plan.plan_sha256
            || ledger.assignment_matrix_sha256 != matrix.matrix_sha256
            || remediation.finding_ledger_sha256 != ledger.ledger_sha256
            || !assignments_match_sources
            || !findings_match_assignments
            || !remediation_matches_ledger
        {
            return Err(PostClosureError::InvalidRenewal(
                "renewal certificate closure".into(),
            ));
        }
        let seed = hash_serializable(&(
            &self.authority_id,
            &self.policy_snapshot_sha256,
            &succession.certificate_sha256,
            &remediation.closure_sha256,
        ))?;
        let certificate_id = format!("renewal-{}", &seed[..24]);
        self.audit.append(PostClosureAuditEvent {
            action: "renewal_certified".into(),
            subject_id: certificate_id.clone(),
            outcome: "certified".into(),
            metadata: BTreeMap::from([
                ("panel_sha256".into(), panel.panel_sha256.clone()),
                (
                    "remediation_closure_sha256".into(),
                    remediation.closure_sha256.clone(),
                ),
            ]),
        })?;
        let authority_audit_tail_hash = self.audit.tail_hash().to_owned();
        let certificate_sha256 = hash_serializable(&(
            &certificate_id,
            &self.policy_snapshot_sha256,
            &succession.certificate_sha256,
            &panel.panel_sha256,
            &sample_plan.plan_sha256,
            &matrix.matrix_sha256,
            &ledger.ledger_sha256,
            &remediation.closure_sha256,
            &authority_audit_tail_hash,
        ))?;
        let certificate = RenewalCertificate {
            certificate_id,
            policy_snapshot_sha256: self.policy_snapshot_sha256.clone(),
            succession_certificate_sha256: succession.certificate_sha256.clone(),
            review_panel_sha256: panel.panel_sha256.clone(),
            sample_plan_sha256: sample_plan.plan_sha256.clone(),
            assignment_matrix_sha256: matrix.matrix_sha256.clone(),
            finding_ledger_sha256: ledger.ledger_sha256.clone(),
            remediation_closure_sha256: remediation.closure_sha256.clone(),
            authority_audit_tail_hash,
            certificate_sha256,
        };
        certificate.verify()?;
        Ok(certificate)
    }

    pub fn audit(&self) -> &PostClosureAuditChain {
        &self.audit
    }
}
