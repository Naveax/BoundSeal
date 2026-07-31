impl ApprovalQuorum {
    pub fn new(
        envelope: &OperatorCommandEnvelope,
        approvals: Vec<OperatorApproval>,
    ) -> Result<Self, AssuranceError> {
        if approvals.is_empty() || approvals.len() > MAX_OPERATOR_APPROVALS {
            return Err(AssuranceError::ApprovalDenied("approval count".into()));
        }
        let mut by_operator = BTreeMap::new();
        for approval in approvals {
            approval.verify(envelope)?;
            if by_operator
                .insert(approval.operator.operator_id.clone(), approval)
                .is_some()
            {
                return Err(AssuranceError::ApprovalDenied(
                    "duplicate operator approval".into(),
                ));
            }
        }
        let roles = by_operator
            .values()
            .map(|a| a.operator.role)
            .collect::<BTreeSet<_>>();
        let count = by_operator.len();
        let accepted = match envelope.command {
            OperatorCommand::Pause
            | OperatorCommand::Cancel
            | OperatorCommand::AcknowledgeIncident => {
                count >= 1
                    && roles.iter().any(|r| {
                        matches!(
                            r,
                            OperatorRole::Operator
                                | OperatorRole::Supervisor
                                | OperatorRole::SafetyOfficer
                        )
                    })
            }
            OperatorCommand::EmergencyStop => {
                count >= 1
                    && roles.iter().any(|r| {
                        matches!(r, OperatorRole::Supervisor | OperatorRole::SafetyOfficer)
                    })
            }
            OperatorCommand::Resume | OperatorCommand::SealRun => {
                count >= 2
                    && roles.contains(&OperatorRole::Supervisor)
                    && roles.contains(&OperatorRole::SafetyOfficer)
            }
        };
        if !accepted {
            return Err(AssuranceError::ApprovalDenied(
                "command quorum or role requirement".into(),
            ));
        }
        Ok(Self {
            approvals: by_operator,
        })
    }
    pub fn digest(&self) -> Result<String, AssuranceError> {
        hash_serializable(&self.approvals)
    }
    pub fn operator_ids(&self) -> BTreeSet<String> {
        self.approvals.keys().cloned().collect()
    }
}
