#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FaultRule {
    pub rule_id: String,
    pub at_sequence: u64,
    pub kind: FaultKind,
    pub magnitude: u64,
}

impl FaultRule {
    pub fn new(
        rule_id: impl Into<String>,
        at_sequence: u64,
        kind: FaultKind,
        magnitude: u64,
    ) -> Result<Self, ReplayError> {
        let rule_id = rule_id.into();
        validate_identifier(&rule_id, "fault rule")?;
        if at_sequence == 0 || magnitude == 0 || magnitude > MAX_FAULT_MAGNITUDE {
            return Err(ReplayError::InvalidFaultPlan(
                "fault sequence or magnitude".into(),
            ));
        }
        Ok(Self {
            rule_id,
            at_sequence,
            kind,
            magnitude,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FaultPlan {
    pub plan_id: String,
    pub bundle_sha256: String,
    pub rules: Vec<FaultRule>,
    pub plan_sha256: String,
}

impl FaultPlan {
    pub fn new(
        plan_id: impl Into<String>,
        bundle_sha256: impl Into<String>,
        mut rules: Vec<FaultRule>,
    ) -> Result<Self, ReplayError> {
        let plan_id = plan_id.into();
        let bundle_sha256 = bundle_sha256.into();
        validate_identifier(&plan_id, "fault plan")?;
        validate_sha256(&bundle_sha256, "fault-plan bundle")?;
        if rules.len() > MAX_FAULT_RULES {
            return Err(ReplayError::InvalidFaultPlan("rule limit".into()));
        }
        rules.sort_by(|left, right| {
            left.at_sequence
                .cmp(&right.at_sequence)
                .then_with(|| left.rule_id.cmp(&right.rule_id))
        });
        let unique = rules
            .iter()
            .map(|rule| rule.rule_id.as_str())
            .collect::<BTreeSet<_>>();
        if unique.len() != rules.len() {
            return Err(ReplayError::InvalidFaultPlan(
                "duplicate rule identifier".into(),
            ));
        }
        let plan_sha256 = hash_serializable(&(&plan_id, &bundle_sha256, &rules))?;
        Ok(Self {
            plan_id,
            bundle_sha256,
            rules,
            plan_sha256,
        })
    }

    pub fn empty(
        plan_id: impl Into<String>,
        bundle_sha256: impl Into<String>,
    ) -> Result<Self, ReplayError> {
        Self::new(plan_id, bundle_sha256, Vec::new())
    }

    pub fn rules_at(&self, sequence: u64) -> impl Iterator<Item = &FaultRule> {
        self.rules
            .iter()
            .filter(move |rule| rule.at_sequence == sequence)
    }

    pub fn verify(&self) -> Result<(), ReplayError> {
        let expected = hash_serializable(&(&self.plan_id, &self.bundle_sha256, &self.rules))?;
        if expected != self.plan_sha256 {
            return Err(ReplayError::InvalidFaultPlan(
                "fault plan digest mismatch".into(),
            ));
        }
        Ok(())
    }
}
