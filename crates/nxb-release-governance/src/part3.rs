#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CompatibilityRequirement {
    pub requirement_id: String,
    pub axis: CompatibilityAxis,
    pub minimum_version: u32,
    pub maximum_version: u32,
    pub observed_version: u32,
    pub evidence_sha256: String,
    pub status: CompatibilityStatus,
}

impl CompatibilityRequirement {
    pub fn new(
        requirement_id: impl Into<String>,
        axis: CompatibilityAxis,
        minimum_version: u32,
        maximum_version: u32,
        observed_version: u32,
        evidence_sha256: impl Into<String>,
    ) -> Result<Self, ReleaseError> {
        let requirement_id = requirement_id.into();
        let evidence_sha256 = evidence_sha256.into();
        validate_identifier(&requirement_id, "compatibility requirement")?;
        validate_sha256(&evidence_sha256, "compatibility evidence")?;
        if minimum_version == 0 || maximum_version < minimum_version || observed_version == 0 {
            return Err(ReleaseError::InvalidCompatibility(
                "version range".into(),
            ));
        }
        let status = if observed_version < minimum_version {
            CompatibilityStatus::TooOld
        } else if observed_version > maximum_version {
            CompatibilityStatus::TooNew
        } else {
            CompatibilityStatus::Compatible
        };
        Ok(Self {
            requirement_id,
            axis,
            minimum_version,
            maximum_version,
            observed_version,
            evidence_sha256,
            status,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MigrationStep {
    pub step_id: String,
    pub kind: MigrationKind,
    pub from_version: u32,
    pub to_version: u32,
    pub reversible: bool,
    pub evidence_sha256: String,
    pub step_sha256: String,
}

impl MigrationStep {
    pub fn new(
        step_id: impl Into<String>,
        kind: MigrationKind,
        from_version: u32,
        to_version: u32,
        reversible: bool,
        evidence_sha256: impl Into<String>,
    ) -> Result<Self, ReleaseError> {
        let step_id = step_id.into();
        let evidence_sha256 = evidence_sha256.into();
        validate_identifier(&step_id, "migration step")?;
        validate_sha256(&evidence_sha256, "migration evidence")?;
        if from_version == 0 || to_version <= from_version || !reversible {
            return Err(ReleaseError::InvalidCompatibility(
                "migration must be forward and reversible".into(),
            ));
        }
        let step_sha256 = hash_serializable(&(
            &step_id,
            kind,
            from_version,
            to_version,
            reversible,
            &evidence_sha256,
        ))?;
        Ok(Self {
            step_id,
            kind,
            from_version,
            to_version,
            reversible,
            evidence_sha256,
            step_sha256,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MigrationPlan {
    pub plan_id: String,
    pub steps: Vec<MigrationStep>,
    pub plan_sha256: String,
}

impl MigrationPlan {
    pub fn new(
        plan_id: impl Into<String>,
        steps: Vec<MigrationStep>,
    ) -> Result<Self, ReleaseError> {
        let plan_id = plan_id.into();
        validate_identifier(&plan_id, "migration plan")?;
        if steps.is_empty() || steps.len() > MAX_MIGRATION_STEPS {
            return Err(ReleaseError::InvalidCompatibility(
                "migration step count".into(),
            ));
        }
        let unique = steps
            .iter()
            .map(|step| step.step_id.as_str())
            .collect::<BTreeSet<_>>();
        if unique.len() != steps.len()
            || steps.windows(2).any(|pair| pair[0].to_version != pair[1].from_version)
        {
            return Err(ReleaseError::InvalidCompatibility(
                "migration identifiers or version continuity".into(),
            ));
        }
        let plan_sha256 = hash_serializable(&(&plan_id, &steps))?;
        Ok(Self {
            plan_id,
            steps,
            plan_sha256,
        })
    }

    pub fn verify(&self) -> Result<(), ReleaseError> {
        let expected = hash_serializable(&(&self.plan_id, &self.steps))?;
        if expected != self.plan_sha256
            || self.steps.iter().any(|step| !step.reversible)
            || self
                .steps
                .windows(2)
                .any(|pair| pair[0].to_version != pair[1].from_version)
        {
            return Err(ReleaseError::InvalidCompatibility(
                "migration plan digest or reversibility".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CompatibilityContract {
    pub contract_id: String,
    pub policy_snapshot_sha256: String,
    pub requirements: BTreeMap<String, CompatibilityRequirement>,
    pub migration_plan_sha256: Option<String>,
    pub all_compatible: bool,
    pub contract_sha256: String,
}

impl CompatibilityContract {
    pub fn new(
        contract_id: impl Into<String>,
        policy_snapshot_sha256: impl Into<String>,
        requirements: Vec<CompatibilityRequirement>,
        migration_plan: Option<&MigrationPlan>,
    ) -> Result<Self, ReleaseError> {
        let contract_id = contract_id.into();
        let policy_snapshot_sha256 = policy_snapshot_sha256.into();
        validate_identifier(&contract_id, "compatibility contract")?;
        validate_sha256(&policy_snapshot_sha256, "compatibility policy")?;
        if requirements.is_empty() || requirements.len() > MAX_COMPATIBILITY_REQUIREMENTS {
            return Err(ReleaseError::InvalidCompatibility(
                "requirement count".into(),
            ));
        }
        if let Some(plan) = migration_plan {
            plan.verify()?;
        }
        let mut by_id = BTreeMap::new();
        for requirement in requirements {
            if by_id
                .insert(requirement.requirement_id.clone(), requirement)
                .is_some()
            {
                return Err(ReleaseError::InvalidCompatibility(
                    "duplicate requirement".into(),
                ));
            }
        }
        let axes = by_id
            .values()
            .map(|requirement| requirement.axis)
            .collect::<BTreeSet<_>>();
        if axes.len() != by_id.len() {
            return Err(ReleaseError::InvalidCompatibility(
                "duplicate compatibility axis".into(),
            ));
        }
        let all_compatible = by_id
            .values()
            .all(|requirement| requirement.status == CompatibilityStatus::Compatible);
        let migration_plan_sha256 = migration_plan.map(|plan| plan.plan_sha256.clone());
        let contract_sha256 = hash_serializable(&(
            &contract_id,
            &policy_snapshot_sha256,
            &by_id,
            &migration_plan_sha256,
            all_compatible,
        ))?;
        Ok(Self {
            contract_id,
            policy_snapshot_sha256,
            requirements: by_id,
            migration_plan_sha256,
            all_compatible,
            contract_sha256,
        })
    }

    pub fn verify(&self) -> Result<(), ReleaseError> {
        let all_compatible = self
            .requirements
            .values()
            .all(|requirement| requirement.status == CompatibilityStatus::Compatible);
        let expected = hash_serializable(&(
            &self.contract_id,
            &self.policy_snapshot_sha256,
            &self.requirements,
            &self.migration_plan_sha256,
            all_compatible,
        ))?;
        if expected != self.contract_sha256 || all_compatible != self.all_compatible {
            return Err(ReleaseError::InvalidCompatibility(
                "compatibility contract digest".into(),
            ));
        }
        Ok(())
    }
}
