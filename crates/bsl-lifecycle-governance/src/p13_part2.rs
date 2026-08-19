impl ChangeProposal {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        proposal_id: impl Into<String>,
        identity: &MaintenanceIdentity,
        class: ChangeClass,
        component_roots: BTreeMap<String, String>,
        change_digest_sha256: impl Into<String>,
        rollback_digest_sha256: impl Into<String>,
        requires_recertification: bool,
    ) -> Result<Self, LifecycleError> {
        identity.verify()?;
        let proposal_id = proposal_id.into();
        let change_digest_sha256 = change_digest_sha256.into();
        let rollback_digest_sha256 = rollback_digest_sha256.into();
        validate_identifier(&proposal_id, "change proposal")?;
        validate_hash_map(&component_roots, "change component", MAX_COMPONENTS)?;
        validate_sha256(&change_digest_sha256, "change digest")?;
        validate_sha256(&rollback_digest_sha256, "rollback digest")?;
        if class != ChangeClass::Documentation && !requires_recertification {
            return Err(LifecycleError::InvalidMaintenance(
                "non-documentation changes require recertification".into(),
            ));
        }
        let maintenance_identity_sha256 = identity.identity_sha256.clone();
        let proposal_sha256 = hash_serializable(&(
            &proposal_id,
            &maintenance_identity_sha256,
            class,
            &component_roots,
            &change_digest_sha256,
            &rollback_digest_sha256,
            requires_recertification,
        ))?;
        Ok(Self {
            proposal_id,
            maintenance_identity_sha256,
            class,
            component_roots,
            change_digest_sha256,
            rollback_digest_sha256,
            requires_recertification,
            proposal_sha256,
        })
    }

    pub fn verify(&self) -> Result<(), LifecycleError> {
        validate_identifier(&self.proposal_id, "change proposal")?;
        validate_hash_map(&self.component_roots, "change component", MAX_COMPONENTS)?;
        for (name, value) in [
            (
                "maintenance identity",
                self.maintenance_identity_sha256.as_str(),
            ),
            ("change digest", self.change_digest_sha256.as_str()),
            ("rollback digest", self.rollback_digest_sha256.as_str()),
            ("proposal digest", self.proposal_sha256.as_str()),
        ] {
            validate_sha256(value, name)?;
        }
        if self.class != ChangeClass::Documentation && !self.requires_recertification {
            return Err(LifecycleError::InvalidMaintenance(
                "proposal recertification policy".into(),
            ));
        }
        let expected = hash_serializable(&(
            &self.proposal_id,
            &self.maintenance_identity_sha256,
            self.class,
            &self.component_roots,
            &self.change_digest_sha256,
            &self.rollback_digest_sha256,
            self.requires_recertification,
        ))?;
        if expected != self.proposal_sha256 {
            return Err(LifecycleError::InvalidMaintenance("proposal digest".into()));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ImpactLevel {
    Low,
    Moderate,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImpactAssessment {
    pub assessment_id: String,
    pub proposal_sha256: String,
    pub affected_components: BTreeSet<String>,
    pub affected_invariants: BTreeSet<String>,
    pub level: ImpactLevel,
    pub safety_critical: bool,
    pub assessment_sha256: String,
}
