#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityMode {
    ReadOnly,
    ForwardCompatible,
    Bidirectional,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CompatibilityEnvelope {
    pub envelope_id: String,
    pub successor_identity_sha256: String,
    pub source_schema_root_sha256: String,
    pub target_schema_root_sha256: String,
    pub mode: CompatibilityMode,
    pub affected_components: BTreeSet<String>,
    pub invariant_roots: BTreeMap<String, String>,
    pub envelope_sha256: String,
}

impl CompatibilityEnvelope {
    pub fn new(
        envelope_id: impl Into<String>,
        identity: &SuccessorIdentity,
        source_schema_root_sha256: impl Into<String>,
        target_schema_root_sha256: impl Into<String>,
        mode: CompatibilityMode,
        affected_components: BTreeSet<String>,
        invariant_roots: BTreeMap<String, String>,
    ) -> Result<Self, PostClosureError> {
        identity.verify()?;
        let envelope_id = envelope_id.into();
        let source_schema_root_sha256 = source_schema_root_sha256.into();
        let target_schema_root_sha256 = target_schema_root_sha256.into();
        validate_identifier(&envelope_id, "compatibility envelope")?;
        validate_sha256(&source_schema_root_sha256, "source schema root")?;
        validate_sha256(&target_schema_root_sha256, "target schema root")?;
        if source_schema_root_sha256 == target_schema_root_sha256
            || affected_components.is_empty()
            || affected_components.len() > MAX_COMPONENTS
        {
            return Err(PostClosureError::InvalidSuccession(
                "compatibility schema or component set".into(),
            ));
        }
        for component in &affected_components {
            validate_identifier(component, "affected component")?;
        }
        validate_hash_map(&invariant_roots, "compatibility invariant", MAX_COMPONENTS)?;
        let successor_identity_sha256 = identity.identity_sha256.clone();
        let envelope_sha256 = hash_serializable(&(
            &envelope_id,
            &successor_identity_sha256,
            &source_schema_root_sha256,
            &target_schema_root_sha256,
            mode,
            &affected_components,
            &invariant_roots,
        ))?;
        Ok(Self {
            envelope_id,
            successor_identity_sha256,
            source_schema_root_sha256,
            target_schema_root_sha256,
            mode,
            affected_components,
            invariant_roots,
            envelope_sha256,
        })
    }

    pub fn verify(&self) -> Result<(), PostClosureError> {
        validate_identifier(&self.envelope_id, "compatibility envelope")?;
        validate_sha256(
            &self.successor_identity_sha256,
            "compatibility successor identity",
        )?;
        validate_sha256(&self.source_schema_root_sha256, "source schema root")?;
        validate_sha256(&self.target_schema_root_sha256, "target schema root")?;
        if self.source_schema_root_sha256 == self.target_schema_root_sha256
            || self.affected_components.is_empty()
            || self.affected_components.len() > MAX_COMPONENTS
        {
            return Err(PostClosureError::InvalidSuccession(
                "compatibility schema or component set".into(),
            ));
        }
        for component in &self.affected_components {
            validate_identifier(component, "affected component")?;
        }
        validate_hash_map(
            &self.invariant_roots,
            "compatibility invariant",
            MAX_COMPONENTS,
        )?;
        let expected = hash_serializable(&(
            &self.envelope_id,
            &self.successor_identity_sha256,
            &self.source_schema_root_sha256,
            &self.target_schema_root_sha256,
            self.mode,
            &self.affected_components,
            &self.invariant_roots,
        ))?;
        if expected != self.envelope_sha256 {
            return Err(PostClosureError::InvalidSuccession(
                "compatibility envelope digest".into(),
            ));
        }
        Ok(())
    }
}
