#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MutationTarget {
    pub location: MutationLocation,
    pub name: String,
    pub name_sha256: String,
    pub original_value_sha256: String,
    pub value_class: ValueClass,
}

impl MutationTarget {
    pub fn new(
        location: MutationLocation,
        name: impl Into<String>,
        original_value_sha256: impl Into<String>,
        value_class: ValueClass,
    ) -> Result<Self, ValidationError> {
        let name = name.into();
        if name.is_empty()
            || name.len() > 256
            || name.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(ValidationError::InvalidMutation(
                "mutation target name".into(),
            ));
        }
        let original_value_sha256 = original_value_sha256.into();
        validate_sha256(&original_value_sha256, "original value")?;
        Ok(Self {
            location,
            name_sha256: hash_bytes(name.as_bytes()),
            name,
            original_value_sha256,
            value_class,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MutationTemplate {
    pub template_id: String,
    pub allowed_kinds: BTreeSet<MutationKind>,
    pub allowed_locations: BTreeSet<MutationLocation>,
    pub maximum_output_bytes: usize,
    pub maximum_variants: u32,
}

impl MutationTemplate {
    pub fn new(
        template_id: impl Into<String>,
        allowed_kinds: BTreeSet<MutationKind>,
        allowed_locations: BTreeSet<MutationLocation>,
        maximum_output_bytes: usize,
        maximum_variants: u32,
    ) -> Result<Self, ValidationError> {
        let template_id = template_id.into();
        validate_identifier(&template_id, "template_id")?;
        if allowed_kinds.is_empty()
            || allowed_locations.is_empty()
            || maximum_output_bytes == 0
            || maximum_output_bytes > MAX_MUTATION_VALUE_BYTES
            || maximum_variants == 0
            || maximum_variants > MAX_MUTATIONS_PER_PLAN
        {
            return Err(ValidationError::InvalidMutation(
                "mutation template bounds".into(),
            ));
        }
        Ok(Self {
            template_id,
            allowed_kinds,
            allowed_locations,
            maximum_output_bytes,
            maximum_variants,
        })
    }
}

#[derive(Clone)]
pub struct SafeMutation {
    pub mutation_id: String,
    pub endpoint_sha256: String,
    pub plan_fingerprint: String,
    pub capability_id: String,
    pub target: MutationTarget,
    pub kind: MutationKind,
    pub value_sha256: String,
    pub value_bytes: usize,
    value: Vec<u8>,
}

impl fmt::Debug for SafeMutation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SafeMutation")
            .field("mutation_id", &self.mutation_id)
            .field("endpoint_sha256", &self.endpoint_sha256)
            .field("plan_fingerprint", &self.plan_fingerprint)
            .field("capability_id", &self.capability_id)
            .field("target", &self.target)
            .field("kind", &self.kind)
            .field("value_sha256", &self.value_sha256)
            .field("value_bytes", &self.value_bytes)
            .field("value", &"[redacted inert marker]")
            .finish()
    }
}

impl SafeMutation {
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    pub fn receipt(&self) -> MutationReceipt {
        MutationReceipt {
            mutation_id: self.mutation_id.clone(),
            endpoint_sha256: self.endpoint_sha256.clone(),
            plan_fingerprint: self.plan_fingerprint.clone(),
            capability_id: self.capability_id.clone(),
            target_name_sha256: self.target.name_sha256.clone(),
            location: self.target.location,
            kind: self.kind,
            value_sha256: self.value_sha256.clone(),
            value_bytes: self.value_bytes,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MutationReceipt {
    pub mutation_id: String,
    pub endpoint_sha256: String,
    pub plan_fingerprint: String,
    pub capability_id: String,
    pub target_name_sha256: String,
    pub location: MutationLocation,
    pub kind: MutationKind,
    pub value_sha256: String,
    pub value_bytes: usize,
}

#[derive(Debug)]
pub struct SafeMutationEngine {
    engine_id: String,
    next_sequence: u64,
    audit: ValidationAuditChain,
}

impl SafeMutationEngine {
    pub fn new(
        engine_id: impl Into<String>,
        audit_genesis: impl Into<String>,
    ) -> Result<Self, ValidationError> {
        let engine_id = engine_id.into();
        validate_identifier(&engine_id, "engine_id")?;
        Ok(Self {
            engine_id,
            next_sequence: 1,
            audit: ValidationAuditChain::new(audit_genesis)?,
        })
    }

    pub fn generate(
        &mut self,
        plan: &RequestIntentPlan,
        capability: &CapabilityUseReceipt,
        target: MutationTarget,
        template: &MutationTemplate,
        kind: MutationKind,
        ordinal: u32,
    ) -> Result<SafeMutation, ValidationError> {
        if plan.risk_class != RiskClass::SafeActive
            || !plan.active_execution_allowed
            || capability.endpoint_sha256 != plan.canonical_url_sha256
            || capability.mutations_used == 0
            || ordinal >= template.maximum_variants
            || !template.allowed_kinds.contains(&kind)
            || !template.allowed_locations.contains(&target.location)
            || !plan.parameter_names.contains(&target.name)
        {
            return Err(ValidationError::MutationDenied);
        }
        let plan_fingerprint = plan.fingerprint();
        let seed = hash_serializable(&(
            &self.engine_id,
            self.next_sequence,
            &plan_fingerprint,
            &capability.capability_id,
            &target.name_sha256,
            kind,
            ordinal,
        ))?;
        let value = render_inert_value(kind, target.value_class, &seed, template.maximum_output_bytes)?;
        let mutation_id = format!("mutation-{:020}", self.next_sequence);
        self.next_sequence = self.next_sequence.saturating_add(1);
        let mutation = SafeMutation {
            mutation_id: mutation_id.clone(),
            endpoint_sha256: plan.canonical_url_sha256.clone(),
            plan_fingerprint,
            capability_id: capability.capability_id.clone(),
            target,
            kind,
            value_sha256: hash_bytes(&value),
            value_bytes: value.len(),
            value,
        };
        self.audit.append(ValidationAuditEvent {
            action: "mutation_generated".into(),
            subject_id: mutation_id,
            outcome: "inert_marker_ready".into(),
            metadata: BTreeMap::from([
                ("endpoint_sha256".into(), mutation.endpoint_sha256.clone()),
                ("value_sha256".into(), mutation.value_sha256.clone()),
                ("value_bytes".into(), mutation.value_bytes.to_string()),
            ]),
        })?;
        Ok(mutation)
    }

    pub fn audit(&self) -> &ValidationAuditChain {
        &self.audit
    }
}

fn render_inert_value(
    kind: MutationKind,
    value_class: ValueClass,
    seed: &str,
    maximum_output_bytes: usize,
) -> Result<Vec<u8>, ValidationError> {
    let marker = format!("nxb_{}", &seed[..16]);
    let text = match kind {
        MutationKind::ReplaceWithMarker | MutationKind::AppendMarker => marker,
        MutationKind::EmptyValue => String::new(),
        MutationKind::TypePreservingMarker => match value_class {
            ValueClass::Integer => {
                let number = u64::from_str_radix(&seed[..12], 16).unwrap_or(1) % 1_000_000;
                number.to_string()
            }
            ValueClass::Boolean => {
                if seed.as_bytes()[0].is_multiple_of(2) {
                    "true".into()
                } else {
                    "false".into()
                }
            }
            ValueClass::Text | ValueClass::Opaque => marker,
        },
        MutationKind::BoundedBoundary => {
            let requested = maximum_output_bytes.min(256);
            marker.chars().cycle().take(requested).collect()
        }
    };
    if text.len() > maximum_output_bytes || text.len() > MAX_MUTATION_VALUE_BYTES {
        return Err(ValidationError::InvalidMutation(
            "rendered marker exceeds bounds".into(),
        ));
    }
    let lower = text.to_ascii_lowercase();
    for forbidden in [
        "<script",
        "javascript:",
        "union select",
        "../",
        "${jndi:",
        "http://",
        "https://",
        "cmd.exe",
        "/bin/sh",
    ] {
        if lower.contains(forbidden) {
            return Err(ValidationError::InvalidMutation(
                "rendered marker is not inert".into(),
            ));
        }
    }
    Ok(text.into_bytes())
}
