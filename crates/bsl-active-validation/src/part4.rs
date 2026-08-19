#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DifferentialSample {
    pub sample_id: String,
    pub endpoint_sha256: String,
    pub mutation_id: Option<String>,
    pub status: u16,
    pub header_fingerprint_sha256: String,
    pub body_sha256: String,
    pub body_bytes: u64,
    pub semantic_tokens: BTreeSet<String>,
    pub elapsed_milliseconds: u64,
    pub session_generation: u64,
    pub audit_anchor: String,
}

impl DifferentialSample {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sample_id: impl Into<String>,
        endpoint_sha256: impl Into<String>,
        mutation_id: Option<String>,
        status: u16,
        header_fingerprint_sha256: impl Into<String>,
        body_sha256: impl Into<String>,
        body_bytes: u64,
        semantic_tokens: BTreeSet<String>,
        elapsed_milliseconds: u64,
        session_generation: u64,
        audit_anchor: impl Into<String>,
    ) -> Result<Self, ValidationError> {
        let sample_id = sample_id.into();
        validate_identifier(&sample_id, "sample_id")?;
        if let Some(value) = mutation_id.as_deref() {
            validate_identifier(value, "mutation_id")?;
        }
        let endpoint_sha256 = endpoint_sha256.into();
        let header_fingerprint_sha256 = header_fingerprint_sha256.into();
        let body_sha256 = body_sha256.into();
        let audit_anchor = audit_anchor.into();
        for (name, value) in [
            ("endpoint", &endpoint_sha256),
            ("headers", &header_fingerprint_sha256),
            ("body", &body_sha256),
            ("audit anchor", &audit_anchor),
        ] {
            validate_sha256(value, name)?;
        }
        if !(100..=599).contains(&status)
            || body_bytes > MAX_SAMPLE_BODY_BYTES
            || semantic_tokens.len() > MAX_SEMANTIC_TOKENS
            || semantic_tokens.iter().any(|token| {
                token.is_empty()
                    || token.len() > 256
                    || token.bytes().any(|byte| byte.is_ascii_control())
            })
            || elapsed_milliseconds > 10 * 60 * 1000
        {
            return Err(ValidationError::InvalidSample(
                "sample bounds or response metadata".into(),
            ));
        }
        Ok(Self {
            sample_id,
            endpoint_sha256,
            mutation_id,
            status,
            header_fingerprint_sha256,
            body_sha256,
            body_bytes,
            semantic_tokens,
            elapsed_milliseconds,
            session_generation,
            audit_anchor,
        })
    }

    pub fn fingerprint(&self) -> Result<String, ValidationError> {
        hash_serializable(&(
            &self.endpoint_sha256,
            self.status,
            &self.header_fingerprint_sha256,
            &self.body_sha256,
            self.body_bytes,
            &self.semantic_tokens,
            self.session_generation,
        ))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DifferentialDelta {
    pub status_changed: bool,
    pub headers_changed: bool,
    pub body_changed: bool,
    pub body_size_delta: i128,
    pub added_tokens: BTreeSet<String>,
    pub removed_tokens: BTreeSet<String>,
    pub elapsed_delta_milliseconds: i128,
    pub session_generation_changed: bool,
    pub delta_fingerprint_sha256: String,
}

impl DifferentialDelta {
    pub fn material_change_count(&self) -> u8 {
        [
            self.status_changed,
            self.headers_changed,
            self.body_changed,
            !self.added_tokens.is_empty(),
            !self.removed_tokens.is_empty(),
            self.session_generation_changed,
        ]
        .into_iter()
        .filter(|changed| *changed)
        .count() as u8
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DifferentialLimits {
    pub maximum_body_size_delta: u64,
    pub maximum_timing_delta_milliseconds: u64,
    pub minimum_material_changes: u8,
}

impl Default for DifferentialLimits {
    fn default() -> Self {
        Self {
            maximum_body_size_delta: 32 * 1024 * 1024,
            maximum_timing_delta_milliseconds: 30_000,
            minimum_material_changes: 1,
        }
    }
}

pub fn compare_samples(
    baseline: &DifferentialSample,
    mutated: &DifferentialSample,
    limits: &DifferentialLimits,
) -> Result<DifferentialDelta, ValidationError> {
    if baseline.endpoint_sha256 != mutated.endpoint_sha256
        || baseline.mutation_id.is_some()
        || mutated.mutation_id.is_none()
        || limits.maximum_body_size_delta > MAX_SAMPLE_BODY_BYTES
        || limits.maximum_timing_delta_milliseconds > 10 * 60 * 1000
        || limits.minimum_material_changes == 0
    {
        return Err(ValidationError::InvalidSample(
            "baseline/mutated binding or limits".into(),
        ));
    }
    let body_size_delta = i128::from(mutated.body_bytes) - i128::from(baseline.body_bytes);
    if body_size_delta.unsigned_abs() > u128::from(limits.maximum_body_size_delta) {
        return Err(ValidationError::InvalidSample(
            "body-size delta exceeds configured bound".into(),
        ));
    }
    let elapsed_delta_milliseconds =
        i128::from(mutated.elapsed_milliseconds) - i128::from(baseline.elapsed_milliseconds);
    if elapsed_delta_milliseconds.unsigned_abs()
        > u128::from(limits.maximum_timing_delta_milliseconds)
    {
        return Err(ValidationError::InvalidSample(
            "timing delta exceeds configured bound".into(),
        ));
    }
    let added_tokens = mutated
        .semantic_tokens
        .difference(&baseline.semantic_tokens)
        .cloned()
        .collect::<BTreeSet<_>>();
    let removed_tokens = baseline
        .semantic_tokens
        .difference(&mutated.semantic_tokens)
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut delta = DifferentialDelta {
        status_changed: baseline.status != mutated.status,
        headers_changed: baseline.header_fingerprint_sha256
            != mutated.header_fingerprint_sha256,
        body_changed: baseline.body_sha256 != mutated.body_sha256,
        body_size_delta,
        added_tokens,
        removed_tokens,
        elapsed_delta_milliseconds,
        session_generation_changed: baseline.session_generation != mutated.session_generation,
        delta_fingerprint_sha256: String::new(),
    };
    delta.delta_fingerprint_sha256 = hash_serializable(&(
        delta.status_changed,
        delta.headers_changed,
        delta.body_changed,
        delta.body_size_delta,
        &delta.added_tokens,
        &delta.removed_tokens,
        delta.session_generation_changed,
    ))?;
    Ok(delta)
}
