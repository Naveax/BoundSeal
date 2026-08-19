#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OracleResult {
    pub oracle_id: String,
    pub candidate_id: String,
    pub mutation_id: String,
    pub decision: OracleDecision,
    pub baseline_sample_count: usize,
    pub mutated_sample_count: usize,
    pub repeatable_delta_sha256: Option<String>,
    pub material_change_count: u8,
    pub evidence_sha256: String,
    pub audit_tail_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatedFinding {
    pub finding_id: String,
    pub candidate_id: String,
    pub rule_id: String,
    pub origin: String,
    pub endpoint_sha256: String,
    pub mutation_id: String,
    pub oracle_evidence_sha256: String,
    pub repeatable_delta_sha256: String,
    pub state: PromotionState,
    pub summary: String,
}

#[derive(Debug)]
pub struct DifferentialOracle {
    oracle_id: String,
    limits: DifferentialLimits,
    audit: ValidationAuditChain,
}

impl DifferentialOracle {
    pub fn new(
        oracle_id: impl Into<String>,
        limits: DifferentialLimits,
        audit_genesis: impl Into<String>,
    ) -> Result<Self, ValidationError> {
        let oracle_id = oracle_id.into();
        validate_identifier(&oracle_id, "oracle_id")?;
        if limits.minimum_material_changes == 0
            || limits.maximum_body_size_delta > MAX_SAMPLE_BODY_BYTES
            || limits.maximum_timing_delta_milliseconds > 10 * 60 * 1000
        {
            return Err(ValidationError::InvalidOracleInput(
                "oracle limits".into(),
            ));
        }
        Ok(Self {
            oracle_id,
            limits,
            audit: ValidationAuditChain::new(audit_genesis)?,
        })
    }

    pub fn evaluate(
        &mut self,
        candidate_id: impl Into<String>,
        mutation: &MutationReceipt,
        baselines: &[DifferentialSample],
        mutated: &[DifferentialSample],
    ) -> Result<OracleResult, ValidationError> {
        let candidate_id = candidate_id.into();
        validate_identifier(&candidate_id, "candidate_id")?;
        if baselines.len() < 2
            || mutated.len() < 2
            || baselines.len() > MAX_DIFFERENTIAL_SAMPLES
            || mutated.len() > MAX_DIFFERENTIAL_SAMPLES
            || baselines.len() != mutated.len()
        {
            return Err(ValidationError::InvalidOracleInput(
                "two or more paired samples are required".into(),
            ));
        }
        let baseline_fingerprints = baselines
            .iter()
            .map(DifferentialSample::fingerprint)
            .collect::<Result<BTreeSet<_>, _>>()?;
        if baseline_fingerprints.len() != 1 {
            return Err(ValidationError::InvalidOracleInput(
                "baseline is not repeatable".into(),
            ));
        }
        let mut deltas = Vec::with_capacity(baselines.len());
        for (baseline, mutated_sample) in baselines.iter().zip(mutated) {
            if baseline.endpoint_sha256 != mutation.endpoint_sha256
                || mutated_sample.endpoint_sha256 != mutation.endpoint_sha256
                || mutated_sample.mutation_id.as_deref() != Some(mutation.mutation_id.as_str())
            {
                return Err(ValidationError::InvalidOracleInput(
                    "sample does not bind to mutation".into(),
                ));
            }
            deltas.push(compare_samples(baseline, mutated_sample, &self.limits)?);
        }
        let repeatable = deltas
            .iter()
            .map(|delta| delta.delta_fingerprint_sha256.clone())
            .collect::<BTreeSet<_>>();
        let material_change_count = deltas
            .iter()
            .map(DifferentialDelta::material_change_count)
            .min()
            .unwrap_or_default();
        let decision = if repeatable.len() == 1
            && material_change_count >= self.limits.minimum_material_changes
        {
            OracleDecision::Confirmed
        } else if material_change_count == 0 {
            OracleDecision::Rejected
        } else {
            OracleDecision::Inconclusive
        };
        let repeatable_delta_sha256 = if repeatable.len() == 1 {
            repeatable.iter().next().cloned()
        } else {
            None
        };
        let evidence_sha256 = hash_serializable(&(
            &candidate_id,
            &mutation.mutation_id,
            &baseline_fingerprints,
            &deltas,
            decision,
        ))?;
        self.audit.append(ValidationAuditEvent {
            action: "oracle_evaluated".into(),
            subject_id: candidate_id.clone(),
            outcome: format!("{decision:?}").to_ascii_lowercase(),
            metadata: BTreeMap::from([
                ("mutation_id".into(), mutation.mutation_id.clone()),
                ("evidence_sha256".into(), evidence_sha256.clone()),
                (
                    "material_change_count".into(),
                    material_change_count.to_string(),
                ),
            ]),
        })?;
        Ok(OracleResult {
            oracle_id: self.oracle_id.clone(),
            candidate_id,
            mutation_id: mutation.mutation_id.clone(),
            decision,
            baseline_sample_count: baselines.len(),
            mutated_sample_count: mutated.len(),
            repeatable_delta_sha256,
            material_change_count,
            evidence_sha256,
            audit_tail_hash: self.audit.tail_hash().into(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn promote(
        &mut self,
        result: &OracleResult,
        rule_id: impl Into<String>,
        origin: impl Into<String>,
        endpoint_sha256: impl Into<String>,
        summary: impl Into<String>,
    ) -> Result<ValidatedFinding, ValidationError> {
        if result.decision != OracleDecision::Confirmed {
            return Err(ValidationError::InvalidOracleInput(
                "only confirmed oracle results can be promoted".into(),
            ));
        }
        let rule_id = rule_id.into();
        let origin = origin.into();
        let endpoint_sha256 = endpoint_sha256.into();
        let summary = summary.into();
        validate_identifier(&rule_id, "rule_id")?;
        validate_sha256(&endpoint_sha256, "finding endpoint")?;
        if origin.is_empty()
            || origin.len() > 512
            || summary.is_empty()
            || summary.len() > 2048
            || summary.bytes().any(|byte| byte == 0)
        {
            return Err(ValidationError::InvalidOracleInput(
                "finding origin or summary".into(),
            ));
        }
        let repeatable_delta_sha256 = result
            .repeatable_delta_sha256
            .clone()
            .ok_or_else(|| ValidationError::InvalidOracleInput("missing repeatable delta".into()))?;
        let finding_id = format!(
            "validated-{}",
            &hash_serializable(&(
                &result.candidate_id,
                &rule_id,
                &origin,
                &endpoint_sha256,
                &result.evidence_sha256,
            ))?[..24]
        );
        self.audit.append(ValidationAuditEvent {
            action: "finding_promoted".into(),
            subject_id: finding_id.clone(),
            outcome: "validated".into(),
            metadata: BTreeMap::from([(
                "oracle_evidence_sha256".into(),
                result.evidence_sha256.clone(),
            )]),
        })?;
        Ok(ValidatedFinding {
            finding_id,
            candidate_id: result.candidate_id.clone(),
            rule_id,
            origin,
            endpoint_sha256,
            mutation_id: result.mutation_id.clone(),
            oracle_evidence_sha256: result.evidence_sha256.clone(),
            repeatable_delta_sha256,
            state: PromotionState::Validated,
            summary,
        })
    }

    pub fn audit(&self) -> &ValidationAuditChain {
        &self.audit
    }
}
