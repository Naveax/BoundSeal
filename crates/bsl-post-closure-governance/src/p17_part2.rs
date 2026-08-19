#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceSamplePlan {
    pub plan_id: String,
    pub succession_certificate_sha256: String,
    pub evidence_roots: BTreeMap<String, String>,
    pub seed_sha256: String,
    pub sample_ids: BTreeSet<String>,
    pub plan_sha256: String,
}

impl EvidenceSamplePlan {
    pub fn new(
        plan_id: impl Into<String>,
        succession: &SuccessionCertificate,
        evidence_roots: BTreeMap<String, String>,
        seed_sha256: impl Into<String>,
        sample_count: usize,
    ) -> Result<Self, PostClosureError> {
        succession.verify()?;
        let plan_id = plan_id.into();
        let seed_sha256 = seed_sha256.into();
        validate_identifier(&plan_id, "evidence sample plan")?;
        validate_sha256(&seed_sha256, "evidence sample seed")?;
        if evidence_roots.is_empty()
            || evidence_roots.len() > MAX_EVIDENCE_ROOTS
            || sample_count == 0
            || sample_count > evidence_roots.len()
            || sample_count > MAX_SAMPLE_COUNT
        {
            return Err(PostClosureError::InvalidRenewal(
                "evidence sample cardinality".into(),
            ));
        }
        for (id, root) in &evidence_roots {
            validate_identifier(id, "evidence id")?;
            validate_sha256(root, "evidence root")?;
        }
        let mut ranked = evidence_roots
            .iter()
            .map(|(id, root)| {
                hash_serializable(&(&seed_sha256, id, root)).map(|rank| (rank, id.clone()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        ranked.sort();
        let sample_ids = ranked
            .into_iter()
            .take(sample_count)
            .map(|(_, id)| id)
            .collect::<BTreeSet<_>>();
        let succession_certificate_sha256 = succession.certificate_sha256.clone();
        let plan_sha256 = hash_serializable(&(
            &plan_id,
            &succession_certificate_sha256,
            &evidence_roots,
            &seed_sha256,
            &sample_ids,
        ))?;
        Ok(Self {
            plan_id,
            succession_certificate_sha256,
            evidence_roots,
            seed_sha256,
            sample_ids,
            plan_sha256,
        })
    }

    pub fn verify(&self) -> Result<(), PostClosureError> {
        validate_identifier(&self.plan_id, "evidence sample plan")?;
        validate_sha256(
            &self.succession_certificate_sha256,
            "sample succession certificate",
        )?;
        validate_sha256(&self.seed_sha256, "evidence sample seed")?;
        if self.evidence_roots.is_empty()
            || self.evidence_roots.len() > MAX_EVIDENCE_ROOTS
            || self.sample_ids.is_empty()
            || self.sample_ids.len() > self.evidence_roots.len()
            || self.sample_ids.len() > MAX_SAMPLE_COUNT
        {
            return Err(PostClosureError::InvalidRenewal(
                "evidence sample cardinality".into(),
            ));
        }
        for (id, root) in &self.evidence_roots {
            validate_identifier(id, "evidence id")?;
            validate_sha256(root, "evidence root")?;
        }
        if !self
            .sample_ids
            .iter()
            .all(|id| self.evidence_roots.contains_key(id))
        {
            return Err(PostClosureError::InvalidRenewal(
                "sample contains unknown evidence".into(),
            ));
        }
        let mut ranked = self
            .evidence_roots
            .iter()
            .map(|(id, root)| {
                hash_serializable(&(&self.seed_sha256, id, root)).map(|rank| (rank, id.clone()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        ranked.sort();
        let expected_samples = ranked
            .into_iter()
            .take(self.sample_ids.len())
            .map(|(_, id)| id)
            .collect::<BTreeSet<_>>();
        let expected = hash_serializable(&(
            &self.plan_id,
            &self.succession_certificate_sha256,
            &self.evidence_roots,
            &self.seed_sha256,
            &self.sample_ids,
        ))?;
        if expected_samples != self.sample_ids || expected != self.plan_sha256 {
            return Err(PostClosureError::InvalidRenewal(
                "evidence sample selection or digest".into(),
            ));
        }
        Ok(())
    }
}
