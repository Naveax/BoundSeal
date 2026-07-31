impl AssuranceCoverageMatrix {
    pub fn new(
        policy_snapshot_sha256: impl Into<String>,
        requirements: Vec<AssuranceRequirement>,
        evidence: Vec<CoverageEvidence>,
    ) -> Result<Self, AssuranceError> {
        let policy_snapshot_sha256 = policy_snapshot_sha256.into();
        validate_sha256(&policy_snapshot_sha256, "coverage policy")?;
        if requirements.is_empty() || requirements.len() > MAX_ASSURANCE_REQUIREMENTS {
            return Err(AssuranceError::ClosureDenied(
                "assurance requirement count".into(),
            ));
        }
        let mut requirement_map = BTreeMap::new();
        for requirement in requirements {
            requirement.verify()?;
            if requirement_map
                .insert(requirement.requirement_id.clone(), requirement)
                .is_some()
            {
                return Err(AssuranceError::ClosureDenied(
                    "duplicate assurance requirement".into(),
                ));
            }
        }
        let mut evidence_map: BTreeMap<String, Vec<CoverageEvidence>> = BTreeMap::new();
        let mut evidence_ids = BTreeSet::new();
        for item in evidence {
            item.verify()?;
            if !requirement_map.contains_key(&item.requirement_id)
                || !evidence_ids.insert(item.evidence_id.clone())
            {
                return Err(AssuranceError::ClosureDenied(
                    "unknown requirement or duplicate evidence".into(),
                ));
            }
            evidence_map
                .entry(item.requirement_id.clone())
                .or_default()
                .push(item);
        }
        if requirement_map.values().filter(|r| r.mandatory).any(|r| {
            evidence_map
                .get(&r.requirement_id)
                .is_none_or(Vec::is_empty)
        }) {
            return Err(AssuranceError::ClosureDenied(
                "mandatory assurance coverage is incomplete".into(),
            ));
        }
        let matrix_sha256 =
            hash_serializable(&(&policy_snapshot_sha256, &requirement_map, &evidence_map))?;
        Ok(Self {
            policy_snapshot_sha256,
            requirements: requirement_map,
            evidence: evidence_map,
            matrix_sha256,
        })
    }
    pub fn verify(&self) -> Result<(), AssuranceError> {
        for r in self.requirements.values() {
            r.verify()?;
        }
        for e in self.evidence.values().flatten() {
            e.verify()?;
        }
        let expected = hash_serializable(&(
            &self.policy_snapshot_sha256,
            &self.requirements,
            &self.evidence,
        ))?;
        if expected != self.matrix_sha256
            || self.requirements.values().filter(|r| r.mandatory).any(|r| {
                self.evidence
                    .get(&r.requirement_id)
                    .is_none_or(Vec::is_empty)
            })
        {
            return Err(AssuranceError::ClosureDenied(
                "assurance matrix digest or coverage".into(),
            ));
        }
        Ok(())
    }
}
