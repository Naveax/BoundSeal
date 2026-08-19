#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReviewAssignment {
    pub evidence_id: String,
    pub reviewer_ids: BTreeSet<String>,
    pub assignment_sha256: String,
}

impl ReviewAssignment {
    pub fn new(
        evidence_id: impl Into<String>,
        reviewer_ids: BTreeSet<String>,
    ) -> Result<Self, PostClosureError> {
        let evidence_id = evidence_id.into();
        validate_identifier(&evidence_id, "review evidence id")?;
        if reviewer_ids.len() < 2 || reviewer_ids.len() > MAX_REVIEWERS {
            return Err(PostClosureError::InvalidRenewal(
                "review assignment cardinality".into(),
            ));
        }
        for reviewer_id in &reviewer_ids {
            validate_identifier(reviewer_id, "review assignment reviewer")?;
        }
        let assignment_sha256 = hash_serializable(&(&evidence_id, &reviewer_ids))?;
        Ok(Self {
            evidence_id,
            reviewer_ids,
            assignment_sha256,
        })
    }

    pub fn verify(&self) -> Result<(), PostClosureError> {
        validate_identifier(&self.evidence_id, "review evidence id")?;
        if self.reviewer_ids.len() < 2 || self.reviewer_ids.len() > MAX_REVIEWERS {
            return Err(PostClosureError::InvalidRenewal(
                "review assignment cardinality".into(),
            ));
        }
        for reviewer_id in &self.reviewer_ids {
            validate_identifier(reviewer_id, "review assignment reviewer")?;
        }
        let expected = hash_serializable(&(&self.evidence_id, &self.reviewer_ids))?;
        if expected != self.assignment_sha256 {
            return Err(PostClosureError::InvalidRenewal(
                "review assignment digest".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReviewAssignmentMatrix {
    pub matrix_id: String,
    pub panel_sha256: String,
    pub sample_plan_sha256: String,
    pub assignments: BTreeMap<String, ReviewAssignment>,
    pub matrix_sha256: String,
}

impl ReviewAssignmentMatrix {
    pub fn new(
        matrix_id: impl Into<String>,
        panel: &ReviewPanel,
        sample_plan: &EvidenceSamplePlan,
        assignments: Vec<ReviewAssignment>,
    ) -> Result<Self, PostClosureError> {
        panel.verify()?;
        sample_plan.verify()?;
        let matrix_id = matrix_id.into();
        validate_identifier(&matrix_id, "review assignment matrix")?;
        let mut by_evidence = BTreeMap::new();
        for assignment in assignments {
            assignment.verify()?;
            if !sample_plan.sample_ids.contains(&assignment.evidence_id)
                || !assignment
                    .reviewer_ids
                    .iter()
                    .all(|reviewer| panel.members.contains_key(reviewer))
            {
                return Err(PostClosureError::InvalidRenewal(
                    "review assignment references".into(),
                ));
            }
            let organizations = assignment
                .reviewer_ids
                .iter()
                .map(|id| panel.members[id].organization_root_sha256.clone())
                .collect::<BTreeSet<_>>();
            if organizations.len() < 2 {
                return Err(PostClosureError::InvalidRenewal(
                    "review assignment organization diversity".into(),
                ));
            }
            if by_evidence
                .insert(assignment.evidence_id.clone(), assignment)
                .is_some()
            {
                return Err(PostClosureError::InvalidRenewal(
                    "duplicate evidence assignment".into(),
                ));
            }
        }
        if by_evidence.keys().cloned().collect::<BTreeSet<_>>() != sample_plan.sample_ids {
            return Err(PostClosureError::InvalidRenewal(
                "review assignment sample coverage".into(),
            ));
        }
        let panel_sha256 = panel.panel_sha256.clone();
        let sample_plan_sha256 = sample_plan.plan_sha256.clone();
        let matrix_sha256 =
            hash_serializable(&(&matrix_id, &panel_sha256, &sample_plan_sha256, &by_evidence))?;
        Ok(Self {
            matrix_id,
            panel_sha256,
            sample_plan_sha256,
            assignments: by_evidence,
            matrix_sha256,
        })
    }

    pub fn verify(&self) -> Result<(), PostClosureError> {
        validate_identifier(&self.matrix_id, "review assignment matrix")?;
        validate_sha256(&self.panel_sha256, "assignment panel")?;
        validate_sha256(&self.sample_plan_sha256, "assignment sample plan")?;
        if self.assignments.is_empty() || self.assignments.len() > MAX_SAMPLE_COUNT {
            return Err(PostClosureError::InvalidRenewal(
                "review assignment matrix cardinality".into(),
            ));
        }
        for (key, assignment) in &self.assignments {
            assignment.verify()?;
            if key != &assignment.evidence_id {
                return Err(PostClosureError::InvalidRenewal(
                    "review assignment matrix key".into(),
                ));
            }
        }
        let expected = hash_serializable(&(
            &self.matrix_id,
            &self.panel_sha256,
            &self.sample_plan_sha256,
            &self.assignments,
        ))?;
        if expected != self.matrix_sha256 {
            return Err(PostClosureError::InvalidRenewal(
                "review assignment matrix digest".into(),
            ));
        }
        Ok(())
    }
}
