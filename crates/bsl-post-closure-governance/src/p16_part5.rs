#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CutoverReceipt {
    pub receipt_id: String,
    pub plan_sha256: String,
    pub step_receipts: BTreeMap<CutoverStep, String>,
    pub completed_tick: u64,
    pub unresolved_object_count: u64,
    pub rollback_verified: bool,
    pub receipt_sha256: String,
}

impl CutoverReceipt {
    pub fn new(
        receipt_id: impl Into<String>,
        plan: &CutoverPlan,
        step_receipts: BTreeMap<CutoverStep, String>,
        completed_tick: u64,
        unresolved_object_count: u64,
        rollback_verified: bool,
    ) -> Result<Self, PostClosureError> {
        plan.verify()?;
        let receipt_id = receipt_id.into();
        validate_identifier(&receipt_id, "cutover receipt")?;
        let expected_steps = canonical_cutover_steps()
            .into_iter()
            .collect::<BTreeSet<_>>();
        let actual_steps = step_receipts.keys().copied().collect::<BTreeSet<_>>();
        if actual_steps != expected_steps
            || step_receipts
                .values()
                .any(|receipt| validate_sha256(receipt, "cutover step receipt").is_err())
            || completed_tick < plan.start_tick
            || completed_tick > plan.end_tick
            || unresolved_object_count != 0
            || !rollback_verified
        {
            return Err(PostClosureError::InvalidSuccession(
                "cutover receipt closure".into(),
            ));
        }
        let plan_sha256 = plan.plan_sha256.clone();
        let receipt_sha256 = hash_serializable(&(
            &receipt_id,
            &plan_sha256,
            &step_receipts,
            completed_tick,
            unresolved_object_count,
            rollback_verified,
        ))?;
        Ok(Self {
            receipt_id,
            plan_sha256,
            step_receipts,
            completed_tick,
            unresolved_object_count,
            rollback_verified,
            receipt_sha256,
        })
    }

    pub fn verify(&self) -> Result<(), PostClosureError> {
        validate_identifier(&self.receipt_id, "cutover receipt")?;
        validate_sha256(&self.plan_sha256, "cutover receipt plan")?;
        let expected_steps = canonical_cutover_steps()
            .into_iter()
            .collect::<BTreeSet<_>>();
        if self.step_receipts.keys().copied().collect::<BTreeSet<_>>() != expected_steps
            || self
                .step_receipts
                .values()
                .any(|receipt| validate_sha256(receipt, "cutover step receipt").is_err())
            || self.unresolved_object_count != 0
            || !self.rollback_verified
        {
            return Err(PostClosureError::InvalidSuccession(
                "cutover receipt closure".into(),
            ));
        }
        let expected = hash_serializable(&(
            &self.receipt_id,
            &self.plan_sha256,
            &self.step_receipts,
            self.completed_tick,
            self.unresolved_object_count,
            self.rollback_verified,
        ))?;
        if expected != self.receipt_sha256 {
            return Err(PostClosureError::InvalidSuccession(
                "cutover receipt digest".into(),
            ));
        }
        Ok(())
    }
}
