impl IndependentVerificationQuorum {
    pub fn new(
        receipts: &[IndependentVerificationReceipt],
        required_quorum: usize,
    ) -> Result<Self, LifecycleError> {
        if required_quorum < 3
            || receipts.len() < required_quorum
            || receipts.len() > MAX_VERIFIERS
        {
            return Err(LifecycleError::InvalidClosure(
                "independent verification quorum count".into(),
            ));
        }
        for receipt in receipts {
            receipt.verify()?;
        }
        let first = receipts
            .first()
            .ok_or_else(|| LifecycleError::InvalidClosure("missing verifier receipt".into()))?;
        let verifier_manifest_sha256 = receipts
            .iter()
            .map(|receipt| receipt.verifier_manifest_sha256.clone())
            .collect::<BTreeSet<_>>();
        let organization_roots = receipts
            .iter()
            .map(|receipt| receipt.organization_root_sha256.clone())
            .collect::<BTreeSet<_>>();
        let implementation_roots = receipts
            .iter()
            .map(|receipt| receipt.implementation_root_sha256.clone())
            .collect::<BTreeSet<_>>();
        let receipt_sha256 = receipts
            .iter()
            .map(|receipt| receipt.receipt_sha256.clone())
            .collect::<BTreeSet<_>>();
        if verifier_manifest_sha256.len() != receipts.len()
            || organization_roots.len() != receipts.len()
            || implementation_roots.len() != receipts.len()
            || receipt_sha256.len() != receipts.len()
            || receipts.iter().any(|receipt| {
                receipt.sample_plan_sha256 != first.sample_plan_sha256
                    || receipt.result_root_sha256 != first.result_root_sha256
                    || receipt.finding_count != 0
                    || receipt.external_io_observed
            })
        {
            return Err(LifecycleError::InvalidClosure(
                "independent verifier diversity or result mismatch".into(),
            ));
        }
        let quorum_sha256 = hash_serializable(&(
            &first.sample_plan_sha256,
            &first.result_root_sha256,
            &verifier_manifest_sha256,
            &organization_roots,
            &implementation_roots,
            &receipt_sha256,
            required_quorum,
        ))?;
        Ok(Self {
            sample_plan_sha256: first.sample_plan_sha256.clone(),
            result_root_sha256: first.result_root_sha256.clone(),
            verifier_manifest_sha256,
            organization_roots,
            implementation_roots,
            receipt_sha256,
            quorum: required_quorum,
            quorum_sha256,
        })
    }

    pub fn verify(&self) -> Result<(), LifecycleError> {
        for (name, value) in [
            ("verification sample plan", self.sample_plan_sha256.as_str()),
            ("verification result", self.result_root_sha256.as_str()),
            ("verification quorum", self.quorum_sha256.as_str()),
        ] {
            validate_sha256(value, name)?;
        }
        let receipt_count = self.receipt_sha256.len();
        if self.quorum < 3
            || receipt_count < self.quorum
            || receipt_count > MAX_VERIFIERS
            || self.verifier_manifest_sha256.len() != receipt_count
            || self.organization_roots.len() != receipt_count
            || self.implementation_roots.len() != receipt_count
            || self
                .verifier_manifest_sha256
                .iter()
                .chain(self.organization_roots.iter())
                .chain(self.implementation_roots.iter())
                .chain(self.receipt_sha256.iter())
                .any(|root| validate_sha256(root, "independent verifier quorum root").is_err())
        {
            return Err(LifecycleError::InvalidClosure(
                "independent verification quorum diversity".into(),
            ));
        }
        let expected = hash_serializable(&(
            &self.sample_plan_sha256,
            &self.result_root_sha256,
            &self.verifier_manifest_sha256,
            &self.organization_roots,
            &self.implementation_roots,
            &self.receipt_sha256,
            self.quorum,
        ))?;
        if expected != self.quorum_sha256 {
            return Err(LifecycleError::InvalidClosure(
                "independent verification quorum digest".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum DecommissionStep {
    FreezeIntake,
    RevokeGrants,
    PurgeSecrets,
    ArchiveMetadata,
    VerifyTombstone,
    SealLifecycle,
}

fn canonical_decommission_steps() -> Vec<DecommissionStep> {
    vec![
        DecommissionStep::FreezeIntake,
        DecommissionStep::RevokeGrants,
        DecommissionStep::PurgeSecrets,
        DecommissionStep::ArchiveMetadata,
        DecommissionStep::VerifyTombstone,
        DecommissionStep::SealLifecycle,
    ]
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecommissionPlan {
    pub plan_id: String,
    pub policy_snapshot_sha256: String,
    pub final_assurance_certificate_sha256: String,
    pub roadmap_closure_sha256: String,
    pub maintenance_release_certificate_sha256: String,
    pub continuity_certificate_sha256: String,
    pub ordered_steps: Vec<DecommissionStep>,
    pub plan_sha256: String,
}
