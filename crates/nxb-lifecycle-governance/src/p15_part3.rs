impl IndependentVerificationReceipt {
    pub fn new(
        receipt_id: impl Into<String>,
        verifier: &IndependentVerifierManifest,
        sample_plan: &EvidenceSamplePlan,
        result_root_sha256: impl Into<String>,
        finding_count: u32,
        external_io_observed: bool,
    ) -> Result<Self, LifecycleError> {
        verifier.verify()?;
        sample_plan.verify()?;
        let receipt_id = receipt_id.into();
        let result_root_sha256 = result_root_sha256.into();
        validate_identifier(&receipt_id, "verification receipt")?;
        validate_sha256(&result_root_sha256, "verification result")?;
        if finding_count != 0 || external_io_observed {
            return Err(LifecycleError::InvalidClosure(
                "independent verification found drift or external I/O".into(),
            ));
        }
        let verifier_manifest_sha256 = verifier.manifest_sha256.clone();
        let organization_root_sha256 = verifier.organization_root_sha256.clone();
        let implementation_root_sha256 = verifier.implementation_root_sha256.clone();
        let sample_plan_sha256 = sample_plan.plan_sha256.clone();
        let receipt_sha256 = hash_serializable(&(
            &receipt_id,
            &verifier_manifest_sha256,
            &organization_root_sha256,
            &implementation_root_sha256,
            &sample_plan_sha256,
            &result_root_sha256,
            finding_count,
            external_io_observed,
        ))?;
        Ok(Self {
            receipt_id,
            verifier_manifest_sha256,
            organization_root_sha256,
            implementation_root_sha256,
            sample_plan_sha256,
            result_root_sha256,
            finding_count,
            external_io_observed,
            receipt_sha256,
        })
    }

    pub fn verify(&self) -> Result<(), LifecycleError> {
        validate_identifier(&self.receipt_id, "verification receipt")?;
        for (name, value) in [
            (
                "verification manifest",
                self.verifier_manifest_sha256.as_str(),
            ),
            (
                "verification organization",
                self.organization_root_sha256.as_str(),
            ),
            (
                "verification implementation",
                self.implementation_root_sha256.as_str(),
            ),
            ("verification sample plan", self.sample_plan_sha256.as_str()),
            ("verification result", self.result_root_sha256.as_str()),
            ("verification receipt", self.receipt_sha256.as_str()),
        ] {
            validate_sha256(value, name)?;
        }
        if self.finding_count != 0 || self.external_io_observed {
            return Err(LifecycleError::InvalidClosure(
                "verification receipt safety closure".into(),
            ));
        }
        let expected = hash_serializable(&(
            &self.receipt_id,
            &self.verifier_manifest_sha256,
            &self.organization_root_sha256,
            &self.implementation_root_sha256,
            &self.sample_plan_sha256,
            &self.result_root_sha256,
            self.finding_count,
            self.external_io_observed,
        ))?;
        if expected != self.receipt_sha256 {
            return Err(LifecycleError::InvalidClosure(
                "verification receipt digest".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IndependentVerificationQuorum {
    pub sample_plan_sha256: String,
    pub result_root_sha256: String,
    pub verifier_manifest_sha256: BTreeSet<String>,
    pub organization_roots: BTreeSet<String>,
    pub implementation_roots: BTreeSet<String>,
    pub receipt_sha256: BTreeSet<String>,
    pub quorum: usize,
    pub quorum_sha256: String,
}
