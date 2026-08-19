#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum SunsetStep {
    FreezeSuccessor,
    PublishVerificationBundle,
    RevokeCapabilities,
    PurgeSecrets,
    ArchiveMetadata,
    SealProgram,
}

pub fn canonical_sunset_steps() -> Vec<SunsetStep> {
    vec![
        SunsetStep::FreezeSuccessor,
        SunsetStep::PublishVerificationBundle,
        SunsetStep::RevokeCapabilities,
        SunsetStep::PurgeSecrets,
        SunsetStep::ArchiveMetadata,
        SunsetStep::SealProgram,
    ]
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SunsetPlan {
    pub plan_id: String,
    pub succession_certificate_sha256: String,
    pub renewal_certificate_sha256: String,
    pub public_bundle_sha256: String,
    pub public_quorum_sha256: String,
    pub archive_root_sha256: String,
    pub steps: Vec<SunsetStep>,
    pub plan_sha256: String,
}

impl SunsetPlan {
    pub fn new(
        plan_id: impl Into<String>,
        succession: &SuccessionCertificate,
        renewal: &RenewalCertificate,
        bundle: &PublicVerificationBundle,
        quorum: &PublicVerificationQuorum,
        archive_root_sha256: impl Into<String>,
    ) -> Result<Self, PostClosureError> {
        succession.verify()?;
        renewal.verify()?;
        bundle.verify()?;
        quorum.verify()?;
        let plan_id = plan_id.into();
        let archive_root_sha256 = archive_root_sha256.into();
        validate_identifier(&plan_id, "sunset plan")?;
        validate_sha256(&archive_root_sha256, "sunset archive root")?;
        if renewal.succession_certificate_sha256 != succession.certificate_sha256
            || bundle.succession_certificate_sha256 != succession.certificate_sha256
            || bundle.renewal_certificate_sha256 != renewal.certificate_sha256
            || quorum.bundle_sha256 != bundle.bundle_sha256
        {
            return Err(PostClosureError::InvalidProgramClosure(
                "sunset plan certificate closure".into(),
            ));
        }
        let steps = canonical_sunset_steps();
        let succession_certificate_sha256 = succession.certificate_sha256.clone();
        let renewal_certificate_sha256 = renewal.certificate_sha256.clone();
        let public_bundle_sha256 = bundle.bundle_sha256.clone();
        let public_quorum_sha256 = quorum.quorum_sha256.clone();
        let plan_sha256 = hash_serializable(&(
            &plan_id,
            &succession_certificate_sha256,
            &renewal_certificate_sha256,
            &public_bundle_sha256,
            &public_quorum_sha256,
            &archive_root_sha256,
            &steps,
        ))?;
        Ok(Self {
            plan_id,
            succession_certificate_sha256,
            renewal_certificate_sha256,
            public_bundle_sha256,
            public_quorum_sha256,
            archive_root_sha256,
            steps,
            plan_sha256,
        })
    }

    pub fn verify(&self) -> Result<(), PostClosureError> {
        validate_identifier(&self.plan_id, "sunset plan")?;
        for (name, value) in [
            (
                "sunset succession certificate",
                self.succession_certificate_sha256.as_str(),
            ),
            (
                "sunset renewal certificate",
                self.renewal_certificate_sha256.as_str(),
            ),
            ("sunset public bundle", self.public_bundle_sha256.as_str()),
            ("sunset public quorum", self.public_quorum_sha256.as_str()),
            ("sunset archive root", self.archive_root_sha256.as_str()),
        ] {
            validate_sha256(value, name)?;
        }
        if self.steps != canonical_sunset_steps() {
            return Err(PostClosureError::InvalidProgramClosure(
                "sunset plan steps".into(),
            ));
        }
        let expected = hash_serializable(&(
            &self.plan_id,
            &self.succession_certificate_sha256,
            &self.renewal_certificate_sha256,
            &self.public_bundle_sha256,
            &self.public_quorum_sha256,
            &self.archive_root_sha256,
            &self.steps,
        ))?;
        if expected != self.plan_sha256 {
            return Err(PostClosureError::InvalidProgramClosure(
                "sunset plan digest".into(),
            ));
        }
        Ok(())
    }
}
