#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CrossCertificateBundle {
    pub policy_snapshot_sha256: String,
    pub adapter_certificate_sha256: String,
    pub reproducibility_certificate_sha256: String,
    pub platform_release_certificate_sha256: String,
    pub bundle_sha256: String,
}

impl CrossCertificateBundle {
    pub fn new(
        adapter: &AdapterConformanceCertificate,
        reproducibility: &ReproducibilityCertificate,
        release: &PlatformReleaseCertificate,
    ) -> Result<Self, AssuranceError> {
        adapter
            .verify()
            .map_err(|error| AssuranceError::InvalidBinding(error.to_string()))?;
        reproducibility
            .verify()
            .map_err(|error| AssuranceError::InvalidBinding(error.to_string()))?;
        release
            .verify()
            .map_err(|error| AssuranceError::InvalidBinding(error.to_string()))?;
        if adapter.policy_snapshot_sha256 != reproducibility.policy_snapshot_sha256
            || adapter.policy_snapshot_sha256 != release.policy_snapshot_sha256
            || release.adapter_conformance_sha256 != adapter.certificate_sha256
            || release.reproducibility_sha256 != reproducibility.certificate_sha256
        {
            return Err(AssuranceError::InvalidBinding(
                "cross-certificate policy or digest closure".into(),
            ));
        }
        let policy_snapshot_sha256 = adapter.policy_snapshot_sha256.clone();
        let adapter_certificate_sha256 = adapter.certificate_sha256.clone();
        let reproducibility_certificate_sha256 = reproducibility.certificate_sha256.clone();
        let platform_release_certificate_sha256 = release.certificate_sha256.clone();
        let bundle_sha256 = hash_serializable(&(
            &policy_snapshot_sha256,
            &adapter_certificate_sha256,
            &reproducibility_certificate_sha256,
            &platform_release_certificate_sha256,
        ))?;
        Ok(Self {
            policy_snapshot_sha256,
            adapter_certificate_sha256,
            reproducibility_certificate_sha256,
            platform_release_certificate_sha256,
            bundle_sha256,
        })
    }

    pub fn verify(&self) -> Result<(), AssuranceError> {
        for (name, value) in [
            ("bundle policy", self.policy_snapshot_sha256.as_str()),
            ("adapter certificate", self.adapter_certificate_sha256.as_str()),
            (
                "reproducibility certificate",
                self.reproducibility_certificate_sha256.as_str(),
            ),
            (
                "platform release certificate",
                self.platform_release_certificate_sha256.as_str(),
            ),
            ("certificate bundle", self.bundle_sha256.as_str()),
        ] {
            validate_sha256(value, name)?;
        }
        let expected = hash_serializable(&(
            &self.policy_snapshot_sha256,
            &self.adapter_certificate_sha256,
            &self.reproducibility_certificate_sha256,
            &self.platform_release_certificate_sha256,
        ))?;
        if expected != self.bundle_sha256 {
            return Err(AssuranceError::InvalidBinding(
                "certificate bundle digest".into(),
            ));
        }
        Ok(())
    }
}

