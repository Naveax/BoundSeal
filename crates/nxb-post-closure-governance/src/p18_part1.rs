#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicVerificationBundle {
    pub bundle_id: String,
    pub policy_snapshot_sha256: String,
    pub lifecycle_closure_sha256: String,
    pub succession_certificate_sha256: String,
    pub renewal_certificate_sha256: String,
    pub schema_roots: BTreeMap<String, String>,
    pub audit_roots: BTreeMap<String, String>,
    pub contains_secret_material: bool,
    pub bundle_sha256: String,
}

impl PublicVerificationBundle {
    pub fn new(
        bundle_id: impl Into<String>,
        lifecycle: &LifecycleClosureCertificate,
        succession: &SuccessionCertificate,
        renewal: &RenewalCertificate,
        schema_roots: BTreeMap<String, String>,
        audit_roots: BTreeMap<String, String>,
        contains_secret_material: bool,
    ) -> Result<Self, PostClosureError> {
        lifecycle
            .verify()
            .map_err(|error| PostClosureError::InvalidProgramClosure(error.to_string()))?;
        succession.verify()?;
        renewal.verify()?;
        let bundle_id = bundle_id.into();
        validate_identifier(&bundle_id, "public verification bundle")?;
        validate_hash_map(&schema_roots, "public schema root", MAX_COMPONENTS)?;
        validate_hash_map(&audit_roots, "public audit root", MAX_COMPONENTS)?;
        if contains_secret_material
            || lifecycle.policy_snapshot_sha256 != succession.policy_snapshot_sha256
            || lifecycle.policy_snapshot_sha256 != renewal.policy_snapshot_sha256
            || succession.baseline_lifecycle_closure_sha256 != lifecycle.certificate_sha256
            || renewal.succession_certificate_sha256 != succession.certificate_sha256
        {
            return Err(PostClosureError::InvalidProgramClosure(
                "public bundle policy, certificate or secret closure".into(),
            ));
        }
        let policy_snapshot_sha256 = lifecycle.policy_snapshot_sha256.clone();
        let lifecycle_closure_sha256 = lifecycle.certificate_sha256.clone();
        let succession_certificate_sha256 = succession.certificate_sha256.clone();
        let renewal_certificate_sha256 = renewal.certificate_sha256.clone();
        let bundle_sha256 = hash_serializable(&(
            &bundle_id,
            &policy_snapshot_sha256,
            &lifecycle_closure_sha256,
            &succession_certificate_sha256,
            &renewal_certificate_sha256,
            &schema_roots,
            &audit_roots,
            contains_secret_material,
        ))?;
        Ok(Self {
            bundle_id,
            policy_snapshot_sha256,
            lifecycle_closure_sha256,
            succession_certificate_sha256,
            renewal_certificate_sha256,
            schema_roots,
            audit_roots,
            contains_secret_material,
            bundle_sha256,
        })
    }

    pub fn verify(&self) -> Result<(), PostClosureError> {
        validate_identifier(&self.bundle_id, "public verification bundle")?;
        for (name, value) in [
            ("public bundle policy", self.policy_snapshot_sha256.as_str()),
            (
                "public lifecycle closure",
                self.lifecycle_closure_sha256.as_str(),
            ),
            (
                "public succession certificate",
                self.succession_certificate_sha256.as_str(),
            ),
            (
                "public renewal certificate",
                self.renewal_certificate_sha256.as_str(),
            ),
        ] {
            validate_sha256(value, name)?;
        }
        validate_hash_map(&self.schema_roots, "public schema root", MAX_COMPONENTS)?;
        validate_hash_map(&self.audit_roots, "public audit root", MAX_COMPONENTS)?;
        if self.contains_secret_material {
            return Err(PostClosureError::InvalidProgramClosure(
                "public bundle contains secret material".into(),
            ));
        }
        let expected = hash_serializable(&(
            &self.bundle_id,
            &self.policy_snapshot_sha256,
            &self.lifecycle_closure_sha256,
            &self.succession_certificate_sha256,
            &self.renewal_certificate_sha256,
            &self.schema_roots,
            &self.audit_roots,
            self.contains_secret_material,
        ))?;
        if expected != self.bundle_sha256 {
            return Err(PostClosureError::InvalidProgramClosure(
                "public verification bundle digest".into(),
            ));
        }
        Ok(())
    }
}
