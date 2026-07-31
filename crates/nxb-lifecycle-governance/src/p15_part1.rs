#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceClass {
    FinalAssurance,
    RoadmapClosure,
    MaintenanceRelease,
    Continuity,
    AuditTail,
    FreezeManifest,
}

fn mandatory_evidence_classes() -> BTreeSet<EvidenceClass> {
    BTreeSet::from([
        EvidenceClass::FinalAssurance,
        EvidenceClass::RoadmapClosure,
        EvidenceClass::MaintenanceRelease,
        EvidenceClass::Continuity,
        EvidenceClass::AuditTail,
        EvidenceClass::FreezeManifest,
    ])
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IndependentVerifierManifest {
    pub verifier_id: String,
    pub organization_root_sha256: String,
    pub implementation_root_sha256: String,
    pub binary_sha256: String,
    pub allowed_evidence_classes: BTreeSet<EvidenceClass>,
    pub external_io_requested: bool,
    pub manifest_sha256: String,
}

impl IndependentVerifierManifest {
    pub fn new(
        verifier_id: impl Into<String>,
        organization_root_sha256: impl Into<String>,
        implementation_root_sha256: impl Into<String>,
        binary_sha256: impl Into<String>,
        allowed_evidence_classes: BTreeSet<EvidenceClass>,
        external_io_requested: bool,
    ) -> Result<Self, LifecycleError> {
        let verifier_id = verifier_id.into();
        let organization_root_sha256 = organization_root_sha256.into();
        let implementation_root_sha256 = implementation_root_sha256.into();
        let binary_sha256 = binary_sha256.into();
        validate_identifier(&verifier_id, "independent verifier")?;
        for (name, value) in [
            ("verifier organization", organization_root_sha256.as_str()),
            (
                "verifier implementation",
                implementation_root_sha256.as_str(),
            ),
            ("verifier binary", binary_sha256.as_str()),
        ] {
            validate_sha256(value, name)?;
        }
        if allowed_evidence_classes != mandatory_evidence_classes() || external_io_requested {
            return Err(LifecycleError::InvalidClosure(
                "verifier evidence scope or external I/O request".into(),
            ));
        }
        let manifest_sha256 = hash_serializable(&(
            &verifier_id,
            &organization_root_sha256,
            &implementation_root_sha256,
            &binary_sha256,
            &allowed_evidence_classes,
            external_io_requested,
        ))?;
        Ok(Self {
            verifier_id,
            organization_root_sha256,
            implementation_root_sha256,
            binary_sha256,
            allowed_evidence_classes,
            external_io_requested,
            manifest_sha256,
        })
    }

    pub fn strict(
        verifier_id: impl Into<String>,
        organization_root_sha256: impl Into<String>,
        implementation_root_sha256: impl Into<String>,
        binary_sha256: impl Into<String>,
    ) -> Result<Self, LifecycleError> {
        Self::new(
            verifier_id,
            organization_root_sha256,
            implementation_root_sha256,
            binary_sha256,
            mandatory_evidence_classes(),
            false,
        )
    }

    pub fn verify(&self) -> Result<(), LifecycleError> {
        validate_identifier(&self.verifier_id, "independent verifier")?;
        for (name, value) in [
            (
                "verifier organization",
                self.organization_root_sha256.as_str(),
            ),
            (
                "verifier implementation",
                self.implementation_root_sha256.as_str(),
            ),
            ("verifier binary", self.binary_sha256.as_str()),
            ("verifier manifest", self.manifest_sha256.as_str()),
        ] {
            validate_sha256(value, name)?;
        }
        if self.allowed_evidence_classes != mandatory_evidence_classes()
            || self.external_io_requested
        {
            return Err(LifecycleError::InvalidClosure(
                "verifier manifest safety boundary".into(),
            ));
        }
        let expected = hash_serializable(&(
            &self.verifier_id,
            &self.organization_root_sha256,
            &self.implementation_root_sha256,
            &self.binary_sha256,
            &self.allowed_evidence_classes,
            self.external_io_requested,
        ))?;
        if expected != self.manifest_sha256 {
            return Err(LifecycleError::InvalidClosure(
                "verifier manifest digest".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceSamplePlan {
    pub plan_id: String,
    pub policy_snapshot_sha256: String,
    pub trusted_evidence_roots: BTreeMap<EvidenceClass, String>,
    pub selected_classes: BTreeSet<EvidenceClass>,
    pub deterministic_seed_sha256: String,
    pub sample_count: u32,
    pub plan_sha256: String,
}
