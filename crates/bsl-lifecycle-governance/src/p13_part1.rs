#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MaintenanceIdentity {
    pub maintenance_id: String,
    pub policy_snapshot_sha256: String,
    pub baseline_final_assurance_sha256: String,
    pub baseline_roadmap_closure_sha256: String,
    pub baseline_freeze_manifest_sha256: String,
    pub identity_sha256: String,
}

impl MaintenanceIdentity {
    pub fn new(
        maintenance_id: impl Into<String>,
        final_assurance: &FinalAssuranceCertificate,
        roadmap: &RoadmapClosureCertificate,
    ) -> Result<Self, LifecycleError> {
        final_assurance
            .verify()
            .map_err(|error| LifecycleError::BindingDenied(error.to_string()))?;
        roadmap
            .verify()
            .map_err(|error| LifecycleError::BindingDenied(error.to_string()))?;
        if roadmap.final_assurance_certificate_sha256 != final_assurance.certificate_sha256 {
            return Err(LifecycleError::BindingDenied(
                "roadmap and final assurance certificates differ".into(),
            ));
        }
        let maintenance_id = maintenance_id.into();
        validate_identifier(&maintenance_id, "maintenance identity")?;
        let policy_snapshot_sha256 = final_assurance.policy_snapshot_sha256.clone();
        let baseline_final_assurance_sha256 = final_assurance.certificate_sha256.clone();
        let baseline_roadmap_closure_sha256 = roadmap.closure_sha256.clone();
        let baseline_freeze_manifest_sha256 = final_assurance.freeze_manifest_sha256.clone();
        let identity_sha256 = hash_serializable(&(
            &maintenance_id,
            &policy_snapshot_sha256,
            &baseline_final_assurance_sha256,
            &baseline_roadmap_closure_sha256,
            &baseline_freeze_manifest_sha256,
        ))?;
        Ok(Self {
            maintenance_id,
            policy_snapshot_sha256,
            baseline_final_assurance_sha256,
            baseline_roadmap_closure_sha256,
            baseline_freeze_manifest_sha256,
            identity_sha256,
        })
    }

    pub fn verify(&self) -> Result<(), LifecycleError> {
        validate_identifier(&self.maintenance_id, "maintenance identity")?;
        for (name, value) in [
            ("maintenance policy", self.policy_snapshot_sha256.as_str()),
            (
                "baseline final assurance",
                self.baseline_final_assurance_sha256.as_str(),
            ),
            (
                "baseline roadmap closure",
                self.baseline_roadmap_closure_sha256.as_str(),
            ),
            (
                "baseline freeze manifest",
                self.baseline_freeze_manifest_sha256.as_str(),
            ),
            ("maintenance identity", self.identity_sha256.as_str()),
        ] {
            validate_sha256(value, name)?;
        }
        let expected = hash_serializable(&(
            &self.maintenance_id,
            &self.policy_snapshot_sha256,
            &self.baseline_final_assurance_sha256,
            &self.baseline_roadmap_closure_sha256,
            &self.baseline_freeze_manifest_sha256,
        ))?;
        if expected != self.identity_sha256 {
            return Err(LifecycleError::InvalidMaintenance(
                "maintenance identity digest".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ChangeClass {
    Documentation,
    Compatibility,
    SecurityPatch,
    DependencyRefresh,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChangeProposal {
    pub proposal_id: String,
    pub maintenance_identity_sha256: String,
    pub class: ChangeClass,
    pub component_roots: BTreeMap<String, String>,
    pub change_digest_sha256: String,
    pub rollback_digest_sha256: String,
    pub requires_recertification: bool,
    pub proposal_sha256: String,
}
