#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlatformReleaseCertificate {
    pub certificate_id: String,
    pub authority_id: String,
    pub policy_snapshot_sha256: String,
    pub adapter_conformance_sha256: String,
    pub reproducibility_sha256: String,
    pub inventory_root_sha256: String,
    pub compatibility_contract_sha256: String,
    pub gate_root_sha256: String,
    pub artifact_attestation_sha256: String,
    pub rollout_plan_sha256: String,
    pub rollback_certificate_sha256: String,
    pub rollout_receipt_sha256: String,
    pub authority_audit_tail_hash: String,
    pub certificate_sha256: String,
}

impl PlatformReleaseCertificate {
    pub fn verify(&self) -> Result<(), ReleaseError> {
        for (name, value) in [
            ("platform policy", self.policy_snapshot_sha256.as_str()),
            (
                "adapter conformance",
                self.adapter_conformance_sha256.as_str(),
            ),
            ("reproducibility", self.reproducibility_sha256.as_str()),
            ("inventory", self.inventory_root_sha256.as_str()),
            (
                "compatibility",
                self.compatibility_contract_sha256.as_str(),
            ),
            ("gate root", self.gate_root_sha256.as_str()),
            (
                "artifact attestation",
                self.artifact_attestation_sha256.as_str(),
            ),
            ("rollout plan", self.rollout_plan_sha256.as_str()),
            (
                "rollback certificate",
                self.rollback_certificate_sha256.as_str(),
            ),
            ("rollout receipt", self.rollout_receipt_sha256.as_str()),
            ("authority audit", self.authority_audit_tail_hash.as_str()),
            ("platform certificate", self.certificate_sha256.as_str()),
        ] {
            validate_sha256(value, name)?;
        }
        let expected = hash_serializable(&(
            &self.certificate_id,
            &self.authority_id,
            &self.policy_snapshot_sha256,
            &self.adapter_conformance_sha256,
            &self.reproducibility_sha256,
            &self.inventory_root_sha256,
            &self.compatibility_contract_sha256,
            &self.gate_root_sha256,
            &self.artifact_attestation_sha256,
            &self.rollout_plan_sha256,
            &self.rollback_certificate_sha256,
            &self.rollout_receipt_sha256,
            &self.authority_audit_tail_hash,
        ))?;
        if expected != self.certificate_sha256 {
            return Err(ReleaseError::CertificationDenied(
                "platform certificate digest".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct PlatformReleaseAuthority {
    authority_id: String,
    policy_snapshot_sha256: String,
    audit: ReleaseAuditChain,
}

impl PlatformReleaseAuthority {
    pub fn new(
        authority_id: impl Into<String>,
        policy_snapshot_sha256: impl Into<String>,
        audit_genesis: impl Into<String>,
    ) -> Result<Self, ReleaseError> {
        let authority_id = authority_id.into();
        let policy_snapshot_sha256 = policy_snapshot_sha256.into();
        validate_identifier(&authority_id, "platform release authority")?;
        validate_sha256(&policy_snapshot_sha256, "platform release policy")?;
        Ok(Self {
            authority_id,
            policy_snapshot_sha256,
            audit: ReleaseAuditChain::new(audit_genesis)?,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn certify(
        &mut self,
        adapter: &AdapterConformanceCertificate,
        reproducibility: &ReproducibilityCertificate,
        inventory: &ComponentInventory,
        compatibility: &CompatibilityContract,
        gates: &ReleaseGateSet,
        attestation: &ArtifactAttestation,
        rollout_plan: &RolloutPlan,
        rollback: &RollbackDrillCertificate,
        rollout_receipt: &RolloutSimulationReceipt,
    ) -> Result<PlatformReleaseCertificate, ReleaseError> {
        adapter
            .verify()
            .map_err(|error| ReleaseError::CertificationDenied(error.to_string()))?;
        reproducibility
            .verify()
            .map_err(|error| ReleaseError::CertificationDenied(error.to_string()))?;
        inventory.verify()?;
        compatibility.verify()?;
        gates.verify()?;
        attestation.verify()?;
        rollout_plan.verify()?;
        rollback.verify()?;
        rollout_receipt.verify()?;
        let policies_match = [
            adapter.policy_snapshot_sha256.as_str(),
            reproducibility.policy_snapshot_sha256.as_str(),
            inventory.policy_snapshot_sha256.as_str(),
            compatibility.policy_snapshot_sha256.as_str(),
            gates.policy_snapshot_sha256.as_str(),
            attestation.policy_snapshot_sha256.as_str(),
            rollout_plan.policy_snapshot_sha256.as_str(),
        ]
        .into_iter()
        .all(|policy| policy == self.policy_snapshot_sha256);
        let required_gate_classes = [
            ReleaseGateClass::HardSafety,
            ReleaseGateClass::Compatibility,
            ReleaseGateClass::Reproducibility,
            ReleaseGateClass::ArtifactIntegrity,
            ReleaseGateClass::RollbackReadiness,
        ];
        let expected_stage_ids = rollout_plan
            .stages
            .iter()
            .map(|stage| stage.stage_id.clone())
            .collect::<BTreeSet<_>>();
        if !policies_match
            || !compatibility.all_compatible
            || !gates.all_hard_passed
            || gates.has_failed_gate()
            || required_gate_classes
                .iter()
                .any(|class| !gates.class_has_acceptable_decision(*class))
            || attestation.inventory_root_sha256 != inventory.inventory_root_sha256
            || attestation.gate_root_sha256 != gates.gate_root_sha256
            || rollout_plan.artifact_attestation_sha256 != attestation.attestation_sha256
            || rollback.rollout_plan_sha256 != rollout_plan.plan_sha256
            || rollback.artifact_attestation_sha256 != attestation.attestation_sha256
            || rollback.restored_manifest_root_sha256
                != rollout_plan.baseline_manifest_root_sha256
            || rollout_receipt.rollout_plan_sha256 != rollout_plan.plan_sha256
            || rollout_receipt.artifact_attestation_sha256 != attestation.attestation_sha256
            || rollout_receipt.rollback_certificate_sha256 != rollback.certificate_sha256
            || rollout_receipt.validated_stage_ids != expected_stage_ids
        {
            return Err(ReleaseError::CertificationDenied(
                "policy, compatibility, gate, artifact, rollout or rollback closure".into(),
            ));
        }
        let seed = hash_serializable(&(
            &self.authority_id,
            &self.policy_snapshot_sha256,
            &adapter.certificate_sha256,
            &reproducibility.certificate_sha256,
            &inventory.inventory_root_sha256,
            &compatibility.contract_sha256,
            &gates.gate_root_sha256,
            &attestation.attestation_sha256,
            &rollout_plan.plan_sha256,
            &rollback.certificate_sha256,
            &rollout_receipt.receipt_sha256,
        ))?;
        let certificate_id = format!("platform-release-{}", &seed[..24]);
        self.audit.append(ReleaseAuditEvent {
            action: "platform_release_certified".into(),
            subject_id: certificate_id.clone(),
            outcome: "certified".into(),
            metadata: BTreeMap::from([
                ("inventory_root_sha256".into(), inventory.inventory_root_sha256.clone()),
                ("rollout_plan_sha256".into(), rollout_plan.plan_sha256.clone()),
                (
                    "rollback_certificate_sha256".into(),
                    rollback.certificate_sha256.clone(),
                ),
            ]),
        })?;
        let certificate_sha256 = hash_serializable(&(
            &certificate_id,
            &self.authority_id,
            &self.policy_snapshot_sha256,
            &adapter.certificate_sha256,
            &reproducibility.certificate_sha256,
            &inventory.inventory_root_sha256,
            &compatibility.contract_sha256,
            &gates.gate_root_sha256,
            &attestation.attestation_sha256,
            &rollout_plan.plan_sha256,
            &rollback.certificate_sha256,
            &rollout_receipt.receipt_sha256,
            self.audit.tail_hash(),
        ))?;
        let certificate = PlatformReleaseCertificate {
            certificate_id,
            authority_id: self.authority_id.clone(),
            policy_snapshot_sha256: self.policy_snapshot_sha256.clone(),
            adapter_conformance_sha256: adapter.certificate_sha256.clone(),
            reproducibility_sha256: reproducibility.certificate_sha256.clone(),
            inventory_root_sha256: inventory.inventory_root_sha256.clone(),
            compatibility_contract_sha256: compatibility.contract_sha256.clone(),
            gate_root_sha256: gates.gate_root_sha256.clone(),
            artifact_attestation_sha256: attestation.attestation_sha256.clone(),
            rollout_plan_sha256: rollout_plan.plan_sha256.clone(),
            rollback_certificate_sha256: rollback.certificate_sha256.clone(),
            rollout_receipt_sha256: rollout_receipt.receipt_sha256.clone(),
            authority_audit_tail_hash: self.audit.tail_hash().into(),
            certificate_sha256,
        };
        certificate.verify()?;
        Ok(certificate)
    }

    pub fn audit(&self) -> &ReleaseAuditChain {
        &self.audit
    }
}
