#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReleaseGate {
    pub gate_id: String,
    pub class: ReleaseGateClass,
    pub decision: GateDecision,
    pub evidence_sha256: String,
    pub waiver_reason_sha256: Option<String>,
    pub gate_sha256: String,
}

impl ReleaseGate {
    pub fn new(
        gate_id: impl Into<String>,
        class: ReleaseGateClass,
        decision: GateDecision,
        evidence_sha256: impl Into<String>,
        waiver_reason: Option<&str>,
    ) -> Result<Self, ReleaseError> {
        let gate_id = gate_id.into();
        let evidence_sha256 = evidence_sha256.into();
        validate_identifier(&gate_id, "release gate")?;
        validate_sha256(&evidence_sha256, "release gate evidence")?;
        if class == ReleaseGateClass::HardSafety && decision == GateDecision::Waived {
            return Err(ReleaseError::InvalidGate(
                "hard safety gates cannot be waived".into(),
            ));
        }
        let waiver_reason_sha256 = match (decision, waiver_reason) {
            (GateDecision::Waived, Some(reason)) if !reason.is_empty() && reason.len() <= 1024 => {
                Some(hash_bytes(reason.as_bytes()))
            }
            (GateDecision::Waived, _) => {
                return Err(ReleaseError::InvalidGate(
                    "waived gate requires bounded reason".into(),
                ));
            }
            (_, None) => None,
            (_, Some(_)) => {
                return Err(ReleaseError::InvalidGate(
                    "non-waived gate cannot carry waiver reason".into(),
                ));
            }
        };
        let gate_sha256 = hash_serializable(&(
            &gate_id,
            class,
            decision,
            &evidence_sha256,
            &waiver_reason_sha256,
        ))?;
        Ok(Self {
            gate_id,
            class,
            decision,
            evidence_sha256,
            waiver_reason_sha256,
            gate_sha256,
        })
    }

    pub fn verify(&self) -> Result<(), ReleaseError> {
        if self.class == ReleaseGateClass::HardSafety && self.decision == GateDecision::Waived {
            return Err(ReleaseError::InvalidGate(
                "hard safety gate waiver".into(),
            ));
        }
        let expected = hash_serializable(&(
            &self.gate_id,
            self.class,
            self.decision,
            &self.evidence_sha256,
            &self.waiver_reason_sha256,
        ))?;
        if expected != self.gate_sha256 {
            return Err(ReleaseError::InvalidGate("gate digest".into()));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReleaseGateSet {
    pub gate_set_id: String,
    pub policy_snapshot_sha256: String,
    pub gates: BTreeMap<String, ReleaseGate>,
    pub all_hard_passed: bool,
    pub gate_root_sha256: String,
}

impl ReleaseGateSet {
    pub fn new(
        gate_set_id: impl Into<String>,
        policy_snapshot_sha256: impl Into<String>,
        gates: Vec<ReleaseGate>,
    ) -> Result<Self, ReleaseError> {
        let gate_set_id = gate_set_id.into();
        let policy_snapshot_sha256 = policy_snapshot_sha256.into();
        validate_identifier(&gate_set_id, "release gate set")?;
        validate_sha256(&policy_snapshot_sha256, "release gate policy")?;
        if gates.is_empty() || gates.len() > MAX_RELEASE_GATES {
            return Err(ReleaseError::InvalidGate("gate count".into()));
        }
        let mut by_id = BTreeMap::new();
        for gate in gates {
            gate.verify()?;
            if by_id.insert(gate.gate_id.clone(), gate).is_some() {
                return Err(ReleaseError::InvalidGate(
                    "duplicate release gate".into(),
                ));
            }
        }
        let all_hard_passed = by_id.values().all(|gate| {
            gate.class != ReleaseGateClass::HardSafety || gate.decision == GateDecision::Passed
        });
        let gate_root_sha256 = hash_serializable(&(
            &gate_set_id,
            &policy_snapshot_sha256,
            &by_id,
            all_hard_passed,
        ))?;
        Ok(Self {
            gate_set_id,
            policy_snapshot_sha256,
            gates: by_id,
            all_hard_passed,
            gate_root_sha256,
        })
    }

    pub fn verify(&self) -> Result<(), ReleaseError> {
        for gate in self.gates.values() {
            gate.verify()?;
        }
        let all_hard_passed = self.gates.values().all(|gate| {
            gate.class != ReleaseGateClass::HardSafety || gate.decision == GateDecision::Passed
        });
        let expected = hash_serializable(&(
            &self.gate_set_id,
            &self.policy_snapshot_sha256,
            &self.gates,
            all_hard_passed,
        ))?;
        if expected != self.gate_root_sha256 || all_hard_passed != self.all_hard_passed {
            return Err(ReleaseError::InvalidGate("gate set digest".into()));
        }
        Ok(())
    }

    pub fn class_has_acceptable_decision(&self, class: ReleaseGateClass) -> bool {
        self.gates.values().any(|gate| {
            gate.class == class
                && matches!(gate.decision, GateDecision::Passed | GateDecision::Waived)
        })
    }

    pub fn has_failed_gate(&self) -> bool {
        self.gates
            .values()
            .any(|gate| gate.decision == GateDecision::Failed)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtifactEntry {
    pub logical_path: String,
    pub component_id: String,
    pub content_sha256: String,
    pub bytes: u64,
}

impl ArtifactEntry {
    pub fn new(
        logical_path: impl Into<String>,
        component_id: impl Into<String>,
        content_sha256: impl Into<String>,
        bytes: u64,
    ) -> Result<Self, ReleaseError> {
        let logical_path = logical_path.into();
        let component_id = component_id.into();
        let content_sha256 = content_sha256.into();
        validate_identifier(&component_id, "artifact component")?;
        validate_sha256(&content_sha256, "artifact content")?;
        if logical_path.is_empty()
            || logical_path.len() > 512
            || logical_path.starts_with('/')
            || logical_path.contains("..")
            || logical_path.contains('\\')
            || logical_path.bytes().any(|byte| byte.is_ascii_control())
            || bytes == 0
            || bytes > MAX_ARTIFACT_BYTES
        {
            return Err(ReleaseError::InvalidArtifact(
                "artifact path or byte bounds".into(),
            ));
        }
        Ok(Self {
            logical_path,
            component_id,
            content_sha256,
            bytes,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtifactManifest {
    pub manifest_id: String,
    pub policy_snapshot_sha256: String,
    pub inventory_root_sha256: String,
    pub entries: BTreeMap<String, ArtifactEntry>,
    pub total_bytes: u64,
    pub manifest_root_sha256: String,
}

impl ArtifactManifest {
    pub fn new(
        manifest_id: impl Into<String>,
        inventory: &ComponentInventory,
        entries: Vec<ArtifactEntry>,
    ) -> Result<Self, ReleaseError> {
        inventory.verify()?;
        let manifest_id = manifest_id.into();
        validate_identifier(&manifest_id, "artifact manifest")?;
        if entries.is_empty() || entries.len() > MAX_ARTIFACT_ENTRIES {
            return Err(ReleaseError::InvalidArtifact("entry count".into()));
        }
        let mut by_path = BTreeMap::new();
        let mut total_bytes = 0_u64;
        for entry in entries {
            let component = inventory
                .components
                .get(&entry.component_id)
                .ok_or_else(|| ReleaseError::InvalidArtifact("unknown component".into()))?;
            if entry.content_sha256 != component.artifact_sha256 {
                return Err(ReleaseError::InvalidArtifact(
                    "entry digest does not match component artifact".into(),
                ));
            }
            total_bytes = total_bytes
                .checked_add(entry.bytes)
                .ok_or_else(|| ReleaseError::InvalidArtifact("byte overflow".into()))?;
            if total_bytes > MAX_ARTIFACT_BYTES
                || by_path.insert(entry.logical_path.clone(), entry).is_some()
            {
                return Err(ReleaseError::InvalidArtifact(
                    "duplicate path or total byte limit".into(),
                ));
            }
        }
        let covered_components = by_path
            .values()
            .map(|entry| entry.component_id.as_str())
            .collect::<BTreeSet<_>>();
        if covered_components.len() != inventory.components.len() {
            return Err(ReleaseError::InvalidArtifact(
                "every inventory component requires an artifact entry".into(),
            ));
        }
        let manifest_root_sha256 = hash_serializable(&(
            &manifest_id,
            &inventory.policy_snapshot_sha256,
            &inventory.inventory_root_sha256,
            &by_path,
            total_bytes,
        ))?;
        Ok(Self {
            manifest_id,
            policy_snapshot_sha256: inventory.policy_snapshot_sha256.clone(),
            inventory_root_sha256: inventory.inventory_root_sha256.clone(),
            entries: by_path,
            total_bytes,
            manifest_root_sha256,
        })
    }

    pub fn verify(&self) -> Result<(), ReleaseError> {
        let actual_total = self
            .entries
            .values()
            .try_fold(0_u64, |total, entry| total.checked_add(entry.bytes))
            .ok_or_else(|| ReleaseError::InvalidArtifact("byte overflow".into()))?;
        let expected = hash_serializable(&(
            &self.manifest_id,
            &self.policy_snapshot_sha256,
            &self.inventory_root_sha256,
            &self.entries,
            actual_total,
        ))?;
        if expected != self.manifest_root_sha256 || actual_total != self.total_bytes {
            return Err(ReleaseError::InvalidArtifact(
                "artifact manifest root".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtifactAttestation {
    pub attestation_id: String,
    pub authority_id: String,
    pub policy_snapshot_sha256: String,
    pub inventory_root_sha256: String,
    pub gate_root_sha256: String,
    pub manifest_root_sha256: String,
    pub authority_audit_tail_hash: String,
    pub attestation_sha256: String,
}

impl ArtifactAttestation {
    pub fn verify(&self) -> Result<(), ReleaseError> {
        let expected = hash_serializable(&(
            &self.attestation_id,
            &self.authority_id,
            &self.policy_snapshot_sha256,
            &self.inventory_root_sha256,
            &self.gate_root_sha256,
            &self.manifest_root_sha256,
            &self.authority_audit_tail_hash,
        ))?;
        if expected != self.attestation_sha256 {
            return Err(ReleaseError::InvalidArtifact(
                "artifact attestation digest".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct ArtifactAttestationAuthority {
    authority_id: String,
    policy_snapshot_sha256: String,
    audit: ReleaseAuditChain,
}

impl ArtifactAttestationAuthority {
    pub fn new(
        authority_id: impl Into<String>,
        policy_snapshot_sha256: impl Into<String>,
        audit_genesis: impl Into<String>,
    ) -> Result<Self, ReleaseError> {
        let authority_id = authority_id.into();
        let policy_snapshot_sha256 = policy_snapshot_sha256.into();
        validate_identifier(&authority_id, "artifact authority")?;
        validate_sha256(&policy_snapshot_sha256, "artifact authority policy")?;
        Ok(Self {
            authority_id,
            policy_snapshot_sha256,
            audit: ReleaseAuditChain::new(audit_genesis)?,
        })
    }

    pub fn attest(
        &mut self,
        inventory: &ComponentInventory,
        gates: &ReleaseGateSet,
        manifest: &ArtifactManifest,
    ) -> Result<ArtifactAttestation, ReleaseError> {
        inventory.verify()?;
        gates.verify()?;
        manifest.verify()?;
        if inventory.policy_snapshot_sha256 != self.policy_snapshot_sha256
            || gates.policy_snapshot_sha256 != self.policy_snapshot_sha256
            || manifest.policy_snapshot_sha256 != self.policy_snapshot_sha256
            || manifest.inventory_root_sha256 != inventory.inventory_root_sha256
            || !gates.all_hard_passed
            || gates.has_failed_gate()
        {
            return Err(ReleaseError::CertificationDenied(
                "artifact policy, inventory or gate closure".into(),
            ));
        }
        let seed = hash_serializable(&(
            &self.authority_id,
            &self.policy_snapshot_sha256,
            &inventory.inventory_root_sha256,
            &gates.gate_root_sha256,
            &manifest.manifest_root_sha256,
        ))?;
        let attestation_id = format!("artifact-attestation-{}", &seed[..24]);
        self.audit.append(ReleaseAuditEvent {
            action: "artifact_attested".into(),
            subject_id: attestation_id.clone(),
            outcome: "attested".into(),
            metadata: BTreeMap::from([
                ("inventory_root_sha256".into(), inventory.inventory_root_sha256.clone()),
                ("manifest_root_sha256".into(), manifest.manifest_root_sha256.clone()),
            ]),
        })?;
        let attestation_sha256 = hash_serializable(&(
            &attestation_id,
            &self.authority_id,
            &self.policy_snapshot_sha256,
            &inventory.inventory_root_sha256,
            &gates.gate_root_sha256,
            &manifest.manifest_root_sha256,
            self.audit.tail_hash(),
        ))?;
        let attestation = ArtifactAttestation {
            attestation_id,
            authority_id: self.authority_id.clone(),
            policy_snapshot_sha256: self.policy_snapshot_sha256.clone(),
            inventory_root_sha256: inventory.inventory_root_sha256.clone(),
            gate_root_sha256: gates.gate_root_sha256.clone(),
            manifest_root_sha256: manifest.manifest_root_sha256.clone(),
            authority_audit_tail_hash: self.audit.tail_hash().into(),
            attestation_sha256,
        };
        attestation.verify()?;
        Ok(attestation)
    }

    pub fn audit(&self) -> &ReleaseAuditChain {
        &self.audit
    }
}
