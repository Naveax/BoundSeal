use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{
    hash_serializable, validate_hash_map, validate_identifier, validate_sha256,
    EvolutionAuditChain, EvolutionAuditEvent, EvolutionError, EvolutionReleaseCertificate,
    GenerationContinuityCertificate, MAX_COMPONENTS, MAX_ROTATION_OVERLAP_TICKS, MAX_STEWARDS,
};
use nxb_lifecycle_governance::LifecycleClosureCertificate;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum StewardRole {
    Custodian,
    Auditor,
    SafetyOfficer,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StewardshipCharter {
    pub charter_id: String,
    pub policy_snapshot_sha256: String,
    pub lifecycle_closure_certificate_sha256: String,
    pub evolution_release_certificate_sha256: String,
    pub generation_continuity_certificate_sha256: String,
    pub required_roles: BTreeSet<StewardRole>,
    pub maximum_term_ticks: u64,
    pub immutable_hard_safety: bool,
    pub charter_sha256: String,
}

impl StewardshipCharter {
    pub fn new(
        charter_id: impl Into<String>,
        lifecycle: &LifecycleClosureCertificate,
        evolution: &EvolutionReleaseCertificate,
        continuity: &GenerationContinuityCertificate,
        maximum_term_ticks: u64,
    ) -> Result<Self, EvolutionError> {
        lifecycle
            .verify()
            .map_err(|error| EvolutionError::BindingDenied(error.to_string()))?;
        evolution.verify()?;
        continuity.verify()?;
        let charter_id = charter_id.into();
        validate_identifier(&charter_id, "stewardship charter")?;
        if lifecycle.policy_snapshot_sha256 != evolution.policy_snapshot_sha256
            || lifecycle.policy_snapshot_sha256 != continuity.policy_snapshot_sha256
            || continuity.evolution_release_certificate_sha256 != evolution.certificate_sha256
            || evolution.lifecycle_closure_certificate_sha256 != lifecycle.certificate_sha256
            || maximum_term_ticks == 0
            || maximum_term_ticks > 365 * 24 * 60 * 60
        {
            return Err(EvolutionError::InvalidStewardship(
                "charter certificate or term binding".into(),
            ));
        }
        let required_roles = BTreeSet::from([
            StewardRole::Custodian,
            StewardRole::Auditor,
            StewardRole::SafetyOfficer,
        ]);
        let policy_snapshot_sha256 = lifecycle.policy_snapshot_sha256.clone();
        let lifecycle_closure_certificate_sha256 = lifecycle.certificate_sha256.clone();
        let evolution_release_certificate_sha256 = evolution.certificate_sha256.clone();
        let generation_continuity_certificate_sha256 = continuity.certificate_sha256.clone();
        let immutable_hard_safety = true;
        let charter_sha256 = hash_serializable(&(
            &charter_id,
            &policy_snapshot_sha256,
            &lifecycle_closure_certificate_sha256,
            &evolution_release_certificate_sha256,
            &generation_continuity_certificate_sha256,
            &required_roles,
            maximum_term_ticks,
            immutable_hard_safety,
        ))?;
        Ok(Self {
            charter_id,
            policy_snapshot_sha256,
            lifecycle_closure_certificate_sha256,
            evolution_release_certificate_sha256,
            generation_continuity_certificate_sha256,
            required_roles,
            maximum_term_ticks,
            immutable_hard_safety,
            charter_sha256,
        })
    }

    pub fn verify(&self) -> Result<(), EvolutionError> {
        let expected_roles = BTreeSet::from([
            StewardRole::Custodian,
            StewardRole::Auditor,
            StewardRole::SafetyOfficer,
        ]);
        let expected = hash_serializable(&(
            &self.charter_id,
            &self.policy_snapshot_sha256,
            &self.lifecycle_closure_certificate_sha256,
            &self.evolution_release_certificate_sha256,
            &self.generation_continuity_certificate_sha256,
            &self.required_roles,
            self.maximum_term_ticks,
            self.immutable_hard_safety,
        ))?;
        if self.required_roles != expected_roles
            || !self.immutable_hard_safety
            || self.maximum_term_ticks == 0
            || self.maximum_term_ticks > 365 * 24 * 60 * 60
            || expected != self.charter_sha256
        {
            return Err(EvolutionError::InvalidStewardship(
                "stewardship charter closure".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StewardIdentity {
    pub steward_id: String,
    pub role: StewardRole,
    pub organization_sha256: String,
    pub identity_sha256: String,
}

impl StewardIdentity {
    pub fn new(
        steward_id: impl Into<String>,
        role: StewardRole,
        organization_sha256: impl Into<String>,
    ) -> Result<Self, EvolutionError> {
        let steward_id = steward_id.into();
        let organization_sha256 = organization_sha256.into();
        validate_identifier(&steward_id, "steward identity")?;
        validate_sha256(&organization_sha256, "steward organization")?;
        let identity_sha256 = hash_serializable(&(&steward_id, role, &organization_sha256))?;
        Ok(Self {
            steward_id,
            role,
            organization_sha256,
            identity_sha256,
        })
    }

    pub fn verify(&self) -> Result<(), EvolutionError> {
        let expected =
            hash_serializable(&(&self.steward_id, self.role, &self.organization_sha256))?;
        if expected != self.identity_sha256 {
            return Err(EvolutionError::InvalidStewardship(
                "steward identity digest".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SuccessionApproval {
    pub steward: StewardIdentity,
    pub charter_sha256: String,
    pub successor_identity_sha256: String,
    pub approved_tick: u64,
    pub approval_sha256: String,
}

impl SuccessionApproval {
    pub fn new(
        steward: StewardIdentity,
        charter: &StewardshipCharter,
        successor_identity_sha256: impl Into<String>,
        approved_tick: u64,
    ) -> Result<Self, EvolutionError> {
        steward.verify()?;
        charter.verify()?;
        let successor_identity_sha256 = successor_identity_sha256.into();
        validate_sha256(&successor_identity_sha256, "successor identity")?;
        let charter_sha256 = charter.charter_sha256.clone();
        let approval_sha256 = hash_serializable(&(
            &steward.identity_sha256,
            &charter_sha256,
            &successor_identity_sha256,
            approved_tick,
        ))?;
        Ok(Self {
            steward,
            charter_sha256,
            successor_identity_sha256,
            approved_tick,
            approval_sha256,
        })
    }

    pub fn verify(
        &self,
        charter: &StewardshipCharter,
        successor_identity_sha256: &str,
    ) -> Result<(), EvolutionError> {
        self.steward.verify()?;
        let expected = hash_serializable(&(
            &self.steward.identity_sha256,
            &self.charter_sha256,
            &self.successor_identity_sha256,
            self.approved_tick,
        ))?;
        if self.charter_sha256 != charter.charter_sha256
            || self.successor_identity_sha256 != successor_identity_sha256
            || expected != self.approval_sha256
        {
            return Err(EvolutionError::InvalidStewardship(
                "succession approval binding".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SuccessionQuorum {
    pub charter_sha256: String,
    pub successor_identity_sha256: String,
    pub approvals: BTreeMap<String, SuccessionApproval>,
    pub organization_sha256: String,
    pub quorum_sha256: String,
}

impl SuccessionQuorum {
    pub fn new(
        charter: &StewardshipCharter,
        successor_identity_sha256: impl Into<String>,
        approvals: Vec<SuccessionApproval>,
    ) -> Result<Self, EvolutionError> {
        let successor_identity_sha256 = successor_identity_sha256.into();
        validate_sha256(&successor_identity_sha256, "successor identity")?;
        if approvals.len() != charter.required_roles.len() || approvals.len() > MAX_STEWARDS {
            return Err(EvolutionError::InvalidStewardship(
                "succession approval count".into(),
            ));
        }
        let mut map = BTreeMap::new();
        let mut roles = BTreeSet::new();
        let mut organizations = BTreeSet::new();
        for approval in approvals {
            approval.verify(charter, &successor_identity_sha256)?;
            roles.insert(approval.steward.role);
            organizations.insert(approval.steward.organization_sha256.clone());
            if map
                .insert(approval.steward.steward_id.clone(), approval)
                .is_some()
            {
                return Err(EvolutionError::InvalidStewardship(
                    "duplicate steward approval".into(),
                ));
            }
        }
        if roles != charter.required_roles || organizations.len() != 1 {
            return Err(EvolutionError::InvalidStewardship(
                "succession role or organization quorum".into(),
            ));
        }
        let organization_sha256 = organizations.into_iter().next().expect("one organization");
        let charter_sha256 = charter.charter_sha256.clone();
        let quorum_sha256 = hash_serializable(&(
            &charter_sha256,
            &successor_identity_sha256,
            &map,
            &organization_sha256,
        ))?;
        Ok(Self {
            charter_sha256,
            successor_identity_sha256,
            approvals: map,
            organization_sha256,
            quorum_sha256,
        })
    }

    pub fn verify(&self, charter: &StewardshipCharter) -> Result<(), EvolutionError> {
        let roles = self
            .approvals
            .values()
            .map(|approval| approval.steward.role)
            .collect::<BTreeSet<_>>();
        let organizations = self
            .approvals
            .values()
            .map(|approval| approval.steward.organization_sha256.clone())
            .collect::<BTreeSet<_>>();
        let expected = hash_serializable(&(
            &self.charter_sha256,
            &self.successor_identity_sha256,
            &self.approvals,
            &self.organization_sha256,
        ))?;
        if self.charter_sha256 != charter.charter_sha256
            || roles != charter.required_roles
            || organizations != BTreeSet::from([self.organization_sha256.clone()])
            || expected != self.quorum_sha256
        {
            return Err(EvolutionError::InvalidStewardship(
                "succession quorum closure".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CustodyTransfer {
    pub transfer_id: String,
    pub charter_sha256: String,
    pub succession_quorum_sha256: String,
    pub from_custodian_sha256: String,
    pub to_custodian_sha256: String,
    pub custody_roots: BTreeMap<String, String>,
    pub transferred_tick: u64,
    pub transfer_sha256: String,
}

impl CustodyTransfer {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        transfer_id: impl Into<String>,
        charter: &StewardshipCharter,
        quorum: &SuccessionQuorum,
        from_custodian_sha256: impl Into<String>,
        to_custodian_sha256: impl Into<String>,
        custody_roots: BTreeMap<String, String>,
        transferred_tick: u64,
    ) -> Result<Self, EvolutionError> {
        charter.verify()?;
        quorum.verify(charter)?;
        let transfer_id = transfer_id.into();
        let from_custodian_sha256 = from_custodian_sha256.into();
        let to_custodian_sha256 = to_custodian_sha256.into();
        validate_identifier(&transfer_id, "custody transfer")?;
        validate_sha256(&from_custodian_sha256, "from custodian")?;
        validate_sha256(&to_custodian_sha256, "to custodian")?;
        validate_hash_map(&custody_roots, "custody root", MAX_COMPONENTS)?;
        if from_custodian_sha256 == to_custodian_sha256
            || quorum.successor_identity_sha256 != to_custodian_sha256
        {
            return Err(EvolutionError::InvalidStewardship(
                "custody transfer identities".into(),
            ));
        }
        let charter_sha256 = charter.charter_sha256.clone();
        let succession_quorum_sha256 = quorum.quorum_sha256.clone();
        let transfer_sha256 = hash_serializable(&(
            &transfer_id,
            &charter_sha256,
            &succession_quorum_sha256,
            &from_custodian_sha256,
            &to_custodian_sha256,
            &custody_roots,
            transferred_tick,
        ))?;
        Ok(Self {
            transfer_id,
            charter_sha256,
            succession_quorum_sha256,
            from_custodian_sha256,
            to_custodian_sha256,
            custody_roots,
            transferred_tick,
            transfer_sha256,
        })
    }

    pub fn verify(
        &self,
        charter: &StewardshipCharter,
        quorum: &SuccessionQuorum,
    ) -> Result<(), EvolutionError> {
        let expected = hash_serializable(&(
            &self.transfer_id,
            &self.charter_sha256,
            &self.succession_quorum_sha256,
            &self.from_custodian_sha256,
            &self.to_custodian_sha256,
            &self.custody_roots,
            self.transferred_tick,
        ))?;
        if self.charter_sha256 != charter.charter_sha256
            || self.succession_quorum_sha256 != quorum.quorum_sha256
            || self.to_custodian_sha256 != quorum.successor_identity_sha256
            || self.from_custodian_sha256 == self.to_custodian_sha256
            || expected != self.transfer_sha256
        {
            return Err(EvolutionError::InvalidStewardship(
                "custody transfer closure".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RootRotationPlan {
    pub rotation_id: String,
    pub custody_transfer_sha256: String,
    pub old_roots: BTreeMap<String, String>,
    pub new_roots: BTreeMap<String, String>,
    pub overlap_ticks: u64,
    pub compromise_declared: bool,
    pub plan_sha256: String,
}

impl RootRotationPlan {
    pub fn new(
        rotation_id: impl Into<String>,
        transfer: &CustodyTransfer,
        old_roots: BTreeMap<String, String>,
        new_roots: BTreeMap<String, String>,
        overlap_ticks: u64,
        compromise_declared: bool,
    ) -> Result<Self, EvolutionError> {
        let rotation_id = rotation_id.into();
        validate_identifier(&rotation_id, "root rotation")?;
        validate_hash_map(&old_roots, "old root", MAX_COMPONENTS)?;
        validate_hash_map(&new_roots, "new root", MAX_COMPONENTS)?;
        if old_roots.keys().collect::<BTreeSet<_>>() != new_roots.keys().collect::<BTreeSet<_>>()
            || old_roots
                .iter()
                .any(|(name, old)| new_roots.get(name).is_some_and(|new| new == old))
            || overlap_ticks == 0
            || overlap_ticks > MAX_ROTATION_OVERLAP_TICKS
        {
            return Err(EvolutionError::InvalidStewardship(
                "root rotation coverage, reuse or overlap".into(),
            ));
        }
        let custody_transfer_sha256 = transfer.transfer_sha256.clone();
        let plan_sha256 = hash_serializable(&(
            &rotation_id,
            &custody_transfer_sha256,
            &old_roots,
            &new_roots,
            overlap_ticks,
            compromise_declared,
        ))?;
        Ok(Self {
            rotation_id,
            custody_transfer_sha256,
            old_roots,
            new_roots,
            overlap_ticks,
            compromise_declared,
            plan_sha256,
        })
    }

    pub fn verify(&self, transfer: &CustodyTransfer) -> Result<(), EvolutionError> {
        let expected = hash_serializable(&(
            &self.rotation_id,
            &self.custody_transfer_sha256,
            &self.old_roots,
            &self.new_roots,
            self.overlap_ticks,
            self.compromise_declared,
        ))?;
        if self.custody_transfer_sha256 != transfer.transfer_sha256
            || self.old_roots.keys().collect::<BTreeSet<_>>()
                != self.new_roots.keys().collect::<BTreeSet<_>>()
            || self
                .old_roots
                .iter()
                .any(|(name, old)| self.new_roots.get(name).is_some_and(|new| new == old))
            || self.overlap_ticks == 0
            || self.overlap_ticks > MAX_ROTATION_OVERLAP_TICKS
            || expected != self.plan_sha256
        {
            return Err(EvolutionError::InvalidStewardship(
                "root rotation plan closure".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HistoricalAttestation {
    pub attestation_id: String,
    pub policy_snapshot_sha256: String,
    pub checkpoint_roots: BTreeMap<u32, String>,
    pub required_checkpoints: BTreeSet<u32>,
    pub independent_verifier_roots: BTreeMap<String, String>,
    pub attestation_sha256: String,
}

impl HistoricalAttestation {
    pub fn new(
        attestation_id: impl Into<String>,
        policy_snapshot_sha256: impl Into<String>,
        checkpoint_roots: BTreeMap<u32, String>,
        independent_verifier_roots: BTreeMap<String, String>,
    ) -> Result<Self, EvolutionError> {
        let attestation_id = attestation_id.into();
        let policy_snapshot_sha256 = policy_snapshot_sha256.into();
        validate_identifier(&attestation_id, "historical attestation")?;
        validate_sha256(&policy_snapshot_sha256, "historical policy")?;
        let required_checkpoints = BTreeSet::from([0, 29, 47, 65, 83, 101, 107, 113]);
        if checkpoint_roots.keys().copied().collect::<BTreeSet<_>>() != required_checkpoints
            || checkpoint_roots
                .values()
                .any(|value| validate_sha256(value, "checkpoint root").is_err())
        {
            return Err(EvolutionError::InvalidStewardship(
                "historical checkpoint coverage".into(),
            ));
        }
        validate_hash_map(
            &independent_verifier_roots,
            "historical verifier",
            MAX_STEWARDS,
        )?;
        if independent_verifier_roots.len() < 3 {
            return Err(EvolutionError::InvalidStewardship(
                "historical verifier diversity".into(),
            ));
        }
        let attestation_sha256 = hash_serializable(&(
            &attestation_id,
            &policy_snapshot_sha256,
            &checkpoint_roots,
            &required_checkpoints,
            &independent_verifier_roots,
        ))?;
        Ok(Self {
            attestation_id,
            policy_snapshot_sha256,
            checkpoint_roots,
            required_checkpoints,
            independent_verifier_roots,
            attestation_sha256,
        })
    }

    pub fn verify(&self) -> Result<(), EvolutionError> {
        let expected_checkpoints = BTreeSet::from([0, 29, 47, 65, 83, 101, 107, 113]);
        let expected = hash_serializable(&(
            &self.attestation_id,
            &self.policy_snapshot_sha256,
            &self.checkpoint_roots,
            &self.required_checkpoints,
            &self.independent_verifier_roots,
        ))?;
        if self.required_checkpoints != expected_checkpoints
            || self
                .checkpoint_roots
                .keys()
                .copied()
                .collect::<BTreeSet<_>>()
                != expected_checkpoints
            || self.independent_verifier_roots.len() < 3
            || expected != self.attestation_sha256
        {
            return Err(EvolutionError::InvalidStewardship(
                "historical attestation closure".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PostLifecycleClosureCertificate {
    pub certificate_id: String,
    pub policy_snapshot_sha256: String,
    pub lifecycle_closure_certificate_sha256: String,
    pub evolution_release_certificate_sha256: String,
    pub generation_continuity_certificate_sha256: String,
    pub stewardship_charter_sha256: String,
    pub succession_quorum_sha256: String,
    pub custody_transfer_sha256: String,
    pub root_rotation_plan_sha256: String,
    pub historical_attestation_sha256: String,
    pub closed_milestones: BTreeSet<u32>,
    pub authority_audit_tail_hash: String,
    pub certificate_sha256: String,
}

impl PostLifecycleClosureCertificate {
    pub fn verify(&self) -> Result<(), EvolutionError> {
        let expected_milestones = (0_u32..=119).collect::<BTreeSet<_>>();
        let expected = hash_serializable(&(
            &self.certificate_id,
            &self.policy_snapshot_sha256,
            &self.lifecycle_closure_certificate_sha256,
            &self.evolution_release_certificate_sha256,
            &self.generation_continuity_certificate_sha256,
            &self.stewardship_charter_sha256,
            &self.succession_quorum_sha256,
            &self.custody_transfer_sha256,
            &self.root_rotation_plan_sha256,
            &self.historical_attestation_sha256,
            &self.closed_milestones,
            &self.authority_audit_tail_hash,
        ))?;
        if self.closed_milestones != expected_milestones || expected != self.certificate_sha256 {
            return Err(EvolutionError::InvalidStewardship(
                "post-lifecycle closure milestone or digest".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct PostLifecycleClosureAuthority {
    authority_id: String,
    policy_snapshot_sha256: String,
    audit: EvolutionAuditChain,
}

impl PostLifecycleClosureAuthority {
    pub fn new(
        authority_id: impl Into<String>,
        policy_snapshot_sha256: impl Into<String>,
        audit_genesis: impl Into<String>,
    ) -> Result<Self, EvolutionError> {
        let authority_id = authority_id.into();
        let policy_snapshot_sha256 = policy_snapshot_sha256.into();
        validate_identifier(&authority_id, "post-lifecycle authority")?;
        validate_sha256(&policy_snapshot_sha256, "post-lifecycle policy")?;
        Ok(Self {
            authority_id,
            policy_snapshot_sha256,
            audit: EvolutionAuditChain::new(audit_genesis)?,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn certify(
        &mut self,
        lifecycle: &LifecycleClosureCertificate,
        evolution: &EvolutionReleaseCertificate,
        continuity: &GenerationContinuityCertificate,
        charter: &StewardshipCharter,
        quorum: &SuccessionQuorum,
        transfer: &CustodyTransfer,
        rotation: &RootRotationPlan,
        history: &HistoricalAttestation,
    ) -> Result<PostLifecycleClosureCertificate, EvolutionError> {
        lifecycle
            .verify()
            .map_err(|error| EvolutionError::BindingDenied(error.to_string()))?;
        evolution.verify()?;
        continuity.verify()?;
        charter.verify()?;
        quorum.verify(charter)?;
        transfer.verify(charter, quorum)?;
        rotation.verify(transfer)?;
        history.verify()?;
        if [
            lifecycle.policy_snapshot_sha256.as_str(),
            evolution.policy_snapshot_sha256.as_str(),
            continuity.policy_snapshot_sha256.as_str(),
            charter.policy_snapshot_sha256.as_str(),
            history.policy_snapshot_sha256.as_str(),
        ]
        .into_iter()
        .any(|policy| policy != self.policy_snapshot_sha256)
            || evolution.lifecycle_closure_certificate_sha256 != lifecycle.certificate_sha256
            || continuity.evolution_release_certificate_sha256 != evolution.certificate_sha256
            || charter.generation_continuity_certificate_sha256 != continuity.certificate_sha256
        {
            return Err(EvolutionError::BindingDenied(
                "post-lifecycle certificate chain".into(),
            ));
        }
        let closed_milestones = (0_u32..=119).collect::<BTreeSet<_>>();
        let seed = hash_serializable(&(
            &self.authority_id,
            &lifecycle.certificate_sha256,
            &evolution.certificate_sha256,
            &continuity.certificate_sha256,
            &charter.charter_sha256,
            &quorum.quorum_sha256,
            &transfer.transfer_sha256,
            &rotation.plan_sha256,
            &history.attestation_sha256,
            &closed_milestones,
        ))?;
        let certificate_id = format!("post-lifecycle-closure-{}", &seed[..24]);
        self.audit.append(EvolutionAuditEvent {
            action: "post_lifecycle_closure_certified".into(),
            subject_id: certificate_id.clone(),
            outcome: "closed".into(),
            metadata: BTreeMap::from([
                (
                    "evolution_sha256".into(),
                    evolution.certificate_sha256.clone(),
                ),
                (
                    "continuity_sha256".into(),
                    continuity.certificate_sha256.clone(),
                ),
                ("history_sha256".into(), history.attestation_sha256.clone()),
            ]),
        })?;
        let authority_audit_tail_hash = self.audit.tail_hash().to_owned();
        let certificate_sha256 = hash_serializable(&(
            &certificate_id,
            &self.policy_snapshot_sha256,
            &lifecycle.certificate_sha256,
            &evolution.certificate_sha256,
            &continuity.certificate_sha256,
            &charter.charter_sha256,
            &quorum.quorum_sha256,
            &transfer.transfer_sha256,
            &rotation.plan_sha256,
            &history.attestation_sha256,
            &closed_milestones,
            &authority_audit_tail_hash,
        ))?;
        let certificate = PostLifecycleClosureCertificate {
            certificate_id,
            policy_snapshot_sha256: self.policy_snapshot_sha256.clone(),
            lifecycle_closure_certificate_sha256: lifecycle.certificate_sha256.clone(),
            evolution_release_certificate_sha256: evolution.certificate_sha256.clone(),
            generation_continuity_certificate_sha256: continuity.certificate_sha256.clone(),
            stewardship_charter_sha256: charter.charter_sha256.clone(),
            succession_quorum_sha256: quorum.quorum_sha256.clone(),
            custody_transfer_sha256: transfer.transfer_sha256.clone(),
            root_rotation_plan_sha256: rotation.plan_sha256.clone(),
            historical_attestation_sha256: history.attestation_sha256.clone(),
            closed_milestones,
            authority_audit_tail_hash,
            certificate_sha256,
        };
        certificate.verify()?;
        Ok(certificate)
    }

    pub fn audit(&self) -> &EvolutionAuditChain {
        &self.audit
    }
}
