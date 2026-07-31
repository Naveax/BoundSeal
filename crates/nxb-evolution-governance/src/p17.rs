use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{
    hash_serializable, validate_hash_map, validate_identifier, validate_sha256,
    EvolutionAuditChain, EvolutionAuditEvent, EvolutionError, EvolutionReleaseCertificate,
    MigrationCapsule, MAX_CANARY_SAMPLES, MAX_GENERATIONS, MAX_STEPS,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GenerationRecord {
    pub generation: u32,
    pub parent_generation: Option<u32>,
    pub release_certificate_sha256: String,
    pub state_schema_sha256: String,
    pub component_root_sha256: String,
    pub record_sha256: String,
}

impl GenerationRecord {
    pub fn new(
        generation: u32,
        parent_generation: Option<u32>,
        release_certificate_sha256: impl Into<String>,
        state_schema_sha256: impl Into<String>,
        component_root_sha256: impl Into<String>,
    ) -> Result<Self, EvolutionError> {
        let release_certificate_sha256 = release_certificate_sha256.into();
        let state_schema_sha256 = state_schema_sha256.into();
        let component_root_sha256 = component_root_sha256.into();
        validate_sha256(&release_certificate_sha256, "generation release")?;
        validate_sha256(&state_schema_sha256, "generation state schema")?;
        validate_sha256(&component_root_sha256, "generation component root")?;
        if generation == 0
            || match parent_generation {
                None => generation != 1,
                Some(parent) => parent.saturating_add(1) != generation,
            }
        {
            return Err(EvolutionError::InvalidGeneration(
                "generation parent relation".into(),
            ));
        }
        let record_sha256 = hash_serializable(&(
            generation,
            parent_generation,
            &release_certificate_sha256,
            &state_schema_sha256,
            &component_root_sha256,
        ))?;
        Ok(Self {
            generation,
            parent_generation,
            release_certificate_sha256,
            state_schema_sha256,
            component_root_sha256,
            record_sha256,
        })
    }

    pub fn verify(&self) -> Result<(), EvolutionError> {
        let expected = hash_serializable(&(
            self.generation,
            self.parent_generation,
            &self.release_certificate_sha256,
            &self.state_schema_sha256,
            &self.component_root_sha256,
        ))?;
        if self.generation == 0
            || match self.parent_generation {
                None => self.generation != 1,
                Some(parent) => parent.saturating_add(1) != self.generation,
            }
            || expected != self.record_sha256
        {
            return Err(EvolutionError::InvalidGeneration(
                "generation record closure".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GenerationRegistry {
    pub policy_snapshot_sha256: String,
    pub generations: BTreeMap<u32, GenerationRecord>,
    pub lineage_edges: BTreeSet<(u32, u32)>,
    pub registry_sha256: String,
}

impl GenerationRegistry {
    pub fn new(
        policy_snapshot_sha256: impl Into<String>,
        generations: Vec<GenerationRecord>,
    ) -> Result<Self, EvolutionError> {
        let policy_snapshot_sha256 = policy_snapshot_sha256.into();
        validate_sha256(&policy_snapshot_sha256, "generation registry policy")?;
        if generations.is_empty() || generations.len() > MAX_GENERATIONS {
            return Err(EvolutionError::InvalidGeneration(
                "generation registry count".into(),
            ));
        }
        let mut map = BTreeMap::new();
        let mut edges = BTreeSet::new();
        for record in generations {
            record.verify()?;
            if let Some(parent) = record.parent_generation {
                edges.insert((parent, record.generation));
            }
            if map.insert(record.generation, record).is_some() {
                return Err(EvolutionError::InvalidGeneration(
                    "duplicate generation".into(),
                ));
            }
        }
        let expected_keys = (1_u32..=map.len() as u32).collect::<BTreeSet<_>>();
        if map.keys().copied().collect::<BTreeSet<_>>() != expected_keys
            || edges
                != (2_u32..=map.len() as u32)
                    .map(|generation| (generation - 1, generation))
                    .collect()
        {
            return Err(EvolutionError::InvalidGeneration(
                "generation lineage is not a single chain".into(),
            ));
        }
        let registry_sha256 = hash_serializable(&(&policy_snapshot_sha256, &map, &edges))?;
        Ok(Self {
            policy_snapshot_sha256,
            generations: map,
            lineage_edges: edges,
            registry_sha256,
        })
    }

    pub fn verify(&self) -> Result<(), EvolutionError> {
        if self.generations.is_empty()
            || self.generations.len() > MAX_GENERATIONS
            || self
                .generations
                .values()
                .any(|record| record.verify().is_err())
        {
            return Err(EvolutionError::InvalidGeneration(
                "generation registry content".into(),
            ));
        }
        let expected_keys = (1_u32..=self.generations.len() as u32).collect::<BTreeSet<_>>();
        let expected_edges = (2_u32..=self.generations.len() as u32)
            .map(|generation| (generation - 1, generation))
            .collect::<BTreeSet<_>>();
        let expected = hash_serializable(&(
            &self.policy_snapshot_sha256,
            &self.generations,
            &self.lineage_edges,
        ))?;
        if self.generations.keys().copied().collect::<BTreeSet<_>>() != expected_keys
            || self.lineage_edges != expected_edges
            || expected != self.registry_sha256
        {
            return Err(EvolutionError::InvalidGeneration(
                "generation registry digest or lineage".into(),
            ));
        }
        Ok(())
    }

    pub fn latest_generation(&self) -> u32 {
        *self
            .generations
            .keys()
            .next_back()
            .expect("non-empty registry")
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransitionDirection {
    Upgrade,
    Downgrade,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GenerationTransitionPath {
    pub path_id: String,
    pub registry_sha256: String,
    pub from_generation: u32,
    pub to_generation: u32,
    pub direction: TransitionDirection,
    pub migration_capsule_sha256: String,
    pub ordered_step_receipts: BTreeMap<String, String>,
    pub path_sha256: String,
}

impl GenerationTransitionPath {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        path_id: impl Into<String>,
        registry: &GenerationRegistry,
        from_generation: u32,
        to_generation: u32,
        direction: TransitionDirection,
        capsule: &MigrationCapsule,
        ordered_step_receipts: BTreeMap<String, String>,
    ) -> Result<Self, EvolutionError> {
        registry.verify()?;
        capsule.verify_reference_only()?;
        let path_id = path_id.into();
        validate_identifier(&path_id, "generation transition path")?;
        validate_hash_map(&ordered_step_receipts, "transition step", MAX_STEPS)?;
        let valid_direction = match direction {
            TransitionDirection::Upgrade => {
                to_generation == from_generation.saturating_add(1)
                    && capsule.from_generation == from_generation
                    && capsule.to_generation == to_generation
                    && ordered_step_receipts.keys().collect::<BTreeSet<_>>()
                        == capsule.forward_steps.keys().collect::<BTreeSet<_>>()
            }
            TransitionDirection::Downgrade => {
                from_generation == to_generation.saturating_add(1)
                    && capsule.from_generation == to_generation
                    && capsule.to_generation == from_generation
                    && ordered_step_receipts.keys().collect::<BTreeSet<_>>()
                        == capsule.rollback_steps.keys().collect::<BTreeSet<_>>()
            }
        };
        if !valid_direction
            || !registry.generations.contains_key(&from_generation)
            || !registry.generations.contains_key(&to_generation)
        {
            return Err(EvolutionError::InvalidGeneration(
                "generation transition is not adjacent and reversible".into(),
            ));
        }
        let registry_sha256 = registry.registry_sha256.clone();
        let migration_capsule_sha256 = capsule.capsule_sha256.clone();
        let path_sha256 = hash_serializable(&(
            &path_id,
            &registry_sha256,
            from_generation,
            to_generation,
            direction,
            &migration_capsule_sha256,
            &ordered_step_receipts,
        ))?;
        Ok(Self {
            path_id,
            registry_sha256,
            from_generation,
            to_generation,
            direction,
            migration_capsule_sha256,
            ordered_step_receipts,
            path_sha256,
        })
    }

    pub fn verify(&self, registry: &GenerationRegistry) -> Result<(), EvolutionError> {
        let expected = hash_serializable(&(
            &self.path_id,
            &self.registry_sha256,
            self.from_generation,
            self.to_generation,
            self.direction,
            &self.migration_capsule_sha256,
            &self.ordered_step_receipts,
        ))?;
        if self.registry_sha256 != registry.registry_sha256
            || !registry.generations.contains_key(&self.from_generation)
            || !registry.generations.contains_key(&self.to_generation)
            || expected != self.path_sha256
        {
            return Err(EvolutionError::InvalidGeneration(
                "generation transition path binding".into(),
            ));
        }
        Ok(())
    }
}

trait CapsuleReferenceValidation {
    fn verify_reference_only(&self) -> Result<(), EvolutionError>;
}

impl CapsuleReferenceValidation for MigrationCapsule {
    fn verify_reference_only(&self) -> Result<(), EvolutionError> {
        validate_sha256(&self.proposal_sha256, "capsule proposal")?;
        validate_sha256(&self.capsule_sha256, "capsule digest")?;
        if !self.reversible
            || self.to_generation != self.from_generation.saturating_add(1)
            || self.forward_steps.keys().collect::<BTreeSet<_>>()
                != self.rollback_steps.keys().collect::<BTreeSet<_>>()
        {
            return Err(EvolutionError::InvalidGeneration(
                "capsule is not reversible".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShadowObservation {
    pub verifier_id: String,
    pub fixture_id: String,
    pub baseline_output_sha256: String,
    pub candidate_output_sha256: String,
    pub invariant_root_sha256: String,
    pub deterministic: bool,
    pub observation_sha256: String,
}

impl ShadowObservation {
    pub fn new(
        verifier_id: impl Into<String>,
        fixture_id: impl Into<String>,
        baseline_output_sha256: impl Into<String>,
        candidate_output_sha256: impl Into<String>,
        invariant_root_sha256: impl Into<String>,
        deterministic: bool,
    ) -> Result<Self, EvolutionError> {
        let verifier_id = verifier_id.into();
        let fixture_id = fixture_id.into();
        let baseline_output_sha256 = baseline_output_sha256.into();
        let candidate_output_sha256 = candidate_output_sha256.into();
        let invariant_root_sha256 = invariant_root_sha256.into();
        validate_identifier(&verifier_id, "shadow verifier")?;
        validate_identifier(&fixture_id, "shadow fixture")?;
        validate_sha256(&baseline_output_sha256, "shadow baseline")?;
        validate_sha256(&candidate_output_sha256, "shadow candidate")?;
        validate_sha256(&invariant_root_sha256, "shadow invariant")?;
        let observation_sha256 = hash_serializable(&(
            &verifier_id,
            &fixture_id,
            &baseline_output_sha256,
            &candidate_output_sha256,
            &invariant_root_sha256,
            deterministic,
        ))?;
        Ok(Self {
            verifier_id,
            fixture_id,
            baseline_output_sha256,
            candidate_output_sha256,
            invariant_root_sha256,
            deterministic,
            observation_sha256,
        })
    }

    pub fn verify(&self) -> Result<(), EvolutionError> {
        let expected = hash_serializable(&(
            &self.verifier_id,
            &self.fixture_id,
            &self.baseline_output_sha256,
            &self.candidate_output_sha256,
            &self.invariant_root_sha256,
            self.deterministic,
        ))?;
        if !self.deterministic || expected != self.observation_sha256 {
            return Err(EvolutionError::InvalidGeneration(
                "shadow observation is not deterministic".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShadowComparisonQuorum {
    pub transition_path_sha256: String,
    pub observations: BTreeMap<String, ShadowObservation>,
    pub required_fixture_ids: BTreeSet<String>,
    pub quorum_sha256: String,
}

impl ShadowComparisonQuorum {
    pub fn new(
        path: &GenerationTransitionPath,
        observations: Vec<ShadowObservation>,
        required_fixture_ids: BTreeSet<String>,
    ) -> Result<Self, EvolutionError> {
        if observations.len() < 2
            || observations.len() > MAX_CANARY_SAMPLES
            || required_fixture_ids.is_empty()
        {
            return Err(EvolutionError::InvalidGeneration(
                "shadow comparison sample count".into(),
            ));
        }
        let mut map = BTreeMap::new();
        let mut verifiers_by_fixture: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for observation in observations {
            observation.verify()?;
            let key = format!("{}:{}", observation.fixture_id, observation.verifier_id);
            verifiers_by_fixture
                .entry(observation.fixture_id.clone())
                .or_default()
                .insert(observation.verifier_id.clone());
            if map.insert(key, observation).is_some() {
                return Err(EvolutionError::InvalidGeneration(
                    "duplicate shadow observation".into(),
                ));
            }
        }
        if verifiers_by_fixture
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>()
            != required_fixture_ids
            || verifiers_by_fixture
                .values()
                .any(|verifiers| verifiers.len() < 2)
        {
            return Err(EvolutionError::InvalidGeneration(
                "shadow verifier diversity or fixture coverage".into(),
            ));
        }
        let transition_path_sha256 = path.path_sha256.clone();
        let quorum_sha256 =
            hash_serializable(&(&transition_path_sha256, &map, &required_fixture_ids))?;
        Ok(Self {
            transition_path_sha256,
            observations: map,
            required_fixture_ids,
            quorum_sha256,
        })
    }

    pub fn verify(&self, path: &GenerationTransitionPath) -> Result<(), EvolutionError> {
        if self.transition_path_sha256 != path.path_sha256
            || self
                .observations
                .values()
                .any(|observation| observation.verify().is_err())
        {
            return Err(EvolutionError::BindingDenied(
                "shadow comparison binding".into(),
            ));
        }
        let expected = hash_serializable(&(
            &self.transition_path_sha256,
            &self.observations,
            &self.required_fixture_ids,
        ))?;
        if expected != self.quorum_sha256 {
            return Err(EvolutionError::InvalidGeneration(
                "shadow quorum digest".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RollbackProof {
    pub transition_path_sha256: String,
    pub source_state_root_sha256: String,
    pub upgraded_state_root_sha256: String,
    pub restored_state_root_sha256: String,
    pub rollback_step_receipts: BTreeMap<String, String>,
    pub fully_restored: bool,
    pub proof_sha256: String,
}

impl RollbackProof {
    pub fn new(
        path: &GenerationTransitionPath,
        source_state_root_sha256: impl Into<String>,
        upgraded_state_root_sha256: impl Into<String>,
        restored_state_root_sha256: impl Into<String>,
        rollback_step_receipts: BTreeMap<String, String>,
    ) -> Result<Self, EvolutionError> {
        let source_state_root_sha256 = source_state_root_sha256.into();
        let upgraded_state_root_sha256 = upgraded_state_root_sha256.into();
        let restored_state_root_sha256 = restored_state_root_sha256.into();
        validate_sha256(&source_state_root_sha256, "rollback source state")?;
        validate_sha256(&upgraded_state_root_sha256, "rollback upgraded state")?;
        validate_sha256(&restored_state_root_sha256, "rollback restored state")?;
        validate_hash_map(&rollback_step_receipts, "rollback proof step", MAX_STEPS)?;
        let fully_restored = source_state_root_sha256 == restored_state_root_sha256
            && source_state_root_sha256 != upgraded_state_root_sha256;
        if !fully_restored {
            return Err(EvolutionError::InvalidGeneration(
                "rollback did not restore the source state".into(),
            ));
        }
        let transition_path_sha256 = path.path_sha256.clone();
        let proof_sha256 = hash_serializable(&(
            &transition_path_sha256,
            &source_state_root_sha256,
            &upgraded_state_root_sha256,
            &restored_state_root_sha256,
            &rollback_step_receipts,
            fully_restored,
        ))?;
        Ok(Self {
            transition_path_sha256,
            source_state_root_sha256,
            upgraded_state_root_sha256,
            restored_state_root_sha256,
            rollback_step_receipts,
            fully_restored,
            proof_sha256,
        })
    }

    pub fn verify(&self, path: &GenerationTransitionPath) -> Result<(), EvolutionError> {
        let expected = hash_serializable(&(
            &self.transition_path_sha256,
            &self.source_state_root_sha256,
            &self.upgraded_state_root_sha256,
            &self.restored_state_root_sha256,
            &self.rollback_step_receipts,
            self.fully_restored,
        ))?;
        if self.transition_path_sha256 != path.path_sha256
            || !self.fully_restored
            || self.source_state_root_sha256 != self.restored_state_root_sha256
            || expected != self.proof_sha256
        {
            return Err(EvolutionError::InvalidGeneration(
                "rollback proof closure".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GenerationContinuityCertificate {
    pub certificate_id: String,
    pub policy_snapshot_sha256: String,
    pub evolution_release_certificate_sha256: String,
    pub generation_registry_sha256: String,
    pub transition_path_sha256: String,
    pub shadow_quorum_sha256: String,
    pub rollback_proof_sha256: String,
    pub authority_audit_tail_hash: String,
    pub certificate_sha256: String,
}

impl GenerationContinuityCertificate {
    pub fn verify(&self) -> Result<(), EvolutionError> {
        for (name, value) in [
            ("generation policy", self.policy_snapshot_sha256.as_str()),
            (
                "generation evolution release",
                self.evolution_release_certificate_sha256.as_str(),
            ),
            (
                "generation registry",
                self.generation_registry_sha256.as_str(),
            ),
            (
                "generation transition",
                self.transition_path_sha256.as_str(),
            ),
            (
                "generation shadow quorum",
                self.shadow_quorum_sha256.as_str(),
            ),
            (
                "generation rollback proof",
                self.rollback_proof_sha256.as_str(),
            ),
            (
                "generation authority audit",
                self.authority_audit_tail_hash.as_str(),
            ),
            (
                "generation continuity certificate",
                self.certificate_sha256.as_str(),
            ),
        ] {
            validate_sha256(value, name)?;
        }
        let expected = hash_serializable(&(
            &self.certificate_id,
            &self.policy_snapshot_sha256,
            &self.evolution_release_certificate_sha256,
            &self.generation_registry_sha256,
            &self.transition_path_sha256,
            &self.shadow_quorum_sha256,
            &self.rollback_proof_sha256,
            &self.authority_audit_tail_hash,
        ))?;
        if expected != self.certificate_sha256 {
            return Err(EvolutionError::InvalidGeneration(
                "generation continuity certificate digest".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct GenerationContinuityAuthority {
    authority_id: String,
    policy_snapshot_sha256: String,
    audit: EvolutionAuditChain,
}

impl GenerationContinuityAuthority {
    pub fn new(
        authority_id: impl Into<String>,
        policy_snapshot_sha256: impl Into<String>,
        audit_genesis: impl Into<String>,
    ) -> Result<Self, EvolutionError> {
        let authority_id = authority_id.into();
        let policy_snapshot_sha256 = policy_snapshot_sha256.into();
        validate_identifier(&authority_id, "generation continuity authority")?;
        validate_sha256(&policy_snapshot_sha256, "generation continuity policy")?;
        Ok(Self {
            authority_id,
            policy_snapshot_sha256,
            audit: EvolutionAuditChain::new(audit_genesis)?,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn certify(
        &mut self,
        release: &EvolutionReleaseCertificate,
        registry: &GenerationRegistry,
        path: &GenerationTransitionPath,
        shadow: &ShadowComparisonQuorum,
        rollback: &RollbackProof,
    ) -> Result<GenerationContinuityCertificate, EvolutionError> {
        release.verify()?;
        registry.verify()?;
        path.verify(registry)?;
        shadow.verify(path)?;
        rollback.verify(path)?;
        if release.policy_snapshot_sha256 != self.policy_snapshot_sha256
            || registry.policy_snapshot_sha256 != self.policy_snapshot_sha256
            || path.from_generation != registry.latest_generation().saturating_sub(1)
            || path.to_generation != registry.latest_generation()
            || path.direction != TransitionDirection::Upgrade
        {
            return Err(EvolutionError::BindingDenied(
                "generation continuity policy or latest-generation binding".into(),
            ));
        }
        let seed = hash_serializable(&(
            &self.authority_id,
            &release.certificate_sha256,
            &registry.registry_sha256,
            &path.path_sha256,
            &shadow.quorum_sha256,
            &rollback.proof_sha256,
        ))?;
        let certificate_id = format!("generation-continuity-{}", &seed[..24]);
        self.audit.append(EvolutionAuditEvent {
            action: "generation_continuity_certified".into(),
            subject_id: certificate_id.clone(),
            outcome: "certified".into(),
            metadata: BTreeMap::from([
                ("registry_sha256".into(), registry.registry_sha256.clone()),
                (
                    "rollback_proof_sha256".into(),
                    rollback.proof_sha256.clone(),
                ),
            ]),
        })?;
        let authority_audit_tail_hash = self.audit.tail_hash().to_owned();
        let certificate_sha256 = hash_serializable(&(
            &certificate_id,
            &self.policy_snapshot_sha256,
            &release.certificate_sha256,
            &registry.registry_sha256,
            &path.path_sha256,
            &shadow.quorum_sha256,
            &rollback.proof_sha256,
            &authority_audit_tail_hash,
        ))?;
        let certificate = GenerationContinuityCertificate {
            certificate_id,
            policy_snapshot_sha256: self.policy_snapshot_sha256.clone(),
            evolution_release_certificate_sha256: release.certificate_sha256.clone(),
            generation_registry_sha256: registry.registry_sha256.clone(),
            transition_path_sha256: path.path_sha256.clone(),
            shadow_quorum_sha256: shadow.quorum_sha256.clone(),
            rollback_proof_sha256: rollback.proof_sha256.clone(),
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
