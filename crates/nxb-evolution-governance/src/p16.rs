use std::collections::{BTreeMap, BTreeSet};

use nxb_lifecycle_governance::LifecycleClosureCertificate;
use serde::{Deserialize, Serialize};

use crate::{
    hash_serializable, validate_hash_map, validate_identifier, validate_sha256,
    EvolutionAuditChain, EvolutionAuditEvent, EvolutionError, MAX_CANARY_SAMPLES, MAX_COMPONENTS,
    MAX_STEPS,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvolutionBaseline {
    pub evolution_id: String,
    pub policy_snapshot_sha256: String,
    pub lifecycle_closure_certificate_sha256: String,
    pub tombstone_certificate_sha256: String,
    pub closed_milestones_sha256: String,
    pub baseline_sha256: String,
}

impl EvolutionBaseline {
    pub fn new(
        evolution_id: impl Into<String>,
        lifecycle: &LifecycleClosureCertificate,
    ) -> Result<Self, EvolutionError> {
        lifecycle
            .verify()
            .map_err(|error| EvolutionError::BindingDenied(error.to_string()))?;
        let evolution_id = evolution_id.into();
        validate_identifier(&evolution_id, "evolution baseline")?;
        let policy_snapshot_sha256 = lifecycle.policy_snapshot_sha256.clone();
        let lifecycle_closure_certificate_sha256 = lifecycle.certificate_sha256.clone();
        let tombstone_certificate_sha256 = lifecycle.tombstone_certificate_sha256.clone();
        let closed_milestones_sha256 = hash_serializable(&lifecycle.closed_milestones)?;
        let baseline_sha256 = hash_serializable(&(
            &evolution_id,
            &policy_snapshot_sha256,
            &lifecycle_closure_certificate_sha256,
            &tombstone_certificate_sha256,
            &closed_milestones_sha256,
        ))?;
        Ok(Self {
            evolution_id,
            policy_snapshot_sha256,
            lifecycle_closure_certificate_sha256,
            tombstone_certificate_sha256,
            closed_milestones_sha256,
            baseline_sha256,
        })
    }

    pub fn verify(&self) -> Result<(), EvolutionError> {
        validate_identifier(&self.evolution_id, "evolution baseline")?;
        for (name, value) in [
            ("evolution policy", self.policy_snapshot_sha256.as_str()),
            (
                "lifecycle closure certificate",
                self.lifecycle_closure_certificate_sha256.as_str(),
            ),
            (
                "baseline tombstone certificate",
                self.tombstone_certificate_sha256.as_str(),
            ),
            (
                "baseline milestone root",
                self.closed_milestones_sha256.as_str(),
            ),
            ("evolution baseline", self.baseline_sha256.as_str()),
        ] {
            validate_sha256(value, name)?;
        }
        let expected = hash_serializable(&(
            &self.evolution_id,
            &self.policy_snapshot_sha256,
            &self.lifecycle_closure_certificate_sha256,
            &self.tombstone_certificate_sha256,
            &self.closed_milestones_sha256,
        ))?;
        if expected != self.baseline_sha256 {
            return Err(EvolutionError::InvalidEvolution(
                "baseline digest mismatch".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum EvolutionClass {
    SchemaOnly,
    MetadataOnly,
    CompatibilityRepair,
    InvariantTightening,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvolutionProposal {
    pub proposal_id: String,
    pub baseline_sha256: String,
    pub policy_snapshot_sha256: String,
    pub class: EvolutionClass,
    pub component_deltas: BTreeMap<String, String>,
    pub invariant_deltas: BTreeMap<String, String>,
    pub created_tick: u64,
    pub expires_tick: u64,
    pub proposal_sha256: String,
}

impl EvolutionProposal {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        proposal_id: impl Into<String>,
        baseline: &EvolutionBaseline,
        class: EvolutionClass,
        component_deltas: BTreeMap<String, String>,
        invariant_deltas: BTreeMap<String, String>,
        created_tick: u64,
        expires_tick: u64,
    ) -> Result<Self, EvolutionError> {
        baseline.verify()?;
        let proposal_id = proposal_id.into();
        validate_identifier(&proposal_id, "evolution proposal")?;
        validate_hash_map(&component_deltas, "component delta", MAX_COMPONENTS)?;
        validate_hash_map(&invariant_deltas, "invariant delta", MAX_COMPONENTS)?;
        if expires_tick <= created_tick || expires_tick - created_tick > 30 * 24 * 60 * 60 {
            return Err(EvolutionError::InvalidEvolution(
                "proposal lifetime is invalid".into(),
            ));
        }
        let baseline_sha256 = baseline.baseline_sha256.clone();
        let policy_snapshot_sha256 = baseline.policy_snapshot_sha256.clone();
        let proposal_sha256 = hash_serializable(&(
            &proposal_id,
            &baseline_sha256,
            &policy_snapshot_sha256,
            class,
            &component_deltas,
            &invariant_deltas,
            created_tick,
            expires_tick,
        ))?;
        Ok(Self {
            proposal_id,
            baseline_sha256,
            policy_snapshot_sha256,
            class,
            component_deltas,
            invariant_deltas,
            created_tick,
            expires_tick,
            proposal_sha256,
        })
    }

    pub fn verify(&self, now_tick: u64) -> Result<(), EvolutionError> {
        validate_identifier(&self.proposal_id, "evolution proposal")?;
        validate_hash_map(&self.component_deltas, "component delta", MAX_COMPONENTS)?;
        validate_hash_map(&self.invariant_deltas, "invariant delta", MAX_COMPONENTS)?;
        if now_tick < self.created_tick || now_tick >= self.expires_tick {
            return Err(EvolutionError::InvalidEvolution(
                "proposal is outside its lifetime".into(),
            ));
        }
        let expected = hash_serializable(&(
            &self.proposal_id,
            &self.baseline_sha256,
            &self.policy_snapshot_sha256,
            self.class,
            &self.component_deltas,
            &self.invariant_deltas,
            self.created_tick,
            self.expires_tick,
        ))?;
        if expected != self.proposal_sha256 {
            return Err(EvolutionError::InvalidEvolution(
                "proposal digest mismatch".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CompatibilityImpactGraph {
    pub proposal_sha256: String,
    pub component_roots: BTreeMap<String, String>,
    pub dependency_edges: BTreeSet<(String, String)>,
    pub impacted_components: BTreeSet<String>,
    pub graph_sha256: String,
}

impl CompatibilityImpactGraph {
    pub fn new(
        proposal: &EvolutionProposal,
        component_roots: BTreeMap<String, String>,
        dependency_edges: BTreeSet<(String, String)>,
        impacted_components: BTreeSet<String>,
    ) -> Result<Self, EvolutionError> {
        validate_hash_map(&component_roots, "impact component", MAX_COMPONENTS)?;
        if dependency_edges.len() > MAX_COMPONENTS * 4
            || impacted_components.is_empty()
            || impacted_components.len() > MAX_COMPONENTS
            || !proposal
                .component_deltas
                .keys()
                .all(|component| impacted_components.contains(component))
            || !impacted_components
                .iter()
                .all(|component| component_roots.contains_key(component))
            || dependency_edges.iter().any(|(from, to)| {
                from == to
                    || !component_roots.contains_key(from)
                    || !component_roots.contains_key(to)
            })
        {
            return Err(EvolutionError::InvalidEvolution(
                "impact graph is incomplete or invalid".into(),
            ));
        }
        let proposal_sha256 = proposal.proposal_sha256.clone();
        let graph_sha256 = hash_serializable(&(
            &proposal_sha256,
            &component_roots,
            &dependency_edges,
            &impacted_components,
        ))?;
        Ok(Self {
            proposal_sha256,
            component_roots,
            dependency_edges,
            impacted_components,
            graph_sha256,
        })
    }

    pub fn verify(&self, proposal: &EvolutionProposal) -> Result<(), EvolutionError> {
        if self.proposal_sha256 != proposal.proposal_sha256
            || !proposal
                .component_deltas
                .keys()
                .all(|component| self.impacted_components.contains(component))
        {
            return Err(EvolutionError::BindingDenied(
                "impact graph proposal binding".into(),
            ));
        }
        let expected = hash_serializable(&(
            &self.proposal_sha256,
            &self.component_roots,
            &self.dependency_edges,
            &self.impacted_components,
        ))?;
        if expected != self.graph_sha256 {
            return Err(EvolutionError::InvalidEvolution(
                "impact graph digest mismatch".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MigrationCapsule {
    pub capsule_id: String,
    pub proposal_sha256: String,
    pub from_generation: u32,
    pub to_generation: u32,
    pub forward_steps: BTreeMap<String, String>,
    pub rollback_steps: BTreeMap<String, String>,
    pub pre_state_schema_sha256: String,
    pub post_state_schema_sha256: String,
    pub reversible: bool,
    pub capsule_sha256: String,
}

impl MigrationCapsule {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        capsule_id: impl Into<String>,
        proposal: &EvolutionProposal,
        from_generation: u32,
        to_generation: u32,
        forward_steps: BTreeMap<String, String>,
        rollback_steps: BTreeMap<String, String>,
        pre_state_schema_sha256: impl Into<String>,
        post_state_schema_sha256: impl Into<String>,
    ) -> Result<Self, EvolutionError> {
        let capsule_id = capsule_id.into();
        let pre_state_schema_sha256 = pre_state_schema_sha256.into();
        let post_state_schema_sha256 = post_state_schema_sha256.into();
        validate_identifier(&capsule_id, "migration capsule")?;
        validate_hash_map(&forward_steps, "forward migration step", MAX_STEPS)?;
        validate_hash_map(&rollback_steps, "rollback migration step", MAX_STEPS)?;
        validate_sha256(&pre_state_schema_sha256, "pre-state schema")?;
        validate_sha256(&post_state_schema_sha256, "post-state schema")?;
        if from_generation == 0
            || to_generation != from_generation.saturating_add(1)
            || forward_steps.keys().collect::<BTreeSet<_>>()
                != rollback_steps.keys().collect::<BTreeSet<_>>()
        {
            return Err(EvolutionError::InvalidEvolution(
                "migration path is not exactly reversible".into(),
            ));
        }
        let proposal_sha256 = proposal.proposal_sha256.clone();
        let reversible = true;
        let capsule_sha256 = hash_serializable(&(
            &capsule_id,
            &proposal_sha256,
            from_generation,
            to_generation,
            &forward_steps,
            &rollback_steps,
            &pre_state_schema_sha256,
            &post_state_schema_sha256,
            reversible,
        ))?;
        Ok(Self {
            capsule_id,
            proposal_sha256,
            from_generation,
            to_generation,
            forward_steps,
            rollback_steps,
            pre_state_schema_sha256,
            post_state_schema_sha256,
            reversible,
            capsule_sha256,
        })
    }

    pub fn verify(&self, proposal: &EvolutionProposal) -> Result<(), EvolutionError> {
        let expected = hash_serializable(&(
            &self.capsule_id,
            &self.proposal_sha256,
            self.from_generation,
            self.to_generation,
            &self.forward_steps,
            &self.rollback_steps,
            &self.pre_state_schema_sha256,
            &self.post_state_schema_sha256,
            self.reversible,
        ))?;
        if self.proposal_sha256 != proposal.proposal_sha256
            || !self.reversible
            || self.to_generation != self.from_generation.saturating_add(1)
            || self.forward_steps.keys().collect::<BTreeSet<_>>()
                != self.rollback_steps.keys().collect::<BTreeSet<_>>()
            || expected != self.capsule_sha256
        {
            return Err(EvolutionError::InvalidEvolution(
                "migration capsule closure".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CanarySample {
    pub fixture_id: String,
    pub baseline_output_sha256: String,
    pub candidate_output_sha256: String,
    pub invariant_result_sha256: String,
    pub deterministic: bool,
    pub sample_sha256: String,
}

impl CanarySample {
    pub fn new(
        fixture_id: impl Into<String>,
        baseline_output_sha256: impl Into<String>,
        candidate_output_sha256: impl Into<String>,
        invariant_result_sha256: impl Into<String>,
        deterministic: bool,
    ) -> Result<Self, EvolutionError> {
        let fixture_id = fixture_id.into();
        let baseline_output_sha256 = baseline_output_sha256.into();
        let candidate_output_sha256 = candidate_output_sha256.into();
        let invariant_result_sha256 = invariant_result_sha256.into();
        validate_identifier(&fixture_id, "canary fixture")?;
        validate_sha256(&baseline_output_sha256, "canary baseline output")?;
        validate_sha256(&candidate_output_sha256, "canary candidate output")?;
        validate_sha256(&invariant_result_sha256, "canary invariant result")?;
        let sample_sha256 = hash_serializable(&(
            &fixture_id,
            &baseline_output_sha256,
            &candidate_output_sha256,
            &invariant_result_sha256,
            deterministic,
        ))?;
        Ok(Self {
            fixture_id,
            baseline_output_sha256,
            candidate_output_sha256,
            invariant_result_sha256,
            deterministic,
            sample_sha256,
        })
    }

    pub fn verify(&self) -> Result<(), EvolutionError> {
        let expected = hash_serializable(&(
            &self.fixture_id,
            &self.baseline_output_sha256,
            &self.candidate_output_sha256,
            &self.invariant_result_sha256,
            self.deterministic,
        ))?;
        if !self.deterministic || expected != self.sample_sha256 {
            return Err(EvolutionError::InvalidEvolution(
                "canary sample is not deterministic".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CanaryMatrix {
    pub proposal_sha256: String,
    pub capsule_sha256: String,
    pub samples: BTreeMap<String, CanarySample>,
    pub required_fixture_ids: BTreeSet<String>,
    pub matrix_sha256: String,
}

impl CanaryMatrix {
    pub fn new(
        proposal: &EvolutionProposal,
        capsule: &MigrationCapsule,
        samples: Vec<CanarySample>,
        required_fixture_ids: BTreeSet<String>,
    ) -> Result<Self, EvolutionError> {
        if samples.is_empty()
            || samples.len() > MAX_CANARY_SAMPLES
            || required_fixture_ids.is_empty()
            || required_fixture_ids.len() > MAX_CANARY_SAMPLES
        {
            return Err(EvolutionError::InvalidEvolution(
                "canary sample count".into(),
            ));
        }
        let mut sample_map = BTreeMap::new();
        for sample in samples {
            sample.verify()?;
            if sample_map
                .insert(sample.fixture_id.clone(), sample)
                .is_some()
            {
                return Err(EvolutionError::InvalidEvolution(
                    "duplicate canary fixture".into(),
                ));
            }
        }
        if sample_map.keys().cloned().collect::<BTreeSet<_>>() != required_fixture_ids {
            return Err(EvolutionError::InvalidEvolution(
                "canary fixture coverage mismatch".into(),
            ));
        }
        let proposal_sha256 = proposal.proposal_sha256.clone();
        let capsule_sha256 = capsule.capsule_sha256.clone();
        let matrix_sha256 = hash_serializable(&(
            &proposal_sha256,
            &capsule_sha256,
            &sample_map,
            &required_fixture_ids,
        ))?;
        Ok(Self {
            proposal_sha256,
            capsule_sha256,
            samples: sample_map,
            required_fixture_ids,
            matrix_sha256,
        })
    }

    pub fn verify(
        &self,
        proposal: &EvolutionProposal,
        capsule: &MigrationCapsule,
    ) -> Result<(), EvolutionError> {
        if self.proposal_sha256 != proposal.proposal_sha256
            || self.capsule_sha256 != capsule.capsule_sha256
            || self.samples.keys().cloned().collect::<BTreeSet<_>>() != self.required_fixture_ids
            || self.samples.values().any(|sample| sample.verify().is_err())
        {
            return Err(EvolutionError::BindingDenied(
                "canary matrix binding".into(),
            ));
        }
        let expected = hash_serializable(&(
            &self.proposal_sha256,
            &self.capsule_sha256,
            &self.samples,
            &self.required_fixture_ids,
        ))?;
        if expected != self.matrix_sha256 {
            return Err(EvolutionError::InvalidEvolution(
                "canary matrix digest mismatch".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvolutionReleaseCertificate {
    pub certificate_id: String,
    pub policy_snapshot_sha256: String,
    pub lifecycle_closure_certificate_sha256: String,
    pub baseline_sha256: String,
    pub proposal_sha256: String,
    pub impact_graph_sha256: String,
    pub migration_capsule_sha256: String,
    pub canary_matrix_sha256: String,
    pub authority_audit_tail_hash: String,
    pub certificate_sha256: String,
}

impl EvolutionReleaseCertificate {
    pub fn verify(&self) -> Result<(), EvolutionError> {
        for (name, value) in [
            ("evolution policy", self.policy_snapshot_sha256.as_str()),
            (
                "evolution lifecycle closure",
                self.lifecycle_closure_certificate_sha256.as_str(),
            ),
            ("evolution baseline", self.baseline_sha256.as_str()),
            ("evolution proposal", self.proposal_sha256.as_str()),
            ("evolution impact graph", self.impact_graph_sha256.as_str()),
            (
                "evolution migration capsule",
                self.migration_capsule_sha256.as_str(),
            ),
            (
                "evolution canary matrix",
                self.canary_matrix_sha256.as_str(),
            ),
            (
                "evolution authority audit",
                self.authority_audit_tail_hash.as_str(),
            ),
            (
                "evolution release certificate",
                self.certificate_sha256.as_str(),
            ),
        ] {
            validate_sha256(value, name)?;
        }
        let expected = hash_serializable(&(
            &self.certificate_id,
            &self.policy_snapshot_sha256,
            &self.lifecycle_closure_certificate_sha256,
            &self.baseline_sha256,
            &self.proposal_sha256,
            &self.impact_graph_sha256,
            &self.migration_capsule_sha256,
            &self.canary_matrix_sha256,
            &self.authority_audit_tail_hash,
        ))?;
        if expected != self.certificate_sha256 {
            return Err(EvolutionError::InvalidEvolution(
                "evolution release certificate digest".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct EvolutionReleaseAuthority {
    authority_id: String,
    policy_snapshot_sha256: String,
    audit: EvolutionAuditChain,
}

impl EvolutionReleaseAuthority {
    pub fn new(
        authority_id: impl Into<String>,
        policy_snapshot_sha256: impl Into<String>,
        audit_genesis: impl Into<String>,
    ) -> Result<Self, EvolutionError> {
        let authority_id = authority_id.into();
        let policy_snapshot_sha256 = policy_snapshot_sha256.into();
        validate_identifier(&authority_id, "evolution release authority")?;
        validate_sha256(&policy_snapshot_sha256, "evolution release policy")?;
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
        baseline: &EvolutionBaseline,
        proposal: &EvolutionProposal,
        graph: &CompatibilityImpactGraph,
        capsule: &MigrationCapsule,
        canary: &CanaryMatrix,
        now_tick: u64,
    ) -> Result<EvolutionReleaseCertificate, EvolutionError> {
        lifecycle
            .verify()
            .map_err(|error| EvolutionError::BindingDenied(error.to_string()))?;
        baseline.verify()?;
        proposal.verify(now_tick)?;
        graph.verify(proposal)?;
        capsule.verify(proposal)?;
        canary.verify(proposal, capsule)?;
        if lifecycle.policy_snapshot_sha256 != self.policy_snapshot_sha256
            || baseline.policy_snapshot_sha256 != self.policy_snapshot_sha256
            || baseline.lifecycle_closure_certificate_sha256 != lifecycle.certificate_sha256
            || proposal.baseline_sha256 != baseline.baseline_sha256
            || proposal.policy_snapshot_sha256 != self.policy_snapshot_sha256
        {
            return Err(EvolutionError::BindingDenied(
                "evolution release certificate policy chain".into(),
            ));
        }
        let seed = hash_serializable(&(
            &self.authority_id,
            &lifecycle.certificate_sha256,
            &baseline.baseline_sha256,
            &proposal.proposal_sha256,
            &graph.graph_sha256,
            &capsule.capsule_sha256,
            &canary.matrix_sha256,
        ))?;
        let certificate_id = format!("evolution-release-{}", &seed[..24]);
        self.audit.append(EvolutionAuditEvent {
            action: "evolution_release_certified".into(),
            subject_id: certificate_id.clone(),
            outcome: "certified".into(),
            metadata: BTreeMap::from([
                ("proposal_sha256".into(), proposal.proposal_sha256.clone()),
                ("canary_matrix_sha256".into(), canary.matrix_sha256.clone()),
            ]),
        })?;
        let authority_audit_tail_hash = self.audit.tail_hash().to_owned();
        let certificate_sha256 = hash_serializable(&(
            &certificate_id,
            &self.policy_snapshot_sha256,
            &lifecycle.certificate_sha256,
            &baseline.baseline_sha256,
            &proposal.proposal_sha256,
            &graph.graph_sha256,
            &capsule.capsule_sha256,
            &canary.matrix_sha256,
            &authority_audit_tail_hash,
        ))?;
        let certificate = EvolutionReleaseCertificate {
            certificate_id,
            policy_snapshot_sha256: self.policy_snapshot_sha256.clone(),
            lifecycle_closure_certificate_sha256: lifecycle.certificate_sha256.clone(),
            baseline_sha256: baseline.baseline_sha256.clone(),
            proposal_sha256: proposal.proposal_sha256.clone(),
            impact_graph_sha256: graph.graph_sha256.clone(),
            migration_capsule_sha256: capsule.capsule_sha256.clone(),
            canary_matrix_sha256: canary.matrix_sha256.clone(),
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
