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

