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
