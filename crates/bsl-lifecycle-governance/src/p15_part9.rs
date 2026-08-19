impl LifecycleClosureAuthority {
    pub fn new(
        authority_id: impl Into<String>,
        policy_snapshot_sha256: impl Into<String>,
        audit_genesis: impl Into<String>,
    ) -> Result<Self, LifecycleError> {
        let authority_id = authority_id.into();
        let policy_snapshot_sha256 = policy_snapshot_sha256.into();
        validate_identifier(&authority_id, "lifecycle closure authority")?;
        validate_sha256(&policy_snapshot_sha256, "lifecycle closure policy")?;
        Ok(Self {
            authority_id,
            policy_snapshot_sha256,
            audit: LifecycleAuditChain::new(audit_genesis)?,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn certify(
        &mut self,
        final_assurance: &FinalAssuranceCertificate,
        roadmap: &RoadmapClosureCertificate,
        maintenance: &MaintenanceReleaseCertificate,
        continuity: &ContinuityCertificate,
        sample_plan: &EvidenceSamplePlan,
        verification_quorum: &IndependentVerificationQuorum,
        decommission: &DecommissionPlan,
        tombstone: &TombstoneCertificate,
    ) -> Result<LifecycleClosureCertificate, LifecycleError> {
        final_assurance
            .verify()
            .map_err(|error| LifecycleError::InvalidClosure(error.to_string()))?;
        roadmap
            .verify()
            .map_err(|error| LifecycleError::InvalidClosure(error.to_string()))?;
        maintenance.verify()?;
        continuity.verify()?;
        sample_plan.verify()?;
        verification_quorum.verify()?;
        decommission.verify()?;
        tombstone.verify()?;
        if final_assurance.policy_snapshot_sha256 != self.policy_snapshot_sha256
            || maintenance.policy_snapshot_sha256 != self.policy_snapshot_sha256
            || continuity.policy_snapshot_sha256 != self.policy_snapshot_sha256
            || sample_plan.policy_snapshot_sha256 != self.policy_snapshot_sha256
            || roadmap.final_assurance_certificate_sha256 != final_assurance.certificate_sha256
            || maintenance.baseline_final_assurance_sha256 != final_assurance.certificate_sha256
            || maintenance.baseline_roadmap_closure_sha256 != roadmap.closure_sha256
            || continuity.maintenance_release_certificate_sha256 != maintenance.certificate_sha256
            || verification_quorum.sample_plan_sha256 != sample_plan.plan_sha256
            || decommission.final_assurance_certificate_sha256 != final_assurance.certificate_sha256
            || decommission.roadmap_closure_sha256 != roadmap.closure_sha256
            || decommission.maintenance_release_certificate_sha256 != maintenance.certificate_sha256
            || decommission.continuity_certificate_sha256 != continuity.certificate_sha256
            || tombstone.decommission_plan_sha256 != decommission.plan_sha256
            || tombstone.continuity_certificate_sha256 != continuity.certificate_sha256
        {
            return Err(LifecycleError::InvalidClosure(
                "lifecycle certificate closure".into(),
            ));
        }
        let closed_milestones = (0_u32..=101).collect::<BTreeSet<_>>();
        let seed = hash_serializable(&(
            &self.authority_id,
            &self.policy_snapshot_sha256,
            &final_assurance.certificate_sha256,
            &roadmap.closure_sha256,
            &maintenance.certificate_sha256,
            &continuity.certificate_sha256,
            &verification_quorum.quorum_sha256,
            &tombstone.certificate_sha256,
        ))?;
        let certificate_id = format!("lifecycle-closure-{}", &seed[..24]);
        self.audit.append(LifecycleAuditEvent {
            action: "lifecycle_closure_certified".into(),
            subject_id: certificate_id.clone(),
            outcome: "certified".into(),
            metadata: BTreeMap::from([
                (
                    "verification_quorum_sha256".into(),
                    verification_quorum.quorum_sha256.clone(),
                ),
                (
                    "tombstone_certificate_sha256".into(),
                    tombstone.certificate_sha256.clone(),
                ),
            ]),
        })?;
        let authority_audit_tail_hash = self.audit.tail_hash().to_owned();
        let certificate_sha256 = hash_serializable(&(
            &certificate_id,
            &self.policy_snapshot_sha256,
            &final_assurance.certificate_sha256,
            &roadmap.closure_sha256,
            &maintenance.certificate_sha256,
            &continuity.certificate_sha256,
            &verification_quorum.quorum_sha256,
            &tombstone.certificate_sha256,
            &closed_milestones,
            &authority_audit_tail_hash,
        ))?;
        let certificate = LifecycleClosureCertificate {
            certificate_id,
            policy_snapshot_sha256: self.policy_snapshot_sha256.clone(),
            final_assurance_certificate_sha256: final_assurance.certificate_sha256.clone(),
            roadmap_closure_sha256: roadmap.closure_sha256.clone(),
            maintenance_release_certificate_sha256: maintenance.certificate_sha256.clone(),
            continuity_certificate_sha256: continuity.certificate_sha256.clone(),
            independent_verification_quorum_sha256: verification_quorum.quorum_sha256.clone(),
            tombstone_certificate_sha256: tombstone.certificate_sha256.clone(),
            closed_milestones,
            authority_audit_tail_hash,
            certificate_sha256,
        };
        certificate.verify()?;
        Ok(certificate)
    }

    pub fn audit(&self) -> &LifecycleAuditChain {
        &self.audit
    }
}
