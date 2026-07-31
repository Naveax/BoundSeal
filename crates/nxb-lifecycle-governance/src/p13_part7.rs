impl MaintenanceReleaseAuthority {
    pub fn new(
        authority_id: impl Into<String>,
        policy_snapshot_sha256: impl Into<String>,
        audit_genesis: impl Into<String>,
    ) -> Result<Self, LifecycleError> {
        let authority_id = authority_id.into();
        let policy_snapshot_sha256 = policy_snapshot_sha256.into();
        validate_identifier(&authority_id, "maintenance authority")?;
        validate_sha256(&policy_snapshot_sha256, "maintenance authority policy")?;
        Ok(Self {
            authority_id,
            policy_snapshot_sha256,
            audit: LifecycleAuditChain::new(audit_genesis)?,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn certify(
        &mut self,
        identity: &MaintenanceIdentity,
        proposal: &ChangeProposal,
        assessment: &ImpactAssessment,
        window: &MaintenanceWindow,
        plan: &PatchAdmissionPlan,
        regression_root_sha256: impl Into<String>,
        rollback_rehearsal_root_sha256: impl Into<String>,
        result_root_sha256: impl Into<String>,
        open_incident_count: u64,
    ) -> Result<MaintenanceReleaseCertificate, LifecycleError> {
        identity.verify()?;
        proposal.verify()?;
        assessment.verify()?;
        window.verify()?;
        plan.verify()?;
        let regression_root_sha256 = regression_root_sha256.into();
        let rollback_rehearsal_root_sha256 = rollback_rehearsal_root_sha256.into();
        let result_root_sha256 = result_root_sha256.into();
        for (name, value) in [
            ("regression root", regression_root_sha256.as_str()),
            (
                "rollback rehearsal root",
                rollback_rehearsal_root_sha256.as_str(),
            ),
            ("maintenance result", result_root_sha256.as_str()),
        ] {
            validate_sha256(value, name)?;
        }
        if identity.policy_snapshot_sha256 != self.policy_snapshot_sha256
            || proposal.maintenance_identity_sha256 != identity.identity_sha256
            || assessment.proposal_sha256 != proposal.proposal_sha256
            || window.proposal_sha256 != proposal.proposal_sha256
            || plan.maintenance_identity_sha256 != identity.identity_sha256
            || plan.proposal_sha256 != proposal.proposal_sha256
            || plan.assessment_sha256 != assessment.assessment_sha256
            || plan.window_sha256 != window.window_sha256
            || open_incident_count != 0
        {
            return Err(LifecycleError::InvalidMaintenance(
                "maintenance release closure".into(),
            ));
        }
        let seed = hash_serializable(&(
            &self.authority_id,
            &self.policy_snapshot_sha256,
            &identity.baseline_final_assurance_sha256,
            &identity.baseline_roadmap_closure_sha256,
            &proposal.proposal_sha256,
            &plan.plan_sha256,
            &result_root_sha256,
        ))?;
        let certificate_id = format!("maintenance-release-{}", &seed[..24]);
        self.audit.append(LifecycleAuditEvent {
            action: "maintenance_release_certified".into(),
            subject_id: certificate_id.clone(),
            outcome: "certified".into(),
            metadata: BTreeMap::from([
                ("proposal_sha256".into(), proposal.proposal_sha256.clone()),
                ("result_root_sha256".into(), result_root_sha256.clone()),
            ]),
        })?;
        let authority_audit_tail_hash = self.audit.tail_hash().to_owned();
        let certificate_sha256 = hash_serializable(&(
            &certificate_id,
            &self.policy_snapshot_sha256,
            &identity.baseline_final_assurance_sha256,
            &identity.baseline_roadmap_closure_sha256,
            &proposal.proposal_sha256,
            &assessment.assessment_sha256,
            &window.window_sha256,
            &plan.plan_sha256,
            &regression_root_sha256,
            &rollback_rehearsal_root_sha256,
            &result_root_sha256,
            &authority_audit_tail_hash,
        ))?;
        let certificate = MaintenanceReleaseCertificate {
            certificate_id,
            policy_snapshot_sha256: self.policy_snapshot_sha256.clone(),
            baseline_final_assurance_sha256: identity.baseline_final_assurance_sha256.clone(),
            baseline_roadmap_closure_sha256: identity.baseline_roadmap_closure_sha256.clone(),
            proposal_sha256: proposal.proposal_sha256.clone(),
            assessment_sha256: assessment.assessment_sha256.clone(),
            window_sha256: window.window_sha256.clone(),
            admission_plan_sha256: plan.plan_sha256.clone(),
            regression_root_sha256,
            rollback_rehearsal_root_sha256,
            result_root_sha256,
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
