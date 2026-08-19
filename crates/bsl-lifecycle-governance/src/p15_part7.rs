impl TombstoneAuthority {
    pub fn new(
        authority_id: impl Into<String>,
        audit_genesis: impl Into<String>,
    ) -> Result<Self, LifecycleError> {
        let authority_id = authority_id.into();
        validate_identifier(&authority_id, "tombstone authority")?;
        Ok(Self {
            authority_id,
            audit: LifecycleAuditChain::new(audit_genesis)?,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn certify(
        &mut self,
        plan: &DecommissionPlan,
        continuity: &ContinuityCertificate,
        step_receipts: BTreeMap<DecommissionStep, String>,
        live_grant_count: u64,
        live_secret_count: u64,
        live_session_count: u64,
        tombstone_root_sha256: impl Into<String>,
    ) -> Result<TombstoneCertificate, LifecycleError> {
        plan.verify()?;
        continuity.verify()?;
        let tombstone_root_sha256 = tombstone_root_sha256.into();
        validate_sha256(&tombstone_root_sha256, "tombstone root")?;
        let expected_steps = canonical_decommission_steps()
            .into_iter()
            .collect::<BTreeSet<_>>();
        let actual_steps = step_receipts.keys().copied().collect::<BTreeSet<_>>();
        if plan.continuity_certificate_sha256 != continuity.certificate_sha256
            || actual_steps != expected_steps
            || step_receipts
                .values()
                .any(|receipt| validate_sha256(receipt, "tombstone step receipt").is_err())
            || live_grant_count != 0
            || live_secret_count != 0
            || live_session_count != 0
        {
            return Err(LifecycleError::InvalidClosure(
                "tombstone certification closure".into(),
            ));
        }
        let seed = hash_serializable(&(
            &self.authority_id,
            &plan.plan_sha256,
            &continuity.certificate_sha256,
            &step_receipts,
            &tombstone_root_sha256,
        ))?;
        let certificate_id = format!("tombstone-{}", &seed[..24]);
        self.audit.append(LifecycleAuditEvent {
            action: "tombstone_certified".into(),
            subject_id: certificate_id.clone(),
            outcome: "certified".into(),
            metadata: BTreeMap::from([
                ("plan_sha256".into(), plan.plan_sha256.clone()),
                (
                    "tombstone_root_sha256".into(),
                    tombstone_root_sha256.clone(),
                ),
            ]),
        })?;
        let authority_audit_tail_hash = self.audit.tail_hash().to_owned();
        let certificate_sha256 = hash_serializable(&(
            &certificate_id,
            &plan.plan_sha256,
            &continuity.certificate_sha256,
            &step_receipts,
            live_grant_count,
            live_secret_count,
            live_session_count,
            &tombstone_root_sha256,
            &authority_audit_tail_hash,
        ))?;
        let certificate = TombstoneCertificate {
            certificate_id,
            decommission_plan_sha256: plan.plan_sha256.clone(),
            continuity_certificate_sha256: continuity.certificate_sha256.clone(),
            step_receipts,
            live_grant_count,
            live_secret_count,
            live_session_count,
            tombstone_root_sha256,
            authority_audit_tail_hash,
            certificate_sha256,
        };
        certificate.verify()?;
        Ok(certificate)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LifecycleClosureCertificate {
    pub certificate_id: String,
    pub policy_snapshot_sha256: String,
    pub final_assurance_certificate_sha256: String,
    pub roadmap_closure_sha256: String,
    pub maintenance_release_certificate_sha256: String,
    pub continuity_certificate_sha256: String,
    pub independent_verification_quorum_sha256: String,
    pub tombstone_certificate_sha256: String,
    pub closed_milestones: BTreeSet<u32>,
    pub authority_audit_tail_hash: String,
    pub certificate_sha256: String,
}
