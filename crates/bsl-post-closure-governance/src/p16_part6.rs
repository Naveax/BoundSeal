#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SuccessionCertificate {
    pub certificate_id: String,
    pub policy_snapshot_sha256: String,
    pub baseline_lifecycle_closure_sha256: String,
    pub successor_identity_sha256: String,
    pub compatibility_envelope_sha256: String,
    pub transfer_manifest_sha256: String,
    pub cutover_plan_sha256: String,
    pub cutover_receipt_sha256: String,
    pub authority_audit_tail_hash: String,
    pub certificate_sha256: String,
}

impl SuccessionCertificate {
    pub fn verify(&self) -> Result<(), PostClosureError> {
        validate_identifier(&self.certificate_id, "succession certificate")?;
        for (name, value) in [
            ("succession policy", self.policy_snapshot_sha256.as_str()),
            (
                "succession lifecycle closure",
                self.baseline_lifecycle_closure_sha256.as_str(),
            ),
            (
                "succession identity",
                self.successor_identity_sha256.as_str(),
            ),
            (
                "succession compatibility",
                self.compatibility_envelope_sha256.as_str(),
            ),
            ("succession transfer", self.transfer_manifest_sha256.as_str()),
            ("succession cutover plan", self.cutover_plan_sha256.as_str()),
            (
                "succession cutover receipt",
                self.cutover_receipt_sha256.as_str(),
            ),
            (
                "succession authority audit",
                self.authority_audit_tail_hash.as_str(),
            ),
        ] {
            validate_sha256(value, name)?;
        }
        let expected = hash_serializable(&(
            &self.certificate_id,
            &self.policy_snapshot_sha256,
            &self.baseline_lifecycle_closure_sha256,
            &self.successor_identity_sha256,
            &self.compatibility_envelope_sha256,
            &self.transfer_manifest_sha256,
            &self.cutover_plan_sha256,
            &self.cutover_receipt_sha256,
            &self.authority_audit_tail_hash,
        ))?;
        if expected != self.certificate_sha256 {
            return Err(PostClosureError::InvalidSuccession(
                "succession certificate digest".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct SuccessionAuthority {
    authority_id: String,
    policy_snapshot_sha256: String,
    audit: PostClosureAuditChain,
}

impl SuccessionAuthority {
    pub fn new(
        authority_id: impl Into<String>,
        policy_snapshot_sha256: impl Into<String>,
        audit_genesis: impl Into<String>,
    ) -> Result<Self, PostClosureError> {
        let authority_id = authority_id.into();
        let policy_snapshot_sha256 = policy_snapshot_sha256.into();
        validate_identifier(&authority_id, "succession authority")?;
        validate_sha256(&policy_snapshot_sha256, "succession authority policy")?;
        Ok(Self {
            authority_id,
            policy_snapshot_sha256,
            audit: PostClosureAuditChain::new(audit_genesis)?,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn certify(
        &mut self,
        lifecycle: &LifecycleClosureCertificate,
        identity: &SuccessorIdentity,
        envelope: &CompatibilityEnvelope,
        transfer: &StateTransferManifest,
        plan: &CutoverPlan,
        receipt: &CutoverReceipt,
    ) -> Result<SuccessionCertificate, PostClosureError> {
        lifecycle
            .verify()
            .map_err(|error| PostClosureError::InvalidSuccession(error.to_string()))?;
        identity.verify()?;
        envelope.verify()?;
        transfer.verify()?;
        plan.verify()?;
        receipt.verify()?;
        if lifecycle.policy_snapshot_sha256 != self.policy_snapshot_sha256
            || identity.policy_snapshot_sha256 != self.policy_snapshot_sha256
            || identity.baseline_lifecycle_closure_sha256 != lifecycle.certificate_sha256
            || envelope.successor_identity_sha256 != identity.identity_sha256
            || transfer.compatibility_envelope_sha256 != envelope.envelope_sha256
            || plan.successor_identity_sha256 != identity.identity_sha256
            || plan.compatibility_envelope_sha256 != envelope.envelope_sha256
            || plan.transfer_manifest_sha256 != transfer.manifest_sha256
            || receipt.plan_sha256 != plan.plan_sha256
            || receipt.completed_tick < plan.start_tick
            || receipt.completed_tick > plan.end_tick
        {
            return Err(PostClosureError::InvalidSuccession(
                "succession certificate closure".into(),
            ));
        }
        let seed = hash_serializable(&(
            &self.authority_id,
            &self.policy_snapshot_sha256,
            &lifecycle.certificate_sha256,
            &identity.identity_sha256,
            &receipt.receipt_sha256,
        ))?;
        let certificate_id = format!("succession-{}", &seed[..24]);
        self.audit.append(PostClosureAuditEvent {
            action: "succession_certified".into(),
            subject_id: certificate_id.clone(),
            outcome: "certified".into(),
            metadata: BTreeMap::from([
                ("identity_sha256".into(), identity.identity_sha256.clone()),
                ("cutover_receipt_sha256".into(), receipt.receipt_sha256.clone()),
            ]),
        })?;
        let authority_audit_tail_hash = self.audit.tail_hash().to_owned();
        let certificate_sha256 = hash_serializable(&(
            &certificate_id,
            &self.policy_snapshot_sha256,
            &lifecycle.certificate_sha256,
            &identity.identity_sha256,
            &envelope.envelope_sha256,
            &transfer.manifest_sha256,
            &plan.plan_sha256,
            &receipt.receipt_sha256,
            &authority_audit_tail_hash,
        ))?;
        let certificate = SuccessionCertificate {
            certificate_id,
            policy_snapshot_sha256: self.policy_snapshot_sha256.clone(),
            baseline_lifecycle_closure_sha256: lifecycle.certificate_sha256.clone(),
            successor_identity_sha256: identity.identity_sha256.clone(),
            compatibility_envelope_sha256: envelope.envelope_sha256.clone(),
            transfer_manifest_sha256: transfer.manifest_sha256.clone(),
            cutover_plan_sha256: plan.plan_sha256.clone(),
            cutover_receipt_sha256: receipt.receipt_sha256.clone(),
            authority_audit_tail_hash,
            certificate_sha256,
        };
        certificate.verify()?;
        Ok(certificate)
    }

    pub fn audit(&self) -> &PostClosureAuditChain {
        &self.audit
    }
}
