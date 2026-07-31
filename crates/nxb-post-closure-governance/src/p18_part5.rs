#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SunsetCertificate {
    pub certificate_id: String,
    pub sunset_plan_sha256: String,
    pub step_receipts: BTreeMap<SunsetStep, String>,
    pub live_capability_count: u64,
    pub live_secret_count: u64,
    pub live_session_count: u64,
    pub live_process_count: u64,
    pub live_socket_count: u64,
    pub authority_audit_tail_hash: String,
    pub certificate_sha256: String,
}

impl SunsetCertificate {
    pub fn verify(&self) -> Result<(), PostClosureError> {
        validate_identifier(&self.certificate_id, "sunset certificate")?;
        validate_sha256(&self.sunset_plan_sha256, "sunset certificate plan")?;
        validate_sha256(&self.authority_audit_tail_hash, "sunset certificate audit")?;
        let expected_steps = canonical_sunset_steps()
            .into_iter()
            .collect::<BTreeSet<_>>();
        if self.step_receipts.keys().copied().collect::<BTreeSet<_>>() != expected_steps
            || self
                .step_receipts
                .values()
                .any(|receipt| validate_sha256(receipt, "sunset step receipt").is_err())
            || self.live_capability_count != 0
            || self.live_secret_count != 0
            || self.live_session_count != 0
            || self.live_process_count != 0
            || self.live_socket_count != 0
        {
            return Err(PostClosureError::InvalidProgramClosure(
                "sunset certificate live-resource or step closure".into(),
            ));
        }
        let expected = hash_serializable(&(
            &self.certificate_id,
            &self.sunset_plan_sha256,
            &self.step_receipts,
            self.live_capability_count,
            self.live_secret_count,
            self.live_session_count,
            self.live_process_count,
            self.live_socket_count,
            &self.authority_audit_tail_hash,
        ))?;
        if expected != self.certificate_sha256 {
            return Err(PostClosureError::InvalidProgramClosure(
                "sunset certificate digest".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct SunsetAuthority {
    authority_id: String,
    audit: PostClosureAuditChain,
}

impl SunsetAuthority {
    pub fn new(
        authority_id: impl Into<String>,
        audit_genesis: impl Into<String>,
    ) -> Result<Self, PostClosureError> {
        let authority_id = authority_id.into();
        validate_identifier(&authority_id, "sunset authority")?;
        Ok(Self {
            authority_id,
            audit: PostClosureAuditChain::new(audit_genesis)?,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn certify(
        &mut self,
        plan: &SunsetPlan,
        step_receipts: BTreeMap<SunsetStep, String>,
        live_capability_count: u64,
        live_secret_count: u64,
        live_session_count: u64,
        live_process_count: u64,
        live_socket_count: u64,
    ) -> Result<SunsetCertificate, PostClosureError> {
        plan.verify()?;
        let expected_steps = canonical_sunset_steps()
            .into_iter()
            .collect::<BTreeSet<_>>();
        if step_receipts.keys().copied().collect::<BTreeSet<_>>() != expected_steps
            || step_receipts
                .values()
                .any(|receipt| validate_sha256(receipt, "sunset step receipt").is_err())
            || live_capability_count != 0
            || live_secret_count != 0
            || live_session_count != 0
            || live_process_count != 0
            || live_socket_count != 0
        {
            return Err(PostClosureError::InvalidProgramClosure(
                "sunset certification live-resource or step closure".into(),
            ));
        }
        let seed = hash_serializable(&(&self.authority_id, &plan.plan_sha256, &step_receipts))?;
        let certificate_id = format!("sunset-{}", &seed[..24]);
        self.audit.append(PostClosureAuditEvent {
            action: "sunset_certified".into(),
            subject_id: certificate_id.clone(),
            outcome: "certified".into(),
            metadata: BTreeMap::from([
                ("sunset_plan_sha256".into(), plan.plan_sha256.clone()),
                (
                    "archive_root_sha256".into(),
                    plan.archive_root_sha256.clone(),
                ),
            ]),
        })?;
        let authority_audit_tail_hash = self.audit.tail_hash().to_owned();
        let certificate_sha256 = hash_serializable(&(
            &certificate_id,
            &plan.plan_sha256,
            &step_receipts,
            live_capability_count,
            live_secret_count,
            live_session_count,
            live_process_count,
            live_socket_count,
            &authority_audit_tail_hash,
        ))?;
        let certificate = SunsetCertificate {
            certificate_id,
            sunset_plan_sha256: plan.plan_sha256.clone(),
            step_receipts,
            live_capability_count,
            live_secret_count,
            live_session_count,
            live_process_count,
            live_socket_count,
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
