#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProgramClosureCertificate {
    pub certificate_id: String,
    pub policy_snapshot_sha256: String,
    pub lifecycle_closure_sha256: String,
    pub succession_certificate_sha256: String,
    pub renewal_certificate_sha256: String,
    pub public_bundle_sha256: String,
    pub public_quorum_sha256: String,
    pub sunset_certificate_sha256: String,
    pub closed_milestones: BTreeSet<u32>,
    pub authority_audit_tail_hash: String,
    pub certificate_sha256: String,
}

impl ProgramClosureCertificate {
    pub fn verify(&self) -> Result<(), PostClosureError> {
        validate_identifier(&self.certificate_id, "program closure certificate")?;
        for (name, value) in [
            ("program policy", self.policy_snapshot_sha256.as_str()),
            (
                "program lifecycle closure",
                self.lifecycle_closure_sha256.as_str(),
            ),
            (
                "program succession certificate",
                self.succession_certificate_sha256.as_str(),
            ),
            (
                "program renewal certificate",
                self.renewal_certificate_sha256.as_str(),
            ),
            ("program public bundle", self.public_bundle_sha256.as_str()),
            ("program public quorum", self.public_quorum_sha256.as_str()),
            (
                "program sunset certificate",
                self.sunset_certificate_sha256.as_str(),
            ),
            (
                "program authority audit",
                self.authority_audit_tail_hash.as_str(),
            ),
        ] {
            validate_sha256(value, name)?;
        }
        let expected_milestones = (0_u32..=119).collect::<BTreeSet<_>>();
        let expected = hash_serializable(&(
            &self.certificate_id,
            &self.policy_snapshot_sha256,
            &self.lifecycle_closure_sha256,
            &self.succession_certificate_sha256,
            &self.renewal_certificate_sha256,
            &self.public_bundle_sha256,
            &self.public_quorum_sha256,
            &self.sunset_certificate_sha256,
            &self.closed_milestones,
            &self.authority_audit_tail_hash,
        ))?;
        if self.closed_milestones != expected_milestones || expected != self.certificate_sha256 {
            return Err(PostClosureError::InvalidProgramClosure(
                "program closure milestone or digest".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct ProgramClosureAuthority {
    authority_id: String,
    policy_snapshot_sha256: String,
    audit: PostClosureAuditChain,
}

impl ProgramClosureAuthority {
    pub fn new(
        authority_id: impl Into<String>,
        policy_snapshot_sha256: impl Into<String>,
        audit_genesis: impl Into<String>,
    ) -> Result<Self, PostClosureError> {
        let authority_id = authority_id.into();
        let policy_snapshot_sha256 = policy_snapshot_sha256.into();
        validate_identifier(&authority_id, "program closure authority")?;
        validate_sha256(&policy_snapshot_sha256, "program closure policy")?;
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
        succession: &SuccessionCertificate,
        renewal: &RenewalCertificate,
        bundle: &PublicVerificationBundle,
        quorum: &PublicVerificationQuorum,
        sunset_plan: &SunsetPlan,
        sunset: &SunsetCertificate,
    ) -> Result<ProgramClosureCertificate, PostClosureError> {
        lifecycle
            .verify()
            .map_err(|error| PostClosureError::InvalidProgramClosure(error.to_string()))?;
        succession.verify()?;
        renewal.verify()?;
        bundle.verify()?;
        quorum.verify()?;
        sunset_plan.verify()?;
        sunset.verify()?;
        if lifecycle.policy_snapshot_sha256 != self.policy_snapshot_sha256
            || succession.policy_snapshot_sha256 != self.policy_snapshot_sha256
            || renewal.policy_snapshot_sha256 != self.policy_snapshot_sha256
            || bundle.policy_snapshot_sha256 != self.policy_snapshot_sha256
            || succession.baseline_lifecycle_closure_sha256 != lifecycle.certificate_sha256
            || renewal.succession_certificate_sha256 != succession.certificate_sha256
            || bundle.lifecycle_closure_sha256 != lifecycle.certificate_sha256
            || bundle.succession_certificate_sha256 != succession.certificate_sha256
            || bundle.renewal_certificate_sha256 != renewal.certificate_sha256
            || quorum.bundle_sha256 != bundle.bundle_sha256
            || sunset_plan.succession_certificate_sha256 != succession.certificate_sha256
            || sunset_plan.renewal_certificate_sha256 != renewal.certificate_sha256
            || sunset_plan.public_bundle_sha256 != bundle.bundle_sha256
            || sunset_plan.public_quorum_sha256 != quorum.quorum_sha256
            || sunset.sunset_plan_sha256 != sunset_plan.plan_sha256
        {
            return Err(PostClosureError::InvalidProgramClosure(
                "program closure certificate chain".into(),
            ));
        }
        let closed_milestones = (0_u32..=119).collect::<BTreeSet<_>>();
        let seed = hash_serializable(&(
            &self.authority_id,
            &self.policy_snapshot_sha256,
            &lifecycle.certificate_sha256,
            &succession.certificate_sha256,
            &renewal.certificate_sha256,
            &sunset.certificate_sha256,
        ))?;
        let certificate_id = format!("program-closure-{}", &seed[..24]);
        self.audit.append(PostClosureAuditEvent {
            action: "program_closure_certified".into(),
            subject_id: certificate_id.clone(),
            outcome: "certified".into(),
            metadata: BTreeMap::from([
                (
                    "public_verification_quorum_sha256".into(),
                    quorum.quorum_sha256.clone(),
                ),
                (
                    "sunset_certificate_sha256".into(),
                    sunset.certificate_sha256.clone(),
                ),
            ]),
        })?;
        let authority_audit_tail_hash = self.audit.tail_hash().to_owned();
        let certificate_sha256 = hash_serializable(&(
            &certificate_id,
            &self.policy_snapshot_sha256,
            &lifecycle.certificate_sha256,
            &succession.certificate_sha256,
            &renewal.certificate_sha256,
            &bundle.bundle_sha256,
            &quorum.quorum_sha256,
            &sunset.certificate_sha256,
            &closed_milestones,
            &authority_audit_tail_hash,
        ))?;
        let certificate = ProgramClosureCertificate {
            certificate_id,
            policy_snapshot_sha256: self.policy_snapshot_sha256.clone(),
            lifecycle_closure_sha256: lifecycle.certificate_sha256.clone(),
            succession_certificate_sha256: succession.certificate_sha256.clone(),
            renewal_certificate_sha256: renewal.certificate_sha256.clone(),
            public_bundle_sha256: bundle.bundle_sha256.clone(),
            public_quorum_sha256: quorum.quorum_sha256.clone(),
            sunset_certificate_sha256: sunset.certificate_sha256.clone(),
            closed_milestones,
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
