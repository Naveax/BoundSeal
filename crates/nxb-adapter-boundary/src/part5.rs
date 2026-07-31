#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdapterConformanceCertificate {
    pub certificate_id: String,
    pub authority_id: String,
    pub session_id: String,
    pub run_id: String,
    pub worker_id: String,
    pub policy_snapshot_sha256: String,
    pub manifest_sha256: String,
    pub grant_sha256: String,
    pub fixture_profile_sha256: String,
    pub limits_sha256: String,
    pub session_audit_tail_hash: String,
    pub fixture_registry_audit_tail_hash: String,
    pub message_count: u64,
    pub observation_count: u64,
    pub external_io_observed: bool,
    pub boundary_violations: u64,
    pub certificate_sha256: String,
}

impl AdapterConformanceCertificate {
    pub fn verify(&self) -> Result<(), BoundaryError> {
        for (name, value) in [
            ("policy", self.policy_snapshot_sha256.as_str()),
            ("manifest", self.manifest_sha256.as_str()),
            ("grant", self.grant_sha256.as_str()),
            ("fixture profile", self.fixture_profile_sha256.as_str()),
            ("limits", self.limits_sha256.as_str()),
            ("session audit", self.session_audit_tail_hash.as_str()),
            (
                "fixture registry audit",
                self.fixture_registry_audit_tail_hash.as_str(),
            ),
            ("certificate", self.certificate_sha256.as_str()),
        ] {
            validate_sha256(value, name)?;
        }
        let expected = hash_serializable(&(
            &self.certificate_id,
            &self.authority_id,
            &self.session_id,
            &self.run_id,
            &self.worker_id,
            &self.policy_snapshot_sha256,
            &self.manifest_sha256,
            &self.grant_sha256,
            &self.fixture_profile_sha256,
            &self.limits_sha256,
            &self.session_audit_tail_hash,
            &self.fixture_registry_audit_tail_hash,
            self.message_count,
            self.observation_count,
            self.external_io_observed,
            self.boundary_violations,
        ))?;
        if expected != self.certificate_sha256
            || self.message_count == 0
            || self.external_io_observed
            || self.boundary_violations != 0
        {
            return Err(BoundaryError::CertificationDenied(
                "certificate digest or safety closure".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct AdapterConformanceAuthority {
    authority_id: String,
    policy_snapshot_sha256: String,
    audit: AdapterAuditChain,
}

impl AdapterConformanceAuthority {
    pub fn new(
        authority_id: impl Into<String>,
        policy_snapshot_sha256: impl Into<String>,
        audit_genesis: impl Into<String>,
    ) -> Result<Self, BoundaryError> {
        let authority_id = authority_id.into();
        let policy_snapshot_sha256 = policy_snapshot_sha256.into();
        validate_identifier(&authority_id, "conformance authority")?;
        validate_sha256(&policy_snapshot_sha256, "conformance policy")?;
        Ok(Self {
            authority_id,
            policy_snapshot_sha256,
            audit: AdapterAuditChain::new(audit_genesis)?,
        })
    }

    pub fn certify(
        &mut self,
        session: &AdapterSession,
        registry: &FixtureRegistry,
        profile: &FixtureProfile,
    ) -> Result<AdapterConformanceCertificate, BoundaryError> {
        session.audit().verify()?;
        registry.audit().verify()?;
        let snapshot = session.snapshot();
        if snapshot.state != SessionState::Completed
            || snapshot.policy_snapshot_sha256 != self.policy_snapshot_sha256
            || snapshot.policy_snapshot_sha256 != profile.policy_snapshot_sha256()
            || snapshot.fixture_profile_sha256 != profile.profile_sha256()
            || !registry.contains_exact(profile)
            || snapshot.message_count == 0
            || snapshot.external_io_observed
            || snapshot.boundary_violations != 0
            || snapshot.limits_sha256 != session.limits().digest()?
        {
            return Err(BoundaryError::CertificationDenied(
                "session, policy, fixture, quota or audit closure".into(),
            ));
        }
        let certificate_id_seed = hash_serializable(&(
            &self.authority_id,
            &snapshot.session_id,
            &snapshot.audit_tail_hash,
            registry.audit().tail_hash(),
        ))?;
        let certificate_id = format!("adapter-conformance-{}", &certificate_id_seed[..24]);
        let certificate_sha256 = hash_serializable(&(
            &certificate_id,
            &self.authority_id,
            &snapshot.session_id,
            &snapshot.run_id,
            &snapshot.worker_id,
            &snapshot.policy_snapshot_sha256,
            &snapshot.manifest_sha256,
            &snapshot.grant_sha256,
            &snapshot.fixture_profile_sha256,
            &snapshot.limits_sha256,
            &snapshot.audit_tail_hash,
            registry.audit().tail_hash(),
            snapshot.message_count,
            snapshot.observation_count,
            snapshot.external_io_observed,
            snapshot.boundary_violations,
        ))?;
        let certificate = AdapterConformanceCertificate {
            certificate_id: certificate_id.clone(),
            authority_id: self.authority_id.clone(),
            session_id: snapshot.session_id.clone(),
            run_id: snapshot.run_id.clone(),
            worker_id: snapshot.worker_id.clone(),
            policy_snapshot_sha256: snapshot.policy_snapshot_sha256.clone(),
            manifest_sha256: snapshot.manifest_sha256.clone(),
            grant_sha256: snapshot.grant_sha256.clone(),
            fixture_profile_sha256: snapshot.fixture_profile_sha256.clone(),
            limits_sha256: snapshot.limits_sha256.clone(),
            session_audit_tail_hash: snapshot.audit_tail_hash.clone(),
            fixture_registry_audit_tail_hash: registry.audit().tail_hash().into(),
            message_count: snapshot.message_count,
            observation_count: snapshot.observation_count,
            external_io_observed: snapshot.external_io_observed,
            boundary_violations: snapshot.boundary_violations,
            certificate_sha256: certificate_sha256.clone(),
        };
        certificate.verify()?;
        self.audit.append(AdapterAuditEvent {
            action: "adapter_conformance_certified".into(),
            subject_id: certificate_id,
            outcome: "certified".into(),
            metadata: BTreeMap::from([
                ("session_id".into(), snapshot.session_id.clone()),
                ("certificate_sha256".into(), certificate_sha256),
            ]),
        })?;
        Ok(certificate)
    }

    pub fn audit(&self) -> &AdapterAuditChain {
        &self.audit
    }
}
