#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdapterResourceLimits {
    pub maximum_messages: u64,
    pub maximum_message_bytes: u64,
    pub maximum_session_bytes: u64,
    pub maximum_cpu_milliseconds: u64,
    pub maximum_memory_bytes: u64,
}

impl AdapterResourceLimits {
    pub fn new(
        maximum_messages: u64,
        maximum_message_bytes: u64,
        maximum_session_bytes: u64,
        maximum_cpu_milliseconds: u64,
        maximum_memory_bytes: u64,
    ) -> Result<Self, BoundaryError> {
        if maximum_messages == 0
            || maximum_messages > MAX_SESSION_MESSAGES
            || maximum_message_bytes == 0
            || maximum_message_bytes > MAX_MESSAGE_BYTES
            || maximum_session_bytes < maximum_message_bytes
            || maximum_session_bytes > MAX_SESSION_BYTES
            || maximum_cpu_milliseconds == 0
            || maximum_cpu_milliseconds > MAX_CPU_MILLISECONDS
            || maximum_memory_bytes == 0
            || maximum_memory_bytes > MAX_MEMORY_BYTES
        {
            return Err(BoundaryError::InvalidManifest(
                "resource limits are zero, inconsistent or above hard ceilings".into(),
            ));
        }
        Ok(Self {
            maximum_messages,
            maximum_message_bytes,
            maximum_session_bytes,
            maximum_cpu_milliseconds,
            maximum_memory_bytes,
        })
    }

    pub fn digest(&self) -> Result<String, BoundaryError> {
        hash_serializable(self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdapterManifest {
    manifest_id: String,
    adapter_name: String,
    adapter_version: String,
    binary_sha256: String,
    schema_version: u32,
    capabilities: BTreeSet<AdapterCapability>,
    allowed_actions: BTreeSet<AdapterAction>,
    limits: AdapterResourceLimits,
    manifest_sha256: String,
}

impl AdapterManifest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        manifest_id: impl Into<String>,
        adapter_name: impl Into<String>,
        adapter_version: impl Into<String>,
        binary_sha256: impl Into<String>,
        schema_version: u32,
        capabilities: BTreeSet<AdapterCapability>,
        allowed_actions: BTreeSet<AdapterAction>,
        limits: AdapterResourceLimits,
        external_io_requested: bool,
    ) -> Result<Self, BoundaryError> {
        let manifest_id = manifest_id.into();
        let adapter_name = adapter_name.into();
        let adapter_version = adapter_version.into();
        let binary_sha256 = binary_sha256.into();
        validate_identifier(&manifest_id, "manifest_id")?;
        validate_identifier(&adapter_name, "adapter_name")?;
        validate_identifier(&adapter_version, "adapter_version")?;
        validate_sha256(&binary_sha256, "adapter binary")?;
        if schema_version == 0
            || capabilities.is_empty()
            || allowed_actions.is_empty()
            || allowed_actions.len() > MAX_ADAPTER_ACTIONS
            || external_io_requested
            || allowed_actions
                .iter()
                .any(|action| !capabilities.contains(&action.required_capability()))
        {
            return Err(BoundaryError::InvalidManifest(
                "schema, action, capability or external-I/O declaration".into(),
            ));
        }
        let manifest_sha256 = hash_serializable(&(
            &manifest_id,
            &adapter_name,
            &adapter_version,
            &binary_sha256,
            schema_version,
            &capabilities,
            &allowed_actions,
            &limits,
            false,
        ))?;
        Ok(Self {
            manifest_id,
            adapter_name,
            adapter_version,
            binary_sha256,
            schema_version,
            capabilities,
            allowed_actions,
            limits,
            manifest_sha256,
        })
    }

    pub fn manifest_id(&self) -> &str {
        &self.manifest_id
    }

    pub fn manifest_sha256(&self) -> &str {
        &self.manifest_sha256
    }

    pub fn binary_sha256(&self) -> &str {
        &self.binary_sha256
    }

    pub fn schema_version(&self) -> u32 {
        self.schema_version
    }

    pub fn capabilities(&self) -> &BTreeSet<AdapterCapability> {
        &self.capabilities
    }

    pub fn allowed_actions(&self) -> &BTreeSet<AdapterAction> {
        &self.allowed_actions
    }

    pub fn limits(&self) -> &AdapterResourceLimits {
        &self.limits
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdapterAdmissionRequest {
    pub request_id: String,
    pub run_id: String,
    pub worker_id: String,
    pub policy_snapshot_sha256: String,
    pub manifest_sha256: String,
    pub fixture_profile_sha256: String,
    pub requested_actions: BTreeSet<AdapterAction>,
    pub issued_at_milliseconds: u64,
    pub expires_at_milliseconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdapterGrant {
    grant_id: String,
    run_id: String,
    worker_id: String,
    policy_snapshot_sha256: String,
    manifest_sha256: String,
    fixture_profile_sha256: String,
    allowed_actions: BTreeSet<AdapterAction>,
    issued_at_milliseconds: u64,
    expires_at_milliseconds: u64,
    grant_sha256: String,
    consumed: bool,
}

impl AdapterGrant {
    pub fn grant_id(&self) -> &str {
        &self.grant_id
    }

    pub fn grant_sha256(&self) -> &str {
        &self.grant_sha256
    }

    pub fn is_consumed(&self) -> bool {
        self.consumed
    }
}

#[derive(Debug)]
pub struct AdapterAdmissionAuthority {
    authority_id: String,
    policy_snapshot_sha256: String,
    next_grant_sequence: u64,
    audit: AdapterAuditChain,
}

impl AdapterAdmissionAuthority {
    pub fn new(
        authority_id: impl Into<String>,
        policy_snapshot_sha256: impl Into<String>,
        audit_genesis: impl Into<String>,
    ) -> Result<Self, BoundaryError> {
        let authority_id = authority_id.into();
        let policy_snapshot_sha256 = policy_snapshot_sha256.into();
        validate_identifier(&authority_id, "adapter admission authority")?;
        validate_sha256(&policy_snapshot_sha256, "policy snapshot")?;
        Ok(Self {
            authority_id,
            policy_snapshot_sha256,
            next_grant_sequence: 1,
            audit: AdapterAuditChain::new(audit_genesis)?,
        })
    }

    pub fn admit(
        &mut self,
        manifest: &AdapterManifest,
        profile: &FixtureProfile,
        request: AdapterAdmissionRequest,
    ) -> Result<AdapterGrant, BoundaryError> {
        for (name, value) in [
            ("request_id", request.request_id.as_str()),
            ("run_id", request.run_id.as_str()),
            ("worker_id", request.worker_id.as_str()),
        ] {
            validate_identifier(value, name)?;
        }
        validate_sha256(&request.policy_snapshot_sha256, "request policy")?;
        validate_sha256(&request.manifest_sha256, "request manifest")?;
        validate_sha256(&request.fixture_profile_sha256, "request fixture profile")?;
        if request.policy_snapshot_sha256 != self.policy_snapshot_sha256
            || request.policy_snapshot_sha256 != profile.policy_snapshot_sha256()
            || request.manifest_sha256 != manifest.manifest_sha256()
            || request.fixture_profile_sha256 != profile.profile_sha256()
            || request.requested_actions.is_empty()
            || !request
                .requested_actions
                .is_subset(manifest.allowed_actions())
            || request.issued_at_milliseconds == 0
            || request.expires_at_milliseconds <= request.issued_at_milliseconds
            || request
                .expires_at_milliseconds
                .saturating_sub(request.issued_at_milliseconds)
                > 3_600_000
        {
            return Err(BoundaryError::AdmissionDenied(
                "policy, manifest, fixture, action or lifetime binding".into(),
            ));
        }
        let grant_id = format!(
            "adapter-grant-{}-{:020}",
            self.authority_id, self.next_grant_sequence
        );
        self.next_grant_sequence = self.next_grant_sequence.saturating_add(1);
        let grant_sha256 = hash_serializable(&(
            &grant_id,
            &request.run_id,
            &request.worker_id,
            &request.policy_snapshot_sha256,
            &request.manifest_sha256,
            &request.fixture_profile_sha256,
            &request.requested_actions,
            request.issued_at_milliseconds,
            request.expires_at_milliseconds,
        ))?;
        let grant = AdapterGrant {
            grant_id: grant_id.clone(),
            run_id: request.run_id,
            worker_id: request.worker_id,
            policy_snapshot_sha256: request.policy_snapshot_sha256,
            manifest_sha256: request.manifest_sha256,
            fixture_profile_sha256: request.fixture_profile_sha256,
            allowed_actions: request.requested_actions,
            issued_at_milliseconds: request.issued_at_milliseconds,
            expires_at_milliseconds: request.expires_at_milliseconds,
            grant_sha256: grant_sha256.clone(),
            consumed: false,
        };
        self.audit.append(AdapterAuditEvent {
            action: "adapter_grant_issued".into(),
            subject_id: grant_id,
            outcome: "issued".into(),
            metadata: BTreeMap::from([
                ("manifest_sha256".into(), manifest.manifest_sha256().into()),
                ("fixture_profile_sha256".into(), profile.profile_sha256().into()),
                ("grant_sha256".into(), grant_sha256),
            ]),
        })?;
        Ok(grant)
    }

    pub fn audit(&self) -> &AdapterAuditChain {
        &self.audit
    }
}
