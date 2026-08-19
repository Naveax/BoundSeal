impl ProbeCapability {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        capability_id: impl Into<String>,
        module_id: impl Into<String>,
        run_id: impl Into<String>,
        worker_id: impl Into<String>,
        allowed_methods: BTreeSet<String>,
        allowed_endpoint_hashes: BTreeSet<String>,
        maximum_requests: u64,
        maximum_mutations: u64,
        secret_access: SecretAccessLevel,
        body_replay_allowed: bool,
        redirect_allowed: bool,
        expires_at_milliseconds: u64,
    ) -> Result<Self, PlannerError> {
        let capability_id = capability_id.into();
        let module_id = module_id.into();
        let run_id = run_id.into();
        let worker_id = worker_id.into();
        for (name, value) in [
            ("capability_id", &capability_id),
            ("module_id", &module_id),
            ("run_id", &run_id),
            ("worker_id", &worker_id),
        ] {
            validate_identifier(value, name)?;
        }
        if allowed_methods.is_empty()
            || allowed_methods.iter().any(|method| validate_method(method).is_err())
            || allowed_endpoint_hashes.is_empty()
            || allowed_endpoint_hashes
                .iter()
                .any(|value| validate_sha256(value, "endpoint").is_err())
            || maximum_requests == 0
            || maximum_requests > MAX_CAPABILITY_REQUESTS
            || maximum_mutations > MAX_CAPABILITY_MUTATIONS
            || expires_at_milliseconds == 0
        {
            return Err(PlannerError::InvalidCapability(
                "capability bounds or allowlists are invalid".into(),
            ));
        }
        Ok(Self {
            capability_id,
            module_id,
            run_id,
            worker_id,
            allowed_methods,
            allowed_endpoint_hashes,
            maximum_requests,
            maximum_mutations,
            secret_access,
            body_replay_allowed,
            redirect_allowed,
            expires_at_milliseconds,
            revoked: false,
            requests_used: 0,
            mutations_used: 0,
        })
    }

    pub fn authorize(
        &mut self,
        request: CapabilityUseRequest,
    ) -> Result<CapabilityUseReceipt, PlannerError> {
        if self.revoked || request.now_milliseconds >= self.expires_at_milliseconds {
            return Err(PlannerError::CapabilityInactive);
        }
        if request.run_id != self.run_id || request.worker_id != self.worker_id {
            return Err(PlannerError::CapabilityDenied(
                "run or worker binding".into(),
            ));
        }
        if !self.allowed_methods.contains(&request.method)
            || !self
                .allowed_endpoint_hashes
                .contains(&request.endpoint_sha256)
        {
            return Err(PlannerError::CapabilityDenied(
                "method or endpoint allowlist".into(),
            ));
        }
        if request.requires_secret_access > self.secret_access {
            return Err(PlannerError::CapabilityDenied("secret access".into()));
        }
        if request.replays_body && !self.body_replay_allowed {
            return Err(PlannerError::CapabilityDenied("body replay".into()));
        }
        if request.follows_redirect && !self.redirect_allowed {
            return Err(PlannerError::CapabilityDenied("redirect".into()));
        }
        if self.requests_used >= self.maximum_requests
            || self
                .mutations_used
                .saturating_add(request.mutations)
                > self.maximum_mutations
        {
            return Err(PlannerError::CapabilityDenied("budget".into()));
        }
        self.requests_used = self.requests_used.saturating_add(1);
        self.mutations_used = self.mutations_used.saturating_add(request.mutations);
        Ok(CapabilityUseReceipt {
            capability_id: self.capability_id.clone(),
            request_number: self.requests_used,
            mutations_used: request.mutations,
            remaining_requests: self.maximum_requests.saturating_sub(self.requests_used),
            remaining_mutations: self.maximum_mutations.saturating_sub(self.mutations_used),
            endpoint_sha256: request.endpoint_sha256,
        })
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlannerAuditEvent {
    pub action: String,
    pub subject_id: String,
    pub outcome: String,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlannerAuditRecord {
    pub sequence: u64,
    pub previous_hash: String,
    pub event: PlannerAuditEvent,
    pub record_hash: String,
}

#[derive(Debug)]
pub struct PlannerAuditChain {
    records: Vec<PlannerAuditRecord>,
    tail_hash: String,
}

impl PlannerAuditChain {
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
            tail_hash: "0".repeat(64),
        }
    }

    pub fn append(&mut self, event: PlannerAuditEvent) -> Result<&PlannerAuditRecord, PlannerError> {
        let sequence = self.records.len() as u64 + 1;
        let previous_hash = self.tail_hash.clone();
        let record_hash = hash_serializable(&(sequence, &previous_hash, &event));
        self.records.push(PlannerAuditRecord {
            sequence,
            previous_hash,
            event,
            record_hash: record_hash.clone(),
        });
        self.tail_hash = record_hash;
        Ok(self.records.last().expect("planner audit append"))
    }

    pub fn records(&self) -> &[PlannerAuditRecord] {
        &self.records
    }

    pub fn tail_hash(&self) -> &str {
        &self.tail_hash
    }

    pub fn verify(&self) -> Result<(), PlannerError> {
        let mut previous = "0".repeat(64);
        for (index, record) in self.records.iter().enumerate() {
            if record.sequence != index as u64 + 1 {
                return Err(PlannerError::AuditSequenceMismatch {
                    record_index: index,
                });
            }
            if record.previous_hash != previous {
                return Err(PlannerError::AuditPreviousHashMismatch {
                    record_index: index,
                });
            }
            let expected = hash_serializable(&(record.sequence, &record.previous_hash, &record.event));
            if record.record_hash != expected {
                return Err(PlannerError::AuditRecordHashMismatch {
                    record_index: index,
                });
            }
            previous = expected;
        }
        if self.tail_hash != previous {
            return Err(PlannerError::AuditTailMismatch);
        }
        Ok(())
    }
}

impl Default for PlannerAuditChain {
    fn default() -> Self {
        Self::new()
    }
}

fn normalized_origin(url: &Url) -> Result<String, PlannerError> {
    let host = url
        .host_str()
        .ok_or_else(|| PlannerError::InvalidPlan("URL host".into()))?
        .to_ascii_lowercase();
    let port = url
        .port_or_known_default()
        .ok_or_else(|| PlannerError::InvalidPlan("URL port".into()))?;
    Ok(format!("{}://{}:{}", url.scheme(), host, port))
}

fn validate_identifier(value: &str, name: &str) -> Result<(), PlannerError> {
    if value.is_empty()
        || value.len() > 160
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(PlannerError::InvalidIdentifier(name.into()));
    }
    Ok(())
}

fn validate_method(value: &str) -> Result<(), PlannerError> {
    if !matches!(
        value,
        "GET" | "HEAD" | "OPTIONS" | "POST" | "PUT" | "PATCH" | "DELETE"
    ) {
        return Err(PlannerError::InvalidPlan("HTTP method".into()));
    }
    Ok(())
}

