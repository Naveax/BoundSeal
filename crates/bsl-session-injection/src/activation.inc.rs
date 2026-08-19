#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SessionInjectionActivationPayload {
    pub version: u32,
    pub activation_id: String,
    pub manifest_sha256: String,
    pub discovery_plan_sha256: String,
    pub target_origin_sha256: String,
    pub session_id_sha256: String,
    pub not_before_epoch_seconds: i64,
    pub expires_at_epoch_seconds: i64,
    pub signer_key_id_sha256: String,
}

impl SessionInjectionActivationPayload {
    pub fn template(
        activation_id: impl Into<String>,
        manifest: &SessionInjectionManifest,
        not_before_epoch_seconds: i64,
        expires_at_epoch_seconds: i64,
    ) -> Result<Self, SessionInjectionError> {
        manifest.validate()?;
        let payload = Self {
            version: SESSION_INJECTION_ACTIVATION_VERSION,
            activation_id: activation_id.into(),
            manifest_sha256: manifest.manifest_sha256.clone(),
            discovery_plan_sha256: manifest.discovery_plan_sha256.clone(),
            target_origin_sha256: manifest.target_origin_sha256.clone(),
            session_id_sha256: hash_bytes(manifest.session_id.as_bytes()),
            not_before_epoch_seconds,
            expires_at_epoch_seconds,
            signer_key_id_sha256: manifest.activation_key_id_sha256.clone(),
        };
        payload.validate()?;
        Ok(payload)
    }

    pub fn validate(&self) -> Result<(), SessionInjectionError> {
        if self.version != SESSION_INJECTION_ACTIVATION_VERSION {
            return Err(SessionInjectionError::UnsupportedActivationVersion);
        }
        validate_identifier(&self.activation_id, "activation_id")?;
        for (value, field) in [
            (&self.manifest_sha256, "manifest_sha256"),
            (&self.discovery_plan_sha256, "discovery_plan_sha256"),
            (&self.target_origin_sha256, "target_origin_sha256"),
            (&self.session_id_sha256, "session_id_sha256"),
            (&self.signer_key_id_sha256, "signer_key_id_sha256"),
        ] {
            validate_sha256(value, field)?;
        }
        if self.not_before_epoch_seconds <= 0
            || self.expires_at_epoch_seconds <= self.not_before_epoch_seconds
            || self
                .expires_at_epoch_seconds
                .saturating_sub(self.not_before_epoch_seconds)
                > MAX_SESSION_INJECTION_ACTIVATION_SECONDS
        {
            return Err(SessionInjectionError::InvalidActivationWindow);
        }
        Ok(())
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, SessionInjectionError> {
        self.validate()?;
        serde_json::to_vec(self)
            .map_err(|error| SessionInjectionError::Serialization(error.to_string()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SessionInjectionActivationCertificate {
    pub payload: SessionInjectionActivationPayload,
    pub signature_hex: String,
}

impl SessionInjectionActivationCertificate {
    pub fn verify(
        &self,
        manifest: &SessionInjectionManifest,
        public_key: &[u8],
        now_epoch_seconds: i64,
    ) -> Result<(), SessionInjectionError> {
        manifest.verify(now_epoch_seconds)?;
        self.payload.validate()?;
        if public_key.len() != 32
            || hash_bytes(public_key) != self.payload.signer_key_id_sha256
            || self.payload.signer_key_id_sha256 != manifest.activation_key_id_sha256
        {
            return Err(SessionInjectionError::ActivationKeyMismatch);
        }
        if self.payload.manifest_sha256 != manifest.manifest_sha256
            || self.payload.discovery_plan_sha256 != manifest.discovery_plan_sha256
            || self.payload.target_origin_sha256 != manifest.target_origin_sha256
            || self.payload.session_id_sha256 != hash_bytes(manifest.session_id.as_bytes())
        {
            return Err(SessionInjectionError::ActivationBindingMismatch);
        }
        if now_epoch_seconds < self.payload.not_before_epoch_seconds
            || now_epoch_seconds > self.payload.expires_at_epoch_seconds
            || self.payload.expires_at_epoch_seconds > manifest.expires_at_epoch_seconds
        {
            return Err(SessionInjectionError::ActivationExpired);
        }
        let signature = decode_lower_hex(&self.signature_hex)?;
        if signature.len() != 64 {
            return Err(SessionInjectionError::InvalidSignature);
        }
        UnparsedPublicKey::new(&ED25519, public_key)
            .verify(&self.payload.signing_bytes()?, &signature)
            .map_err(|_| SessionInjectionError::InvalidSignature)
    }

    pub fn certificate_sha256(&self) -> Result<String, SessionInjectionError> {
        hash_serializable(self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SessionInjectionUseMarker {
    version: u32,
    injection_id_sha256: String,
    activation_id_sha256: String,
    activation_certificate_sha256: String,
    manifest_sha256: String,
    discovery_plan_sha256: String,
    consumed_at_epoch_seconds: i64,
    state: String,
}

#[derive(Debug)]
pub struct ConsumedSessionInjectionActivation {
    manifest_sha256: String,
    discovery_plan_sha256: String,
    target_origin_sha256: String,
    session_id_sha256: String,
    certificate_sha256: String,
    not_before_epoch_seconds: i64,
    expires_at_epoch_seconds: i64,
}

impl ConsumedSessionInjectionActivation {
    pub fn certificate_sha256(&self) -> &str {
        &self.certificate_sha256
    }
}

pub fn consume_activation_once(
    state_directory: &Path,
    manifest: &SessionInjectionManifest,
    certificate: &SessionInjectionActivationCertificate,
    public_key: &[u8],
    now_epoch_seconds: i64,
) -> Result<ConsumedSessionInjectionActivation, SessionInjectionError> {
    certificate.verify(manifest, public_key, now_epoch_seconds)?;
    fs::create_dir_all(state_directory).map_err(|error| {
        SessionInjectionError::StateIo(format!(
            "could not create session-injection state directory {}: {error}",
            state_directory.display()
        ))
    })?;
    let certificate_sha256 = certificate.certificate_sha256()?;
    let injection_id_sha256 = hash_bytes(manifest.injection_id.as_bytes());
    let activation_id_sha256 = hash_bytes(certificate.payload.activation_id.as_bytes());
    let marker_path = state_directory.join(format!(
        "session-injection-{injection_id_sha256}-{activation_id_sha256}.used.json"
    ));
    let marker = SessionInjectionUseMarker {
        version: 1,
        injection_id_sha256,
        activation_id_sha256,
        activation_certificate_sha256: certificate_sha256.clone(),
        manifest_sha256: manifest.manifest_sha256.clone(),
        discovery_plan_sha256: manifest.discovery_plan_sha256.clone(),
        consumed_at_epoch_seconds: now_epoch_seconds,
        state: "consumed_fail_closed_no_replay".into(),
    };
    let bytes = serde_json::to_vec_pretty(&marker)
        .map_err(|error| SessionInjectionError::Serialization(error.to_string()))?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&marker_path)
        .map_err(|error| {
            SessionInjectionError::StateIo(format!(
                "session-injection activation was already used or marker creation failed {}: {error}",
                marker_path.display()
            ))
        })?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|error| SessionInjectionError::StateIo(error.to_string()))?;
    Ok(ConsumedSessionInjectionActivation {
        manifest_sha256: manifest.manifest_sha256.clone(),
        discovery_plan_sha256: manifest.discovery_plan_sha256.clone(),
        target_origin_sha256: manifest.target_origin_sha256.clone(),
        session_id_sha256: hash_bytes(manifest.session_id.as_bytes()),
        certificate_sha256,
        not_before_epoch_seconds: certificate.payload.not_before_epoch_seconds,
        expires_at_epoch_seconds: certificate.payload.expires_at_epoch_seconds,
    })
}
