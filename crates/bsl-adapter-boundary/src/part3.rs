#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FixtureObject {
    pub object_id: String,
    pub fixture_uri: String,
    pub kind: FixtureObjectKind,
    pub content_sha256: String,
    pub bytes: u64,
    pub metadata: BTreeMap<String, String>,
}

impl FixtureObject {
    pub fn new(
        object_id: impl Into<String>,
        fixture_uri: impl Into<String>,
        kind: FixtureObjectKind,
        content_sha256: impl Into<String>,
        bytes: u64,
        metadata: BTreeMap<String, String>,
    ) -> Result<Self, BoundaryError> {
        let object_id = object_id.into();
        let fixture_uri = fixture_uri.into();
        let content_sha256 = content_sha256.into();
        validate_identifier(&object_id, "fixture object")?;
        validate_sha256(&content_sha256, "fixture content")?;
        validate_fixture_uri(&fixture_uri)?;
        if bytes == 0
            || bytes > MAX_FIXTURE_OBJECT_BYTES
            || metadata.len() > 64
            || metadata.iter().any(|(key, value)| {
                key.is_empty()
                    || key.len() > 96
                    || value.len() > 512
                    || key.bytes().any(|byte| byte.is_ascii_control())
                    || value.bytes().any(|byte| byte == 0)
                    || reject_secret_like_text(value).is_err()
            })
        {
            return Err(BoundaryError::InvalidFixture(
                "fixture size or metadata".into(),
            ));
        }
        Ok(Self {
            object_id,
            fixture_uri,
            kind,
            content_sha256,
            bytes,
            metadata,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FixtureProfile {
    profile_id: String,
    policy_snapshot_sha256: String,
    objects: BTreeMap<String, FixtureObject>,
    maximum_observations: u64,
    profile_sha256: String,
}

impl FixtureProfile {
    pub fn new(
        profile_id: impl Into<String>,
        policy_snapshot_sha256: impl Into<String>,
        objects: Vec<FixtureObject>,
        maximum_observations: u64,
    ) -> Result<Self, BoundaryError> {
        let profile_id = profile_id.into();
        let policy_snapshot_sha256 = policy_snapshot_sha256.into();
        validate_identifier(&profile_id, "fixture profile")?;
        validate_sha256(&policy_snapshot_sha256, "fixture policy")?;
        if objects.is_empty()
            || objects.len() > MAX_FIXTURE_OBJECTS
            || maximum_observations == 0
            || maximum_observations > MAX_SESSION_MESSAGES
        {
            return Err(BoundaryError::InvalidFixture(
                "fixture object or observation bounds".into(),
            ));
        }
        let mut by_id = BTreeMap::new();
        let mut uris = BTreeSet::new();
        for object in objects {
            if by_id.contains_key(&object.object_id) || !uris.insert(object.fixture_uri.clone()) {
                return Err(BoundaryError::InvalidFixture(
                    "duplicate fixture object or URI".into(),
                ));
            }
            by_id.insert(object.object_id.clone(), object);
        }
        let profile_sha256 = hash_serializable(&(
            &profile_id,
            &policy_snapshot_sha256,
            &by_id,
            maximum_observations,
        ))?;
        Ok(Self {
            profile_id,
            policy_snapshot_sha256,
            objects: by_id,
            maximum_observations,
            profile_sha256,
        })
    }

    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    pub fn policy_snapshot_sha256(&self) -> &str {
        &self.policy_snapshot_sha256
    }

    pub fn objects(&self) -> &BTreeMap<String, FixtureObject> {
        &self.objects
    }

    pub fn maximum_observations(&self) -> u64 {
        self.maximum_observations
    }

    pub fn profile_sha256(&self) -> &str {
        &self.profile_sha256
    }
}

#[derive(Debug)]
pub struct FixtureRegistry {
    policy_snapshot_sha256: String,
    profiles: BTreeMap<String, FixtureProfile>,
    audit: AdapterAuditChain,
}

impl FixtureRegistry {
    pub fn new(
        policy_snapshot_sha256: impl Into<String>,
        audit_genesis: impl Into<String>,
    ) -> Result<Self, BoundaryError> {
        let policy_snapshot_sha256 = policy_snapshot_sha256.into();
        validate_sha256(&policy_snapshot_sha256, "registry policy")?;
        Ok(Self {
            policy_snapshot_sha256,
            profiles: BTreeMap::new(),
            audit: AdapterAuditChain::new(audit_genesis)?,
        })
    }

    pub fn register(
        &mut self,
        profile: FixtureProfile,
    ) -> Result<&FixtureProfile, BoundaryError> {
        if profile.policy_snapshot_sha256 != self.policy_snapshot_sha256
            || self.profiles.contains_key(&profile.profile_id)
        {
            return Err(BoundaryError::InvalidFixture(
                "registry policy mismatch or duplicate profile".into(),
            ));
        }
        let profile_id = profile.profile_id.clone();
        let profile_sha256 = profile.profile_sha256.clone();
        self.profiles.insert(profile_id.clone(), profile);
        self.audit.append(AdapterAuditEvent {
            action: "fixture_profile_registered".into(),
            subject_id: profile_id.clone(),
            outcome: "registered".into(),
            metadata: BTreeMap::from([("profile_sha256".into(), profile_sha256)]),
        })?;
        Ok(self
            .profiles
            .get(&profile_id)
            .expect("fixture profile inserted"))
    }

    pub fn get(&self, profile_id: &str) -> Option<&FixtureProfile> {
        self.profiles.get(profile_id)
    }

    pub fn contains_exact(&self, profile: &FixtureProfile) -> bool {
        self.profiles
            .get(profile.profile_id())
            .map(|stored| stored.profile_sha256() == profile.profile_sha256())
            .unwrap_or(false)
    }

    pub fn audit(&self) -> &AdapterAuditChain {
        &self.audit
    }
}

fn validate_fixture_uri(value: &str) -> Result<(), BoundaryError> {
    if !value.starts_with("fixture://")
        || value.len() > 512
        || value.contains('?')
        || value.contains('#')
        || value.contains('@')
        || value.contains("..")
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(BoundaryError::InvalidFixture(
            "fixture URI must be a bounded credential-free fixture:// identifier".into(),
        ));
    }
    let remainder = &value[10..];
    if remainder.is_empty()
        || remainder.contains("://")
        || !remainder.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/' | b':')
        })
    {
        return Err(BoundaryError::InvalidFixture(
            "fixture URI characters or nested scheme".into(),
        ));
    }
    Ok(())
}
