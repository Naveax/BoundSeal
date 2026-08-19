#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReplayInputRef {
    pub input_id: String,
    pub fixture_uri: String,
    pub content_sha256: String,
    pub bytes: u64,
}

impl ReplayInputRef {
    pub fn new(
        input_id: impl Into<String>,
        fixture_uri: impl Into<String>,
        content_sha256: impl Into<String>,
        bytes: u64,
    ) -> Result<Self, ReplayError> {
        let input_id = input_id.into();
        let fixture_uri = fixture_uri.into();
        let content_sha256 = content_sha256.into();
        validate_identifier(&input_id, "replay input")?;
        validate_sha256(&content_sha256, "replay input content")?;
        let remainder = fixture_uri.strip_prefix("fixture://");
        if fixture_uri.len() > 512
            || fixture_uri.contains('?')
            || fixture_uri.contains('#')
            || fixture_uri.contains('@')
            || fixture_uri.contains("..")
            || remainder.is_none_or(|value| {
                value.is_empty()
                    || value.contains("://")
                    || !value.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric()
                            || matches!(byte, b'-' | b'_' | b'.' | b'/' | b':')
                    })
            })
            || bytes == 0
            || bytes > MAX_REPLAY_INPUT_BYTES
        {
            return Err(ReplayError::InvalidBundle(
                "input must be a bounded single-scheme fixture:// reference".into(),
            ));
        }
        Ok(Self {
            input_id,
            fixture_uri,
            content_sha256,
            bytes,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReplayBundle {
    pub bundle_id: String,
    pub policy_snapshot_sha256: String,
    pub adapter_conformance_sha256: String,
    pub fixture_profile_sha256: String,
    pub inputs: Vec<ReplayInputRef>,
    pub expected_observation_sha256: BTreeSet<String>,
    pub seed_sha256: String,
    pub initial_tick: u64,
    pub bundle_sha256: String,
}

impl ReplayBundle {
    pub fn new(
        bundle_id: impl Into<String>,
        certificate: &AdapterConformanceCertificate,
        inputs: Vec<ReplayInputRef>,
        expected_observation_sha256: BTreeSet<String>,
        seed_sha256: impl Into<String>,
        initial_tick: u64,
    ) -> Result<Self, ReplayError> {
        certificate
            .verify()
            .map_err(|error| ReplayError::InvalidBundle(error.to_string()))?;
        let bundle_id = bundle_id.into();
        let seed_sha256 = seed_sha256.into();
        validate_identifier(&bundle_id, "replay bundle")?;
        validate_sha256(&seed_sha256, "replay seed")?;
        if inputs.is_empty()
            || inputs.len() > MAX_REPLAY_INPUTS
            || expected_observation_sha256.len() > MAX_REPLAY_INPUTS
            || initial_tick > MAX_VIRTUAL_TICK
            || expected_observation_sha256
                .iter()
                .any(|value| validate_sha256(value, "expected observation").is_err())
        {
            return Err(ReplayError::InvalidBundle(
                "input, observation or virtual-time bounds".into(),
            ));
        }
        let total_bytes = inputs
            .iter()
            .try_fold(0_u64, |total, input| total.checked_add(input.bytes))
            .ok_or_else(|| ReplayError::InvalidBundle("input byte overflow".into()))?;
        if total_bytes > MAX_REPLAY_TOTAL_BYTES {
            return Err(ReplayError::InvalidBundle(
                "replay input byte budget".into(),
            ));
        }
        let unique_ids = inputs
            .iter()
            .map(|input| input.input_id.as_str())
            .collect::<BTreeSet<_>>();
        let unique_uris = inputs
            .iter()
            .map(|input| input.fixture_uri.as_str())
            .collect::<BTreeSet<_>>();
        if unique_ids.len() != inputs.len() || unique_uris.len() != inputs.len() {
            return Err(ReplayError::InvalidBundle(
                "duplicate input identifier or fixture URI".into(),
            ));
        }
        let adapter_conformance_sha256 = certificate.certificate_sha256.clone();
        let fixture_profile_sha256 = certificate.fixture_profile_sha256.clone();
        let policy_snapshot_sha256 = certificate.policy_snapshot_sha256.clone();
        let bundle_sha256 = hash_serializable(&(
            &bundle_id,
            &policy_snapshot_sha256,
            &adapter_conformance_sha256,
            &fixture_profile_sha256,
            &inputs,
            &expected_observation_sha256,
            &seed_sha256,
            initial_tick,
        ))?;
        Ok(Self {
            bundle_id,
            policy_snapshot_sha256,
            adapter_conformance_sha256,
            fixture_profile_sha256,
            inputs,
            expected_observation_sha256,
            seed_sha256,
            initial_tick,
            bundle_sha256,
        })
    }

    pub fn verify(&self) -> Result<(), ReplayError> {
        let expected = hash_serializable(&(
            &self.bundle_id,
            &self.policy_snapshot_sha256,
            &self.adapter_conformance_sha256,
            &self.fixture_profile_sha256,
            &self.inputs,
            &self.expected_observation_sha256,
            &self.seed_sha256,
            self.initial_tick,
        ))?;
        if expected != self.bundle_sha256 {
            return Err(ReplayError::InvalidBundle(
                "bundle digest mismatch".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VirtualClock {
    initial_tick: u64,
    current_tick: u64,
    maximum_tick: u64,
}

impl VirtualClock {
    pub fn new(initial_tick: u64, maximum_tick: u64) -> Result<Self, ReplayError> {
        if initial_tick > maximum_tick || maximum_tick > MAX_VIRTUAL_TICK {
            return Err(ReplayError::InvalidClock);
        }
        Ok(Self {
            initial_tick,
            current_tick: initial_tick,
            maximum_tick,
        })
    }

    pub fn advance(&mut self, delta: u64) -> Result<u64, ReplayError> {
        let next = self
            .current_tick
            .checked_add(delta)
            .ok_or(ReplayError::InvalidClock)?;
        if next > self.maximum_tick {
            return Err(ReplayError::InvalidClock);
        }
        self.current_tick = next;
        Ok(self.current_tick)
    }

    pub fn current_tick(&self) -> u64 {
        self.current_tick
    }

    pub fn reset(&mut self) {
        self.current_tick = self.initial_tick;
    }
}

#[derive(Debug, Clone)]
pub struct DeterministicSeed {
    seed_sha256: String,
    counter: u64,
}

impl DeterministicSeed {
    pub fn new(seed_sha256: impl Into<String>) -> Result<Self, ReplayError> {
        let seed_sha256 = seed_sha256.into();
        validate_sha256(&seed_sha256, "deterministic seed")?;
        Ok(Self {
            seed_sha256,
            counter: 0,
        })
    }

    pub fn next_u64(&mut self) -> u64 {
        let digest = Sha256::digest(format!("{}:{}", self.seed_sha256, self.counter).as_bytes());
        self.counter = self.counter.saturating_add(1);
        u64::from_be_bytes([
            digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6],
            digest[7],
        ])
    }

    pub fn counter(&self) -> u64 {
        self.counter
    }
}
