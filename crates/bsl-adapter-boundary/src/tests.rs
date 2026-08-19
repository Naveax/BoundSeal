fn hex(character: char) -> String {
    std::iter::repeat_n(character, 64).collect()
}

fn limits() -> AdapterResourceLimits {
    AdapterResourceLimits::new(16, 4096, 65_536, 10_000, 64 * 1024 * 1024).unwrap()
}

fn manifest() -> AdapterManifest {
    AdapterManifest::new(
        "manifest-1",
        "fixture-parser",
        "1.0.0",
        hex('a'),
        1,
        BTreeSet::from([
            AdapterCapability::FixtureRead,
            AdapterCapability::DeterministicTransform,
            AdapterCapability::ObservationEmit,
            AdapterCapability::Finalization,
        ]),
        BTreeSet::from([
            AdapterAction::LoadFixture,
            AdapterAction::ExecuteReadOnly,
            AdapterAction::EmitObservation,
            AdapterAction::Finalize,
        ]),
        limits(),
        false,
    )
    .unwrap()
}

fn profile() -> FixtureProfile {
    FixtureProfile::new(
        "fixture-profile-1",
        hex('b'),
        vec![
            FixtureObject::new(
                "request-metadata-1",
                "fixture://profile-1/request-metadata-1",
                FixtureObjectKind::RequestMetadata,
                hex('c'),
                512,
                BTreeMap::from([("method".into(), "GET".into())]),
            )
            .unwrap(),
            FixtureObject::new(
                "response-metadata-1",
                "fixture://profile-1/response-metadata-1",
                FixtureObjectKind::ResponseMetadata,
                hex('d'),
                1024,
                BTreeMap::from([("status".into(), "200".into())]),
            )
            .unwrap(),
        ],
        8,
    )
    .unwrap()
}

fn grant(manifest: &AdapterManifest, profile: &FixtureProfile) -> AdapterGrant {
    let mut authority =
        AdapterAdmissionAuthority::new("admission-1", hex('b'), hex('0')).unwrap();
    authority
        .admit(
            manifest,
            profile,
            AdapterAdmissionRequest {
                request_id: "request-1".into(),
                run_id: "run-1".into(),
                worker_id: "worker-1".into(),
                policy_snapshot_sha256: hex('b'),
                manifest_sha256: manifest.manifest_sha256().into(),
                fixture_profile_sha256: profile.profile_sha256().into(),
                requested_actions: manifest.allowed_actions().clone(),
                issued_at_milliseconds: 100,
                expires_at_milliseconds: 10_000,
            },
        )
        .unwrap()
}

fn execute_step(
    session: &mut AdapterSession,
    sequence: u64,
    action: AdapterAction,
    outcome: AdapterOutcome,
) -> AdapterReceipt {
    let envelope = AdapterEnvelope::new(
        session.snapshot().session_id.clone(),
        sequence,
        action,
        session.snapshot().fixture_profile_sha256.clone(),
        hex(char::from_digit((sequence % 10) as u32, 10).unwrap_or('1')),
        128,
        BTreeMap::new(),
    )
    .unwrap();
    session
        .execute(
            envelope,
            AdapterResourceUsage {
                cpu_milliseconds: 10,
                peak_memory_bytes: 1024,
                output_bytes: 64,
            },
            hex('e'),
            outcome,
            200 + sequence,
        )
        .unwrap()
}

#[test]
fn external_io_manifest_is_rejected() {
    assert!(matches!(
        AdapterManifest::new(
            "manifest-1",
            "unsafe-adapter",
            "1.0.0",
            hex('a'),
            1,
            BTreeSet::from([AdapterCapability::FixtureRead]),
            BTreeSet::from([AdapterAction::LoadFixture]),
            limits(),
            true,
        ),
        Err(BoundaryError::InvalidManifest(_))
    ));
}

#[test]
fn fixtures_are_synthetic_and_secret_free() {
    assert!(matches!(
        FixtureObject::new(
            "object-1",
            "https://example.com/data",
            FixtureObjectKind::StructuredDocument,
            hex('a'),
            10,
            BTreeMap::new(),
        ),
        Err(BoundaryError::InvalidFixture(_))
    ));
    assert!(matches!(
        FixtureObject::new(
            "object-1",
            "fixture://profile/object",
            FixtureObjectKind::StructuredDocument,
            hex('a'),
            10,
            BTreeMap::from([("note".into(), "Authorization: Bearer secret".into())]),
        ),
        Err(BoundaryError::InvalidFixture(_))
    ));
}

#[test]
fn grant_is_exact_and_single_use() {
    let manifest = manifest();
    let profile = profile();
    let mut grant = grant(&manifest, &profile);
    let session = AdapterSession::open(&manifest, &mut grant, &profile, 150).unwrap();
    assert_eq!(session.snapshot().run_id, "run-1");
    assert!(grant.is_consumed());
    assert!(matches!(
        AdapterSession::open(&manifest, &mut grant, &profile, 151),
        Err(BoundaryError::GrantInactive)
    ));
}

#[test]
fn session_enforces_sequence_actions_and_resources() {
    let manifest = manifest();
    let profile = profile();
    let mut grant = grant(&manifest, &profile);
    let mut session = AdapterSession::open(&manifest, &mut grant, &profile, 150).unwrap();
    let wrong = AdapterEnvelope::new(
        session.snapshot().session_id.clone(),
        2,
        AdapterAction::LoadFixture,
        profile.profile_sha256(),
        hex('1'),
        1,
        BTreeMap::new(),
    )
    .unwrap();
    assert!(matches!(
        session.execute(
            wrong,
            AdapterResourceUsage {
                cpu_milliseconds: 1,
                peak_memory_bytes: 1,
                output_bytes: 1,
            },
            hex('2'),
            AdapterOutcome::Accepted,
            151,
        ),
        Err(BoundaryError::InvalidEnvelope(_))
    ));
    let oversized = AdapterEnvelope::new(
        session.snapshot().session_id.clone(),
        1,
        AdapterAction::LoadFixture,
        profile.profile_sha256(),
        hex('1'),
        4096,
        BTreeMap::new(),
    )
    .unwrap();
    assert!(matches!(
        session.execute(
            oversized,
            AdapterResourceUsage {
                cpu_milliseconds: 1,
                peak_memory_bytes: 1,
                output_bytes: 4097,
            },
            hex('2'),
            AdapterOutcome::Accepted,
            151,
        ),
        Err(BoundaryError::QuotaExceeded(_))
    ));
    assert_eq!(session.snapshot().state, SessionState::Failed);
}

#[test]
fn completed_session_receives_conformance_certificate() {
    let manifest = manifest();
    let profile = profile();
    let mut registry = FixtureRegistry::new(hex('b'), hex('0')).unwrap();
    registry.register(profile.clone()).unwrap();
    let mut grant = grant(&manifest, &profile);
    let mut session = AdapterSession::open(&manifest, &mut grant, &profile, 150).unwrap();
    execute_step(
        &mut session,
        1,
        AdapterAction::LoadFixture,
        AdapterOutcome::Accepted,
    );
    execute_step(
        &mut session,
        2,
        AdapterAction::ExecuteReadOnly,
        AdapterOutcome::Accepted,
    );
    execute_step(
        &mut session,
        3,
        AdapterAction::EmitObservation,
        AdapterOutcome::ProducedObservation,
    );
    let receipt = execute_step(
        &mut session,
        4,
        AdapterAction::Finalize,
        AdapterOutcome::Finalized,
    );
    assert_eq!(receipt.state, SessionState::Completed);
    let mut authority =
        AdapterConformanceAuthority::new("conformance-1", hex('b'), hex('0')).unwrap();
    let certificate = authority.certify(&session, &registry, &profile).unwrap();
    certificate.verify().unwrap();
    authority.audit().verify().unwrap();
}

#[test]
fn audit_tampering_blocks_conformance() {
    let manifest = manifest();
    let profile = profile();
    let mut grant = grant(&manifest, &profile);
    let mut session = AdapterSession::open(&manifest, &mut grant, &profile, 150).unwrap();
    execute_step(
        &mut session,
        1,
        AdapterAction::Finalize,
        AdapterOutcome::Finalized,
    );
    session.audit_mut().records_mut()[0].event.outcome = "modified".into();
    assert!(matches!(
        session.audit().verify(),
        Err(BoundaryError::AuditRecordHashMismatch { record_index: 0 })
    ));
}
