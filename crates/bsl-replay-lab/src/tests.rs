use bsl_adapter_boundary::{
    AdapterAction, AdapterAdmissionAuthority, AdapterAdmissionRequest, AdapterCapability,
    AdapterConformanceAuthority, AdapterEnvelope, AdapterGrant, AdapterManifest, AdapterOutcome,
    AdapterResourceLimits, AdapterResourceUsage, AdapterSession, FixtureObject, FixtureObjectKind,
    FixtureProfile, FixtureRegistry,
};

fn hex(character: char) -> String {
    std::iter::repeat_n(character, 64).collect()
}

fn adapter_certificate() -> AdapterConformanceCertificate {
    let limits = AdapterResourceLimits::new(16, 4096, 65_536, 10_000, 1024 * 1024).unwrap();
    let manifest = AdapterManifest::new(
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
        limits,
        false,
    )
    .unwrap();
    let profile = FixtureProfile::new(
        "profile-1",
        hex('b'),
        vec![
            FixtureObject::new(
                "input-1",
                "fixture://profile-1/input-1",
                FixtureObjectKind::StructuredDocument,
                hex('c'),
                100,
                BTreeMap::new(),
            )
            .unwrap(),
            FixtureObject::new(
                "input-2",
                "fixture://profile-1/input-2",
                FixtureObjectKind::StructuredDocument,
                hex('d'),
                100,
                BTreeMap::new(),
            )
            .unwrap(),
        ],
        8,
    )
    .unwrap();
    let mut registry = FixtureRegistry::new(hex('b'), hex('0')).unwrap();
    registry.register(profile.clone()).unwrap();
    let mut admission =
        AdapterAdmissionAuthority::new("admission-1", hex('b'), hex('0')).unwrap();
    let mut grant: AdapterGrant = admission
        .admit(
            &manifest,
            &profile,
            AdapterAdmissionRequest {
                request_id: "request-1".into(),
                run_id: "run-1".into(),
                worker_id: "worker-1".into(),
                policy_snapshot_sha256: hex('b'),
                manifest_sha256: manifest.manifest_sha256().into(),
                fixture_profile_sha256: profile.profile_sha256().into(),
                requested_actions: manifest.allowed_actions().clone(),
                issued_at_milliseconds: 1,
                expires_at_milliseconds: 10_000,
            },
        )
        .unwrap();
    let mut session = AdapterSession::open(&manifest, &mut grant, &profile, 2).unwrap();
    let envelope = AdapterEnvelope::new(
        session.snapshot().session_id.clone(),
        1,
        AdapterAction::Finalize,
        profile.profile_sha256(),
        hex('e'),
        1,
        BTreeMap::new(),
    )
    .unwrap();
    session
        .execute(
            envelope,
            AdapterResourceUsage {
                cpu_milliseconds: 1,
                peak_memory_bytes: 1,
                output_bytes: 1,
            },
            hex('f'),
            AdapterOutcome::Finalized,
            3,
        )
        .unwrap();
    let mut authority =
        AdapterConformanceAuthority::new("conformance-1", hex('b'), hex('0')).unwrap();
    authority.certify(&session, &registry, &profile).unwrap()
}

fn bundle() -> ReplayBundle {
    ReplayBundle::new(
        "bundle-1",
        &adapter_certificate(),
        vec![
            ReplayInputRef::new(
                "input-1",
                "fixture://profile-1/input-1",
                hex('c'),
                100,
            )
            .unwrap(),
            ReplayInputRef::new(
                "input-2",
                "fixture://profile-1/input-2",
                hex('d'),
                100,
            )
            .unwrap(),
        ],
        BTreeSet::from([hex('9')]),
        hex('1'),
        100,
    )
    .unwrap()
}

fn plan(bundle: &ReplayBundle) -> FaultPlan {
    FaultPlan::new(
        "fault-plan-1",
        bundle.bundle_sha256.clone(),
        vec![
            FaultRule::new("delay-1", 1, FaultKind::Delay, 5).unwrap(),
            FaultRule::new("backpressure-2", 2, FaultKind::Backpressure, 3).unwrap(),
        ],
    )
    .unwrap()
}

fn run(engine_id: &str, bundle: ReplayBundle, plan: FaultPlan) -> (ReplayTrace, ReplayReceipt) {
    let mut engine = ReplayEngine::new(engine_id, bundle, plan, hex('0')).unwrap();
    engine.start().unwrap();
    engine.step(1, hex('2'), hex('3'), 10).unwrap();
    engine.step(2, hex('4'), hex('5'), 10).unwrap();
    engine.finish().unwrap()
}

#[test]
fn replay_bundle_requires_valid_adapter_conformance() {
    let mut certificate = adapter_certificate();
    certificate.certificate_sha256 = hex('0');
    assert!(matches!(
        ReplayBundle::new(
            "bundle-1",
            &certificate,
            vec![ReplayInputRef::new(
                "input-1",
                "fixture://profile/input",
                hex('1'),
                1,
            )
            .unwrap()],
            BTreeSet::new(),
            hex('2'),
            0,
        ),
        Err(ReplayError::InvalidBundle(_))
    ));
}

#[test]
fn virtual_clock_and_seed_are_deterministic() {
    let mut left = DeterministicSeed::new(hex('1')).unwrap();
    let mut right = DeterministicSeed::new(hex('1')).unwrap();
    assert_eq!(left.next_u64(), right.next_u64());
    assert_eq!(left.next_u64(), right.next_u64());
    let mut clock = VirtualClock::new(10, 20).unwrap();
    assert_eq!(clock.advance(5).unwrap(), 15);
    assert_eq!(clock.advance(6), Err(ReplayError::InvalidClock));
}

#[test]
fn replay_applies_only_declared_bounded_faults() {
    let bundle = bundle();
    let plan = plan(&bundle);
    let mut engine = ReplayEngine::new("engine-1", bundle, plan, hex('0')).unwrap();
    engine.start().unwrap();
    let first = engine.step(1, hex('2'), hex('3'), 10).unwrap();
    assert_eq!(first.outcome, ReplayStepOutcome::Observed);
    assert!(first.applied_fault_ids.contains("delay-1"));
    let second = engine.step(2, hex('4'), hex('5'), 10).unwrap();
    assert_eq!(second.outcome, ReplayStepOutcome::Backpressured);
    let (trace, receipt) = engine.finish().unwrap();
    trace.verify().unwrap();
    receipt.verify().unwrap();
}

#[test]
fn checkpoint_resume_preserves_deterministic_trace() {
    let bundle = bundle();
    let plan = plan(&bundle);
    let (baseline_trace, _) = run("engine-baseline", bundle.clone(), plan.clone());

    let mut engine =
        ReplayEngine::new("engine-resume", bundle.clone(), plan.clone(), hex('0')).unwrap();
    engine.start().unwrap();
    engine.step(1, hex('2'), hex('3'), 10).unwrap();
    let prefix = engine.observations().to_vec();
    let checkpoint = engine.checkpoint().unwrap();
    checkpoint.verify().unwrap();
    let mut resumed =
        ReplayEngine::resume("engine-resume", bundle, plan, &checkpoint, prefix).unwrap();
    resumed.step(2, hex('4'), hex('5'), 10).unwrap();
    let (resumed_trace, _) = resumed.finish().unwrap();
    assert_eq!(baseline_trace.trace_sha256, resumed_trace.trace_sha256);
}

#[test]
fn drift_comparator_distinguishes_timing_and_semantic_changes() {
    let bundle = bundle();
    let plan = plan(&bundle);
    let (baseline, _) = run("engine-1", bundle, plan);
    let comparator = ReplayDriftComparator;
    assert_eq!(
        comparator.compare(&baseline, &baseline).unwrap().class,
        DriftClass::Exact
    );

    let mut timing = baseline.clone();
    timing.observations[0].virtual_tick += 1;
    timing.observations[0].observation_sha256 = hash_serializable(&(
        timing.observations[0].sequence,
        &timing.observations[0].input_id,
        &timing.observations[0].input_sha256,
        &timing.observations[0].output_sha256,
        &timing.observations[0].metadata_sha256,
        timing.observations[0].virtual_tick,
        timing.observations[0].outcome,
        &timing.observations[0].applied_fault_ids,
    ))
    .unwrap();
    timing.trace_sha256 = hash_serializable(&(
        &timing.bundle_sha256,
        &timing.fault_plan_sha256,
        &timing.observations,
    ))
    .unwrap();
    assert_eq!(
        comparator.compare(&baseline, &timing).unwrap().class,
        DriftClass::TimingDrift
    );

    let mut semantic = baseline.clone();
    semantic.observations[0].output_sha256 = hex('8');
    semantic.observations[0].observation_sha256 = hash_serializable(&(
        semantic.observations[0].sequence,
        &semantic.observations[0].input_id,
        &semantic.observations[0].input_sha256,
        &semantic.observations[0].output_sha256,
        &semantic.observations[0].metadata_sha256,
        semantic.observations[0].virtual_tick,
        semantic.observations[0].outcome,
        &semantic.observations[0].applied_fault_ids,
    ))
    .unwrap();
    semantic.trace_sha256 = hash_serializable(&(
        &semantic.bundle_sha256,
        &semantic.fault_plan_sha256,
        &semantic.observations,
    ))
    .unwrap();
    assert_eq!(
        comparator.compare(&baseline, &semantic).unwrap().class,
        DriftClass::SemanticDrift
    );
}

#[test]
fn independent_identical_replays_receive_reproducibility_certificate() {
    let bundle = bundle();
    let plan = plan(&bundle);
    let (_, first) = run("engine-1", bundle.clone(), plan.clone());
    let (_, second) = run("engine-2", bundle, plan);
    let mut authority =
        ReproducibilityAuthority::new("repro-1", hex('b'), 2, hex('0')).unwrap();
    let certificate = authority.certify(&[first, second]).unwrap();
    certificate.verify().unwrap();
    authority.audit().verify().unwrap();
}

#[test]
fn result_drift_blocks_reproducibility() {
    let bundle = bundle();
    let plan = plan(&bundle);
    let (_, first) = run("engine-1", bundle.clone(), plan.clone());
    let mut changed_plan = plan;
    changed_plan.rules.push(FaultRule::new("timeout-1", 1, FaultKind::Timeout, 1).unwrap());
    changed_plan.plan_sha256 = hash_serializable(&(
        &changed_plan.plan_id,
        &changed_plan.bundle_sha256,
        &changed_plan.rules,
    ))
    .unwrap();
    let (_, second) = run("engine-2", bundle, changed_plan);
    let mut authority =
        ReproducibilityAuthority::new("repro-1", hex('b'), 2, hex('0')).unwrap();
    assert!(matches!(
        authority.certify(&[first, second]),
        Err(ReplayError::CertificationDenied(_))
    ));
}

#[test]
fn replay_audit_tampering_is_detected() {
    let bundle = bundle();
    let plan = plan(&bundle);
    let mut engine = ReplayEngine::new("engine-1", bundle, plan, hex('0')).unwrap();
    engine.start().unwrap();
    engine.audit_mut().records_mut()[0].event.outcome = "modified".into();
    assert_eq!(
        engine.audit().verify(),
        Err(ReplayError::AuditRecordHashMismatch { record_index: 0 })
    );
}
