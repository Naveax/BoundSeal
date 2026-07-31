use nxb_adapter_boundary::{
    AdapterAction, AdapterAdmissionAuthority, AdapterAdmissionRequest, AdapterCapability,
    AdapterConformanceAuthority, AdapterEnvelope, AdapterGrant, AdapterManifest, AdapterOutcome,
    AdapterResourceLimits, AdapterResourceUsage, AdapterSession, FixtureObject, FixtureObjectKind,
    FixtureProfile, FixtureRegistry,
};
use nxb_replay_lab::{
    FaultPlan, ReplayBundle, ReplayEngine, ReplayInputRef, ReproducibilityAuthority,
};

fn hex(character: char) -> String {
    std::iter::repeat_n(character, 64).collect()
}

fn adapter_certificate() -> AdapterConformanceCertificate {
    let limits = AdapterResourceLimits::new(8, 4096, 32_768, 10_000, 1024 * 1024).unwrap();
    let manifest = AdapterManifest::new(
        "manifest-1",
        "fixture-adapter",
        "1.0.0",
        hex('a'),
        1,
        BTreeSet::from([
            AdapterCapability::FixtureRead,
            AdapterCapability::Finalization,
        ]),
        BTreeSet::from([AdapterAction::LoadFixture, AdapterAction::Finalize]),
        limits,
        false,
    )
    .unwrap();
    let profile = FixtureProfile::new(
        "profile-1",
        hex('b'),
        vec![FixtureObject::new(
            "input-1",
            "fixture://profile-1/input-1",
            FixtureObjectKind::StructuredDocument,
            hex('c'),
            100,
            BTreeMap::new(),
        )
        .unwrap()],
        4,
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
                expires_at_milliseconds: 1000,
            },
        )
        .unwrap();
    let mut session = AdapterSession::open(&manifest, &mut grant, &profile, 2).unwrap();
    let load = AdapterEnvelope::new(
        session.snapshot().session_id.clone(),
        1,
        AdapterAction::LoadFixture,
        profile.profile_sha256(),
        hex('c'),
        100,
        BTreeMap::new(),
    )
    .unwrap();
    session
        .execute(
            load,
            AdapterResourceUsage {
                cpu_milliseconds: 1,
                peak_memory_bytes: 1024,
                output_bytes: 1,
            },
            hex('d'),
            AdapterOutcome::Accepted,
            3,
        )
        .unwrap();
    let finalize = AdapterEnvelope::new(
        session.snapshot().session_id.clone(),
        2,
        AdapterAction::Finalize,
        profile.profile_sha256(),
        hex('d'),
        1,
        BTreeMap::new(),
    )
    .unwrap();
    session
        .execute(
            finalize,
            AdapterResourceUsage {
                cpu_milliseconds: 1,
                peak_memory_bytes: 1024,
                output_bytes: 1,
            },
            hex('e'),
            AdapterOutcome::Finalized,
            4,
        )
        .unwrap();
    let mut authority =
        AdapterConformanceAuthority::new("conformance-1", hex('b'), hex('0')).unwrap();
    authority.certify(&session, &registry, &profile).unwrap()
}

fn reproducibility_certificate(
    adapter: &AdapterConformanceCertificate,
) -> ReproducibilityCertificate {
    let bundle = ReplayBundle::new(
        "bundle-1",
        adapter,
        vec![ReplayInputRef::new(
            "input-1",
            "fixture://profile-1/input-1",
            hex('c'),
            100,
        )
        .unwrap()],
        BTreeSet::from([hex('f')]),
        hex('1'),
        0,
    )
    .unwrap();
    let plan = FaultPlan::empty("fault-plan-1", bundle.bundle_sha256.clone()).unwrap();
    let run = |engine_id: &str| {
        let mut engine =
            ReplayEngine::new(engine_id, bundle.clone(), plan.clone(), hex('0')).unwrap();
        engine.start().unwrap();
        engine.step(1, hex('2'), hex('3'), 1).unwrap();
        engine.finish().unwrap().1
    };
    let first = run("engine-1");
    let second = run("engine-2");
    let mut authority =
        ReproducibilityAuthority::new("repro-1", hex('b'), 2, hex('0')).unwrap();
    authority.certify(&[first, second]).unwrap()
}

fn inventory() -> ComponentInventory {
    ComponentInventory::new(
        "inventory-1",
        hex('b'),
        vec![
            ComponentRecord::new(
                "policy-schema",
                ComponentKind::PolicySchema,
                "1.0.0",
                hex('1'),
                hex('2'),
                "Apache-2.0",
                BTreeSet::new(),
            )
            .unwrap(),
            ComponentRecord::new(
                "adapter-boundary",
                ComponentKind::Library,
                "1.0.0",
                hex('3'),
                hex('4'),
                "Apache-2.0",
                BTreeSet::from(["policy-schema".into()]),
            )
            .unwrap(),
            ComponentRecord::new(
                "nxb-platform",
                ComponentKind::Binary,
                "1.0.0",
                hex('5'),
                hex('6'),
                "Apache-2.0",
                BTreeSet::from(["adapter-boundary".into()]),
            )
            .unwrap(),
        ],
        "release",
    )
    .unwrap()
}

fn compatibility(policy: &str) -> CompatibilityContract {
    let axes = [
        CompatibilityAxis::EventSchema,
        CompatibilityAxis::PolicySchema,
        CompatibilityAxis::FixtureSchema,
        CompatibilityAxis::AdapterSchema,
        CompatibilityAxis::ReplaySchema,
        CompatibilityAxis::ReportSchema,
    ];
    let requirements = axes
        .into_iter()
        .enumerate()
        .map(|(index, axis)| {
            CompatibilityRequirement::new(
                format!("requirement-{}", index + 1),
                axis,
                1,
                1,
                1,
                hex(char::from_digit((index + 1) as u32, 10).unwrap()),
            )
            .unwrap()
        })
        .collect();
    CompatibilityContract::new("compatibility-1", policy, requirements, None).unwrap()
}

fn gates(policy: &str) -> ReleaseGateSet {
    let classes = [
        ReleaseGateClass::HardSafety,
        ReleaseGateClass::Compatibility,
        ReleaseGateClass::Reproducibility,
        ReleaseGateClass::ArtifactIntegrity,
        ReleaseGateClass::RollbackReadiness,
    ];
    let gates = classes
        .into_iter()
        .enumerate()
        .map(|(index, class)| {
            ReleaseGate::new(
                format!("gate-{}", index + 1),
                class,
                GateDecision::Passed,
                hex(char::from_digit((index + 1) as u32, 10).unwrap()),
                None,
            )
            .unwrap()
        })
        .collect();
    ReleaseGateSet::new("gate-set-1", policy, gates).unwrap()
}

fn artifacts(
    inventory: &ComponentInventory,
    gates: &ReleaseGateSet,
) -> (ArtifactManifest, ArtifactAttestation) {
    let entries = inventory
        .components
        .values()
        .enumerate()
        .map(|(index, component)| {
            ArtifactEntry::new(
                format!("artifacts/{}.bin", component.component_id),
                component.component_id.clone(),
                component.artifact_sha256.clone(),
                (index + 1) as u64 * 100,
            )
            .unwrap()
        })
        .collect();
    let manifest = ArtifactManifest::new("artifact-manifest-1", inventory, entries).unwrap();
    let mut authority =
        ArtifactAttestationAuthority::new("artifact-authority-1", hex('b'), hex('0')).unwrap();
    let attestation = authority.attest(inventory, gates, &manifest).unwrap();
    (manifest, attestation)
}

fn rollout(
    attestation: &ArtifactAttestation,
) -> (RolloutPlan, RollbackDrillCertificate, RolloutSimulationReceipt) {
    let plan = RolloutPlan::new(
        "rollout-1",
        attestation,
        vec![
            RolloutStage::new("canary-10", 10, 10, hex('7')).unwrap(),
            RolloutStage::new("canary-100", 100, 20, hex('8')).unwrap(),
        ],
    )
    .unwrap();
    let mut drill = RolloutDrill::new(plan.clone(), hex('0')).unwrap();
    drill.start().unwrap();
    assert_eq!(
        drill.record_stage("canary-10", hex('7'), true).unwrap(),
        RolloutState::CanaryRunning
    );
    assert_eq!(
        drill.record_stage("canary-100", hex('8'), true).unwrap(),
        RolloutState::CanaryValidated
    );
    drill.begin_rollback_drill().unwrap();
    let rollback = drill
        .complete_rollback(plan.baseline_manifest_root_sha256.clone(), hex('9'))
        .unwrap();
    let receipt = drill.finalize().unwrap();
    (plan, rollback, receipt)
}

#[test]
fn inventory_rejects_unknown_dependencies_and_cycles() {
    let unknown = ComponentRecord::new(
        "component-a",
        ComponentKind::Library,
        "1.0.0",
        hex('1'),
        hex('2'),
        "Apache-2.0",
        BTreeSet::from(["missing".into()]),
    )
    .unwrap();
    assert!(matches!(
        ComponentInventory::new("inventory-1", hex('b'), vec![unknown], "release"),
        Err(ReleaseError::InvalidInventory(_))
    ));

    let left = ComponentRecord::new(
        "left",
        ComponentKind::Library,
        "1.0.0",
        hex('1'),
        hex('2'),
        "Apache-2.0",
        BTreeSet::from(["right".into()]),
    )
    .unwrap();
    let right = ComponentRecord::new(
        "right",
        ComponentKind::Library,
        "1.0.0",
        hex('3'),
        hex('4'),
        "Apache-2.0",
        BTreeSet::from(["left".into()]),
    )
    .unwrap();
    assert!(matches!(
        ComponentInventory::new("inventory-2", hex('b'), vec![left, right], "release"),
        Err(ReleaseError::InvalidInventory(_))
    ));
}

#[test]
fn compatibility_records_version_drift_and_reversible_migrations() {
    let requirement = CompatibilityRequirement::new(
        "event-schema",
        CompatibilityAxis::EventSchema,
        2,
        3,
        1,
        hex('1'),
    )
    .unwrap();
    assert_eq!(requirement.status, CompatibilityStatus::TooOld);
    let migration = MigrationPlan::new(
        "migration-1",
        vec![MigrationStep::new(
            "step-1",
            MigrationKind::SchemaForward,
            1,
            2,
            true,
            hex('2'),
        )
        .unwrap()],
    )
    .unwrap();
    migration.verify().unwrap();
    let contract =
        CompatibilityContract::new("contract-1", hex('b'), vec![requirement], Some(&migration))
            .unwrap();
    assert!(!contract.all_compatible);
}

#[test]
fn hard_safety_gate_cannot_be_waived() {
    assert!(matches!(
        ReleaseGate::new(
            "hard-safety",
            ReleaseGateClass::HardSafety,
            GateDecision::Waived,
            hex('1'),
            Some("accepted risk"),
        ),
        Err(ReleaseError::InvalidGate(_))
    ));
}

#[test]
fn artifact_manifest_requires_exact_inventory_coverage() {
    let inventory = inventory();
    let component = inventory.components.values().next().unwrap();
    let incomplete = vec![ArtifactEntry::new(
        "artifacts/one.bin",
        component.component_id.clone(),
        component.artifact_sha256.clone(),
        1,
    )
    .unwrap()];
    assert!(matches!(
        ArtifactManifest::new("manifest-1", &inventory, incomplete),
        Err(ReleaseError::InvalidArtifact(_))
    ));
}

#[test]
fn rollout_cannot_finalize_without_rollback_drill() {
    let inventory = inventory();
    let gates = gates(&hex('b'));
    let (_, attestation) = artifacts(&inventory, &gates);
    let plan = RolloutPlan::new(
        "rollout-1",
        &attestation,
        vec![RolloutStage::new("canary-100", 100, 10, hex('7')).unwrap()],
    )
    .unwrap();
    let mut drill = RolloutDrill::new(plan, hex('0')).unwrap();
    drill.start().unwrap();
    drill.record_stage("canary-100", hex('7'), true).unwrap();
    assert_eq!(
        drill.finalize(),
        Err(ReleaseError::InvalidRolloutTransition)
    );
}

#[test]
fn unhealthy_canary_rolls_back_but_is_not_release_certifiable() {
    let adapter = adapter_certificate();
    let reproducibility = reproducibility_certificate(&adapter);
    let inventory = inventory();
    let compatibility = compatibility(&hex('b'));
    let gates = gates(&hex('b'));
    let (_, attestation) = artifacts(&inventory, &gates);
    let plan = RolloutPlan::new(
        "rollout-1",
        &attestation,
        vec![
            RolloutStage::new("canary-10", 10, 10, hex('7')).unwrap(),
            RolloutStage::new("canary-100", 100, 20, hex('8')).unwrap(),
        ],
    )
    .unwrap();
    let mut drill = RolloutDrill::new(plan.clone(), hex('0')).unwrap();
    drill.start().unwrap();
    assert_eq!(
        drill.record_stage("canary-10", hex('0'), false).unwrap(),
        RolloutState::RollbackRunning
    );
    let rollback = drill
        .complete_rollback(plan.baseline_manifest_root_sha256.clone(), hex('9'))
        .unwrap();
    let receipt = drill.finalize().unwrap();
    let mut authority =
        PlatformReleaseAuthority::new("platform-authority-1", hex('b'), hex('0')).unwrap();
    assert!(matches!(
        authority.certify(
            &adapter,
            &reproducibility,
            &inventory,
            &compatibility,
            &gates,
            &attestation,
            &plan,
            &rollback,
            &receipt,
        ),
        Err(ReleaseError::CertificationDenied(_))
    ));
}

#[test]
fn full_p7_p8_p9_chain_receives_platform_release_certificate() {
    let adapter = adapter_certificate();
    let reproducibility = reproducibility_certificate(&adapter);
    let inventory = inventory();
    let compatibility = compatibility(&hex('b'));
    let gates = gates(&hex('b'));
    let (_, attestation) = artifacts(&inventory, &gates);
    let (plan, rollback, receipt) = rollout(&attestation);
    let mut authority =
        PlatformReleaseAuthority::new("platform-authority-1", hex('b'), hex('0')).unwrap();
    let certificate = authority
        .certify(
            &adapter,
            &reproducibility,
            &inventory,
            &compatibility,
            &gates,
            &attestation,
            &plan,
            &rollback,
            &receipt,
        )
        .unwrap();
    certificate.verify().unwrap();
    authority.audit().verify().unwrap();
}

#[test]
fn policy_drift_blocks_platform_release() {
    let adapter = adapter_certificate();
    let reproducibility = reproducibility_certificate(&adapter);
    let inventory = inventory();
    let compatibility = compatibility(&hex('a'));
    let gates = gates(&hex('b'));
    let (_, attestation) = artifacts(&inventory, &gates);
    let (plan, rollback, receipt) = rollout(&attestation);
    let mut authority =
        PlatformReleaseAuthority::new("platform-authority-1", hex('b'), hex('0')).unwrap();
    assert!(matches!(
        authority.certify(
            &adapter,
            &reproducibility,
            &inventory,
            &compatibility,
            &gates,
            &attestation,
            &plan,
            &rollback,
            &receipt,
        ),
        Err(ReleaseError::CertificationDenied(_))
    ));
}

#[test]
fn release_audit_tampering_is_detected() {
    let mut audit = ReleaseAuditChain::new(hex('0')).unwrap();
    audit
        .append(ReleaseAuditEvent {
            action: "test".into(),
            subject_id: "subject-1".into(),
            outcome: "ok".into(),
            metadata: BTreeMap::new(),
        })
        .unwrap();
    audit.records_mut()[0].event.outcome = "modified".into();
    assert_eq!(
        audit.verify(),
        Err(ReleaseError::AuditRecordHashMismatch { record_index: 0 })
    );
}
