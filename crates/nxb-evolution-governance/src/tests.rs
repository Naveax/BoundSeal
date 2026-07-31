use std::collections::{BTreeMap, BTreeSet};

use nxb_lifecycle_governance::LifecycleClosureCertificate;

use crate::*;

fn hex(character: char) -> String {
    character.to_string().repeat(64)
}

fn lifecycle_fixture() -> LifecycleClosureCertificate {
    let certificate_id = "lifecycle-closure-fixture".to_string();
    let policy_snapshot_sha256 = hex('a');
    let final_assurance_certificate_sha256 = hex('b');
    let roadmap_closure_sha256 = hex('c');
    let maintenance_release_certificate_sha256 = hex('d');
    let continuity_certificate_sha256 = hex('e');
    let independent_verification_quorum_sha256 = hex('f');
    let tombstone_certificate_sha256 = hex('1');
    let closed_milestones = (0_u32..=101).collect::<BTreeSet<_>>();
    let authority_audit_tail_hash = hex('2');
    let certificate_sha256 = hash_serializable(&(
        &certificate_id,
        &policy_snapshot_sha256,
        &final_assurance_certificate_sha256,
        &roadmap_closure_sha256,
        &maintenance_release_certificate_sha256,
        &continuity_certificate_sha256,
        &independent_verification_quorum_sha256,
        &tombstone_certificate_sha256,
        &closed_milestones,
        &authority_audit_tail_hash,
    ))
    .unwrap();
    LifecycleClosureCertificate {
        certificate_id,
        policy_snapshot_sha256,
        final_assurance_certificate_sha256,
        roadmap_closure_sha256,
        maintenance_release_certificate_sha256,
        continuity_certificate_sha256,
        independent_verification_quorum_sha256,
        tombstone_certificate_sha256,
        closed_milestones,
        authority_audit_tail_hash,
        certificate_sha256,
    }
}

struct Fixture {
    lifecycle: LifecycleClosureCertificate,
    baseline: EvolutionBaseline,
    proposal: EvolutionProposal,
    graph: CompatibilityImpactGraph,
    capsule: MigrationCapsule,
    canary: CanaryMatrix,
    evolution: EvolutionReleaseCertificate,
    registry: GenerationRegistry,
    path: GenerationTransitionPath,
    shadow: ShadowComparisonQuorum,
    rollback: RollbackProof,
    continuity: GenerationContinuityCertificate,
    charter: StewardshipCharter,
    quorum: SuccessionQuorum,
    transfer: CustodyTransfer,
    rotation: RootRotationPlan,
    history: HistoricalAttestation,
}

fn fixture() -> Fixture {
    let lifecycle = lifecycle_fixture();
    let baseline = EvolutionBaseline::new("evolution-1", &lifecycle).unwrap();
    let component_deltas = BTreeMap::from([("core".into(), hex('3')), ("policy".into(), hex('4'))]);
    let invariant_deltas = BTreeMap::from([
        ("audit-integrity".into(), hex('5')),
        ("fail-closed".into(), hex('6')),
    ]);
    let proposal = EvolutionProposal::new(
        "proposal-1",
        &baseline,
        EvolutionClass::InvariantTightening,
        component_deltas,
        invariant_deltas,
        10,
        1_000,
    )
    .unwrap();
    let graph = CompatibilityImpactGraph::new(
        &proposal,
        BTreeMap::from([
            ("core".into(), hex('7')),
            ("policy".into(), hex('8')),
            ("audit".into(), hex('9')),
        ]),
        BTreeSet::from([
            ("policy".into(), "core".into()),
            ("core".into(), "audit".into()),
        ]),
        BTreeSet::from(["core".into(), "policy".into()]),
    )
    .unwrap();
    let forward = BTreeMap::from([("schema".into(), hex('a')), ("metadata".into(), hex('b'))]);
    let rollback_steps =
        BTreeMap::from([("schema".into(), hex('c')), ("metadata".into(), hex('d'))]);
    let capsule = MigrationCapsule::new(
        "capsule-1",
        &proposal,
        1,
        2,
        forward,
        rollback_steps,
        hex('e'),
        hex('f'),
    )
    .unwrap();
    let canary_samples = vec![
        CanarySample::new("fixture-a", hex('1'), hex('2'), hex('3'), true).unwrap(),
        CanarySample::new("fixture-b", hex('4'), hex('5'), hex('6'), true).unwrap(),
    ];
    let canary = CanaryMatrix::new(
        &proposal,
        &capsule,
        canary_samples,
        BTreeSet::from(["fixture-a".into(), "fixture-b".into()]),
    )
    .unwrap();
    let mut evolution_authority =
        EvolutionReleaseAuthority::new("evolution-authority", hex('a'), hex('7')).unwrap();
    let evolution = evolution_authority
        .certify(
            &lifecycle, &baseline, &proposal, &graph, &capsule, &canary, 100,
        )
        .unwrap();

    let registry = GenerationRegistry::new(
        hex('a'),
        vec![
            GenerationRecord::new(
                1,
                None,
                lifecycle.certificate_sha256.clone(),
                hex('8'),
                hex('9'),
            )
            .unwrap(),
            GenerationRecord::new(
                2,
                Some(1),
                evolution.certificate_sha256.clone(),
                hex('f'),
                hex('1'),
            )
            .unwrap(),
        ],
    )
    .unwrap();
    let path = GenerationTransitionPath::new(
        "upgrade-1-2",
        &registry,
        1,
        2,
        TransitionDirection::Upgrade,
        &capsule,
        BTreeMap::from([("schema".into(), hex('2')), ("metadata".into(), hex('3'))]),
    )
    .unwrap();
    let shadow = ShadowComparisonQuorum::new(
        &path,
        vec![
            ShadowObservation::new(
                "verifier-a",
                "fixture-a",
                hex('4'),
                hex('5'),
                hex('6'),
                true,
            )
            .unwrap(),
            ShadowObservation::new(
                "verifier-b",
                "fixture-a",
                hex('4'),
                hex('5'),
                hex('6'),
                true,
            )
            .unwrap(),
            ShadowObservation::new(
                "verifier-a",
                "fixture-b",
                hex('7'),
                hex('8'),
                hex('9'),
                true,
            )
            .unwrap(),
            ShadowObservation::new(
                "verifier-b",
                "fixture-b",
                hex('7'),
                hex('8'),
                hex('9'),
                true,
            )
            .unwrap(),
        ],
        BTreeSet::from(["fixture-a".into(), "fixture-b".into()]),
    )
    .unwrap();
    let rollback = RollbackProof::new(
        &path,
        hex('a'),
        hex('b'),
        hex('a'),
        BTreeMap::from([("schema".into(), hex('c')), ("metadata".into(), hex('d'))]),
    )
    .unwrap();
    let mut generation_authority =
        GenerationContinuityAuthority::new("generation-authority", hex('a'), hex('e')).unwrap();
    let continuity = generation_authority
        .certify(&evolution, &registry, &path, &shadow, &rollback)
        .unwrap();

    let charter =
        StewardshipCharter::new("charter-1", &lifecycle, &evolution, &continuity, 10_000).unwrap();
    let organization = hex('f');
    let successor = hex('1');
    let approvals = vec![
        SuccessionApproval::new(
            StewardIdentity::new("custodian-a", StewardRole::Custodian, organization.clone())
                .unwrap(),
            &charter,
            successor.clone(),
            1_000,
        )
        .unwrap(),
        SuccessionApproval::new(
            StewardIdentity::new("auditor-a", StewardRole::Auditor, organization.clone()).unwrap(),
            &charter,
            successor.clone(),
            1_000,
        )
        .unwrap(),
        SuccessionApproval::new(
            StewardIdentity::new("safety-a", StewardRole::SafetyOfficer, organization.clone())
                .unwrap(),
            &charter,
            successor.clone(),
            1_000,
        )
        .unwrap(),
    ];
    let quorum = SuccessionQuorum::new(&charter, successor.clone(), approvals).unwrap();
    let custody_roots = BTreeMap::from([
        ("archive".into(), hex('2')),
        ("audit".into(), hex('3')),
        ("policy".into(), hex('4')),
    ]);
    let transfer = CustodyTransfer::new(
        "transfer-1",
        &charter,
        &quorum,
        hex('5'),
        successor,
        custody_roots.clone(),
        1_100,
    )
    .unwrap();
    let rotation = RootRotationPlan::new(
        "rotation-1",
        &transfer,
        custody_roots,
        BTreeMap::from([
            ("archive".into(), hex('6')),
            ("audit".into(), hex('7')),
            ("policy".into(), hex('8')),
        ]),
        1_000,
        false,
    )
    .unwrap();
    let history = HistoricalAttestation::new(
        "history-1",
        hex('a'),
        BTreeMap::from([
            (0, hex('1')),
            (29, hex('2')),
            (47, hex('3')),
            (65, hex('4')),
            (83, hex('5')),
            (101, lifecycle.certificate_sha256.clone()),
            (107, evolution.certificate_sha256.clone()),
            (113, continuity.certificate_sha256.clone()),
        ]),
        BTreeMap::from([
            ("verifier-a".into(), hex('6')),
            ("verifier-b".into(), hex('7')),
            ("verifier-c".into(), hex('8')),
        ]),
    )
    .unwrap();

    Fixture {
        lifecycle,
        baseline,
        proposal,
        graph,
        capsule,
        canary,
        evolution,
        registry,
        path,
        shadow,
        rollback,
        continuity,
        charter,
        quorum,
        transfer,
        rotation,
        history,
    }
}

#[test]
fn closes_nxb_102_through_119() {
    let fixture = fixture();
    fixture.baseline.verify().unwrap();
    fixture.proposal.verify(100).unwrap();
    fixture.graph.verify(&fixture.proposal).unwrap();
    fixture.capsule.verify(&fixture.proposal).unwrap();
    fixture
        .canary
        .verify(&fixture.proposal, &fixture.capsule)
        .unwrap();
    fixture.evolution.verify().unwrap();
    fixture.registry.verify().unwrap();
    fixture.path.verify(&fixture.registry).unwrap();
    fixture.shadow.verify(&fixture.path).unwrap();
    fixture.rollback.verify(&fixture.path).unwrap();
    fixture.continuity.verify().unwrap();
    fixture.charter.verify().unwrap();
    fixture.quorum.verify(&fixture.charter).unwrap();
    fixture
        .transfer
        .verify(&fixture.charter, &fixture.quorum)
        .unwrap();
    fixture.rotation.verify(&fixture.transfer).unwrap();
    fixture.history.verify().unwrap();

    let mut authority =
        PostLifecycleClosureAuthority::new("post-lifecycle-authority", hex('a'), hex('9')).unwrap();
    let certificate = authority
        .certify(
            &fixture.lifecycle,
            &fixture.evolution,
            &fixture.continuity,
            &fixture.charter,
            &fixture.quorum,
            &fixture.transfer,
            &fixture.rotation,
            &fixture.history,
        )
        .unwrap();
    certificate.verify().unwrap();
    assert_eq!(certificate.closed_milestones, (0_u32..=119).collect());
    authority.audit().verify().unwrap();
}

#[test]
fn incomplete_impact_graph_is_rejected() {
    let lifecycle = lifecycle_fixture();
    let baseline = EvolutionBaseline::new("evolution-x", &lifecycle).unwrap();
    let proposal = EvolutionProposal::new(
        "proposal-x",
        &baseline,
        EvolutionClass::SchemaOnly,
        BTreeMap::from([("core".into(), hex('1'))]),
        BTreeMap::from([("schema".into(), hex('2'))]),
        1,
        100,
    )
    .unwrap();
    let result = CompatibilityImpactGraph::new(
        &proposal,
        BTreeMap::from([("other".into(), hex('3'))]),
        BTreeSet::new(),
        BTreeSet::from(["other".into()]),
    );
    assert!(matches!(result, Err(EvolutionError::InvalidEvolution(_))));
}

#[test]
fn irreversible_migration_is_rejected_by_step_symmetry() {
    let fixture = fixture();
    let result = MigrationCapsule::new(
        "capsule-bad",
        &fixture.proposal,
        1,
        2,
        BTreeMap::from([("forward".into(), hex('1'))]),
        BTreeMap::from([("different".into(), hex('2'))]),
        hex('3'),
        hex('4'),
    );
    assert!(matches!(result, Err(EvolutionError::InvalidEvolution(_))));
}

#[test]
fn generation_fork_is_rejected() {
    let fixture = fixture();
    let result = GenerationRegistry::new(
        hex('a'),
        vec![
            GenerationRecord::new(1, None, hex('1'), hex('2'), hex('3')).unwrap(),
            GenerationRecord::new(3, Some(2), hex('4'), hex('5'), hex('6')).unwrap(),
        ],
    );
    assert!(matches!(result, Err(EvolutionError::InvalidGeneration(_))));
}

#[test]
fn rollback_must_restore_source_root() {
    let fixture = fixture();
    let result = RollbackProof::new(
        &fixture.path,
        hex('1'),
        hex('2'),
        hex('3'),
        BTreeMap::from([("schema".into(), hex('4'))]),
    );
    assert!(matches!(result, Err(EvolutionError::InvalidGeneration(_))));
}

#[test]
fn succession_requires_one_organization_and_all_roles() {
    let fixture = fixture();
    let successor = hex('1');
    let approvals = vec![
        SuccessionApproval::new(
            StewardIdentity::new("custodian-b", StewardRole::Custodian, hex('2')).unwrap(),
            &fixture.charter,
            successor.clone(),
            1,
        )
        .unwrap(),
        SuccessionApproval::new(
            StewardIdentity::new("auditor-b", StewardRole::Auditor, hex('3')).unwrap(),
            &fixture.charter,
            successor.clone(),
            1,
        )
        .unwrap(),
        SuccessionApproval::new(
            StewardIdentity::new("safety-b", StewardRole::SafetyOfficer, hex('2')).unwrap(),
            &fixture.charter,
            successor.clone(),
            1,
        )
        .unwrap(),
    ];
    let result = SuccessionQuorum::new(&fixture.charter, successor, approvals);
    assert!(matches!(result, Err(EvolutionError::InvalidStewardship(_))));
}

#[test]
fn root_rotation_rejects_reused_roots() {
    let fixture = fixture();
    let roots = BTreeMap::from([("audit".into(), hex('1'))]);
    let result = RootRotationPlan::new(
        "rotation-bad",
        &fixture.transfer,
        roots.clone(),
        roots,
        10,
        false,
    );
    assert!(matches!(result, Err(EvolutionError::InvalidStewardship(_))));
}

#[test]
fn audit_tampering_is_detected() {
    let fixture = fixture();
    let mut authority =
        PostLifecycleClosureAuthority::new("post-lifecycle-authority", hex('a'), hex('9')).unwrap();
    authority
        .certify(
            &fixture.lifecycle,
            &fixture.evolution,
            &fixture.continuity,
            &fixture.charter,
            &fixture.quorum,
            &fixture.transfer,
            &fixture.rotation,
            &fixture.history,
        )
        .unwrap();
    authority.audit.records_mut()[0].event.outcome = "tampered".into();
    assert!(matches!(
        authority.audit.verify(),
        Err(EvolutionError::AuditRecordHashMismatch(0))
    ));
}
