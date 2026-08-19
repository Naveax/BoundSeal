use std::collections::{BTreeMap, BTreeSet};

use nxb_lifecycle_governance::LifecycleClosureCertificate;

use crate::*;

fn hex(character: char) -> String {
    std::iter::repeat_n(character, 64).collect()
}

fn lifecycle_fixture() -> LifecycleClosureCertificate {
    let certificate_id = "lifecycle-closure-fixture".to_string();
    let policy_snapshot_sha256 = hex('a');
    let final_assurance_certificate_sha256 = hex('b');
    let roadmap_closure_sha256 = hex('c');
    let maintenance_release_certificate_sha256 = hex('d');
    let continuity_certificate_sha256 = hex('e');
    let independent_verification_quorum_sha256 = hex('1');
    let tombstone_certificate_sha256 = hex('2');
    let closed_milestones = (0_u32..=101).collect::<BTreeSet<_>>();
    let authority_audit_tail_hash = hex('3');
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

struct FullFixture {
    lifecycle: LifecycleClosureCertificate,
    identity: SuccessorIdentity,
    envelope: CompatibilityEnvelope,
    transfer: StateTransferManifest,
    cutover_plan: CutoverPlan,
    cutover_receipt: CutoverReceipt,
    succession: SuccessionCertificate,
    panel: ReviewPanel,
    sample_plan: EvidenceSamplePlan,
    matrix: ReviewAssignmentMatrix,
    ledger: ReviewFindingLedger,
    remediation: RemediationClosure,
    renewal: RenewalCertificate,
    bundle: PublicVerificationBundle,
    epoch: TrustEpoch,
    quorum: PublicVerificationQuorum,
    sunset_plan: SunsetPlan,
    sunset: SunsetCertificate,
}

fn full_fixture() -> FullFixture {
    let lifecycle = lifecycle_fixture();
    let identity = SuccessorIdentity::new("successor-1", "lineage-1", &lifecycle).unwrap();
    let envelope = CompatibilityEnvelope::new(
        "compat-1",
        &identity,
        hex('4'),
        hex('5'),
        CompatibilityMode::ForwardCompatible,
        ["core".to_string(), "audit".to_string()]
            .into_iter()
            .collect(),
        BTreeMap::from([
            ("audit-chain".into(), hex('6')),
            ("secret-boundary".into(), hex('7')),
        ]),
    )
    .unwrap();
    let transfer = StateTransferManifest::new(
        "transfer-1",
        &envelope,
        vec![
            StateTransferObject::new("object-1", hex('8'), 64).unwrap(),
            StateTransferObject::new("object-2", hex('9'), 128).unwrap(),
        ],
        hex('a'),
    )
    .unwrap();
    let cutover_plan = CutoverPlan::new(
        "cutover-1",
        &identity,
        &envelope,
        &transfer,
        100,
        200,
        [hex('b'), hex('c')].into_iter().collect(),
        hex('d'),
    )
    .unwrap();
    let cutover_receipt = CutoverReceipt::new(
        "cutover-receipt-1",
        &cutover_plan,
        canonical_cutover_steps()
            .into_iter()
            .enumerate()
            .map(|(index, step)| {
                (
                    step,
                    hex(char::from_digit((index as u32 % 9) + 1, 16).unwrap()),
                )
            })
            .collect(),
        150,
        0,
        true,
    )
    .unwrap();
    let mut succession_authority = SuccessionAuthority::new(
        "succession-authority",
        &lifecycle.policy_snapshot_sha256,
        hex('e'),
    )
    .unwrap();
    let succession = succession_authority
        .certify(
            &lifecycle,
            &identity,
            &envelope,
            &transfer,
            &cutover_plan,
            &cutover_receipt,
        )
        .unwrap();
    let panel = ReviewPanel::new(
        "panel-1",
        &succession,
        vec![
            ReviewPanelMember::new(
                "reviewer-1",
                ReviewRole::Protocol,
                hex('1'),
                hex('4'),
                false,
            )
            .unwrap(),
            ReviewPanelMember::new("reviewer-2", ReviewRole::Safety, hex('2'), hex('5'), false)
                .unwrap(),
            ReviewPanelMember::new("reviewer-3", ReviewRole::Audit, hex('3'), hex('6'), false)
                .unwrap(),
        ],
    )
    .unwrap();
    let evidence_roots = BTreeMap::from([
        ("evidence-1".into(), hex('7')),
        ("evidence-2".into(), hex('8')),
        ("evidence-3".into(), hex('9')),
    ]);
    let sample_plan =
        EvidenceSamplePlan::new("sample-1", &succession, evidence_roots, hex('a'), 3).unwrap();
    let reviewer_ids = panel.members.keys().cloned().collect::<BTreeSet<_>>();
    let assignments = sample_plan
        .sample_ids
        .iter()
        .map(|evidence_id| {
            ReviewAssignment::new(evidence_id.clone(), reviewer_ids.clone()).unwrap()
        })
        .collect::<Vec<_>>();
    let matrix =
        ReviewAssignmentMatrix::new("matrix-1", &panel, &sample_plan, assignments).unwrap();
    let finding = ReviewFinding::new(
        "finding-1",
        sample_plan.sample_ids.iter().next().unwrap().clone(),
        ReviewFindingSeverity::High,
        ReviewFindingState::Remediated,
        hex('b'),
        Some(hex('c')),
    )
    .unwrap();
    let ledger = ReviewFindingLedger::new("ledger-1", &matrix, vec![finding]).unwrap();
    let remediation = RemediationClosure::new("remediation-1", &ledger).unwrap();
    let mut renewal_authority = RenewalAuthority::new(
        "renewal-authority",
        &lifecycle.policy_snapshot_sha256,
        hex('d'),
    )
    .unwrap();
    let renewal = renewal_authority
        .certify(
            &succession,
            &panel,
            &sample_plan,
            &matrix,
            &ledger,
            &remediation,
        )
        .unwrap();
    let bundle = PublicVerificationBundle::new(
        "bundle-1",
        &lifecycle,
        &succession,
        &renewal,
        BTreeMap::from([("schema".into(), hex('e'))]),
        BTreeMap::from([("audit".into(), hex('f'))]),
        false,
    )
    .unwrap();
    let epoch = TrustEpoch::new(
        "epoch-1",
        &bundle,
        1_000,
        2_000,
        ["sha256".to_string()].into_iter().collect(),
        0,
    )
    .unwrap();
    let result = hex('1');
    let quorum = PublicVerificationQuorum::new(
        "quorum-1",
        &bundle,
        &epoch,
        vec![
            PublicVerifierReceipt::new(
                "public-verifier-1",
                hex('2'),
                hex('5'),
                &bundle,
                &epoch,
                &result,
                true,
            )
            .unwrap(),
            PublicVerifierReceipt::new(
                "public-verifier-2",
                hex('3'),
                hex('6'),
                &bundle,
                &epoch,
                &result,
                true,
            )
            .unwrap(),
            PublicVerifierReceipt::new(
                "public-verifier-3",
                hex('4'),
                hex('7'),
                &bundle,
                &epoch,
                &result,
                true,
            )
            .unwrap(),
        ],
    )
    .unwrap();
    let sunset_plan = SunsetPlan::new(
        "sunset-plan-1",
        &succession,
        &renewal,
        &bundle,
        &quorum,
        hex('8'),
    )
    .unwrap();
    let mut sunset_authority = SunsetAuthority::new("sunset-authority", hex('9')).unwrap();
    let sunset = sunset_authority
        .certify(
            &sunset_plan,
            canonical_sunset_steps()
                .into_iter()
                .enumerate()
                .map(|(index, step)| {
                    (
                        step,
                        hex(char::from_digit((index as u32 % 9) + 1, 16).unwrap()),
                    )
                })
                .collect(),
            0,
            0,
            0,
            0,
            0,
        )
        .unwrap();
    FullFixture {
        lifecycle,
        identity,
        envelope,
        transfer,
        cutover_plan,
        cutover_receipt,
        succession,
        panel,
        sample_plan,
        matrix,
        ledger,
        remediation,
        renewal,
        bundle,
        epoch,
        quorum,
        sunset_plan,
        sunset,
    }
}

#[test]
fn full_p16_p18_closure_reaches_milestone_119() {
    let fixture = full_fixture();
    let mut authority = ProgramClosureAuthority::new(
        "program-authority",
        &fixture.lifecycle.policy_snapshot_sha256,
        hex('a'),
    )
    .unwrap();
    let certificate = authority
        .certify(
            &fixture.lifecycle,
            &fixture.succession,
            &fixture.renewal,
            &fixture.bundle,
            &fixture.quorum,
            &fixture.sunset_plan,
            &fixture.sunset,
        )
        .unwrap();
    certificate.verify().unwrap();
    assert_eq!(certificate.closed_milestones.len(), 120);
    assert_eq!(*certificate.closed_milestones.last().unwrap(), 119);
}

#[test]
fn cross_policy_successor_is_denied() {
    let lifecycle = lifecycle_fixture();
    let mut identity = SuccessorIdentity::new("successor-1", "lineage-1", &lifecycle).unwrap();
    identity.policy_snapshot_sha256 = hex('f');
    assert!(identity.verify().is_err());
}

#[test]
fn external_io_reviewer_is_denied() {
    assert!(
        ReviewPanelMember::new("reviewer-1", ReviewRole::Safety, hex('1'), hex('2'), true).is_err()
    );
}

#[test]
fn unresolved_finding_blocks_remediation() {
    let fixture = full_fixture();
    let finding = ReviewFinding::new(
        "finding-open",
        fixture
            .sample_plan
            .sample_ids
            .iter()
            .next()
            .unwrap()
            .clone(),
        ReviewFindingSeverity::Medium,
        ReviewFindingState::Open,
        hex('b'),
        None,
    )
    .unwrap();
    let ledger = ReviewFindingLedger::new("ledger-open", &fixture.matrix, vec![finding]).unwrap();
    assert!(RemediationClosure::new("closure-open", &ledger).is_err());
}

#[test]
fn public_quorum_requires_organization_diversity() {
    let fixture = full_fixture();
    let result = hex('1');
    let receipts = vec![
        PublicVerifierReceipt::new(
            "verifier-a",
            hex('2'),
            hex('5'),
            &fixture.bundle,
            &fixture.epoch,
            &result,
            true,
        )
        .unwrap(),
        PublicVerifierReceipt::new(
            "verifier-b",
            hex('2'),
            hex('6'),
            &fixture.bundle,
            &fixture.epoch,
            &result,
            true,
        )
        .unwrap(),
        PublicVerifierReceipt::new(
            "verifier-c",
            hex('2'),
            hex('7'),
            &fixture.bundle,
            &fixture.epoch,
            &result,
            true,
        )
        .unwrap(),
    ];
    assert!(
        PublicVerificationQuorum::new("bad-quorum", &fixture.bundle, &fixture.epoch, receipts)
            .is_err()
    );
}

#[test]
fn live_resources_block_sunset() {
    let fixture = full_fixture();
    let mut authority = SunsetAuthority::new("sunset-authority-2", hex('9')).unwrap();
    let receipts = canonical_sunset_steps()
        .into_iter()
        .enumerate()
        .map(|(index, step)| {
            (
                step,
                hex(char::from_digit((index as u32 % 9) + 1, 16).unwrap()),
            )
        })
        .collect();
    assert!(authority
        .certify(&fixture.sunset_plan, receipts, 1, 0, 0, 0, 0)
        .is_err());
}

#[test]
fn audit_tampering_is_detected() {
    let mut audit = PostClosureAuditChain::new(hex('a')).unwrap();
    audit
        .append(PostClosureAuditEvent {
            action: "test".into(),
            subject_id: "subject-1".into(),
            outcome: "ok".into(),
            metadata: BTreeMap::new(),
        })
        .unwrap();
    audit.records_mut()[0].event.outcome = "changed".into();
    assert!(matches!(
        audit.verify(),
        Err(PostClosureError::AuditRecordHashMismatch(0))
    ));
}

#[test]
fn fixture_components_are_individually_valid() {
    let fixture = full_fixture();
    fixture.identity.verify().unwrap();
    fixture.envelope.verify().unwrap();
    fixture.transfer.verify().unwrap();
    fixture.cutover_plan.verify().unwrap();
    fixture.cutover_receipt.verify().unwrap();
    fixture.panel.verify().unwrap();
    fixture.matrix.verify().unwrap();
    fixture.ledger.verify().unwrap();
    fixture.remediation.verify().unwrap();
}
