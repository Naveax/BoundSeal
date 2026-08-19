#[test]
fn recovery_quorum_requires_diverse_organizations_and_implementations() {
    let (_, _, _, archive, retention, redaction, _, _, _) = continuity_chain();
    let recovery =
        RecoveryPlan::canonical("recovery-diversity", &archive, &retention, &redaction, 1000)
            .unwrap();
    let receipts = vec![
        RecoveryRehearsalReceipt::new(
            "receipt-a",
            "engine-a",
            hex('1'),
            hex('2'),
            &recovery,
            hex('3'),
            10,
            true,
        )
        .unwrap(),
        RecoveryRehearsalReceipt::new(
            "receipt-b",
            "engine-b",
            hex('1'),
            hex('4'),
            &recovery,
            hex('3'),
            11,
            true,
        )
        .unwrap(),
    ];
    assert!(matches!(
        RecoveryQuorum::new(&receipts, 2),
        Err(LifecycleError::InvalidContinuity(_))
    ));
}

#[test]
fn independent_verification_requires_three_diverse_verifiers() {
    let (final_assurance, roadmap, maintenance, _, _, _, _, _, continuity) = continuity_chain();
    let plan = EvidenceSamplePlan::new(
        "sample",
        &final_assurance,
        &roadmap,
        &maintenance,
        &continuity,
        hex('1'),
        10,
    )
    .unwrap();
    let verifier_a =
        IndependentVerifierManifest::strict("verifier-a", hex('2'), hex('3'), hex('4')).unwrap();
    let verifier_b =
        IndependentVerifierManifest::strict("verifier-b", hex('2'), hex('5'), hex('6')).unwrap();
    let receipts = vec![
        IndependentVerificationReceipt::new("receipt-a", &verifier_a, &plan, hex('7'), 0, false)
            .unwrap(),
        IndependentVerificationReceipt::new("receipt-b", &verifier_b, &plan, hex('7'), 0, false)
            .unwrap(),
    ];
    assert!(matches!(
        IndependentVerificationQuorum::new(&receipts, 3),
        Err(LifecycleError::InvalidClosure(_))
    ));
}

#[test]
fn tombstone_rejects_live_resources() {
    let (final_assurance, roadmap, maintenance, _, _, _, _, _, continuity) = continuity_chain();
    let plan = DecommissionPlan::canonical(
        "decommission",
        &final_assurance,
        &roadmap,
        &maintenance,
        &continuity,
    )
    .unwrap();
    let step_receipts = BTreeMap::from([
        (DecommissionStep::FreezeIntake, hex('1')),
        (DecommissionStep::RevokeGrants, hex('2')),
        (DecommissionStep::PurgeSecrets, hex('3')),
        (DecommissionStep::ArchiveMetadata, hex('4')),
        (DecommissionStep::VerifyTombstone, hex('5')),
        (DecommissionStep::SealLifecycle, hex('6')),
    ]);
    let mut authority = TombstoneAuthority::new("authority", hex('7')).unwrap();
    assert!(matches!(
        authority.certify(&plan, &continuity, step_receipts, 1, 0, 0, hex('8')),
        Err(LifecycleError::InvalidClosure(_))
    ));
}

#[test]
fn audit_tampering_is_detected() {
    let mut audit = LifecycleAuditChain::new(hex('1')).unwrap();
    audit
        .append(LifecycleAuditEvent {
            action: "test_action".into(),
            subject_id: "test_subject".into(),
            outcome: "accepted".into(),
            metadata: BTreeMap::new(),
        })
        .unwrap();
    audit.records_mut()[0].event.outcome = "changed".into();
    assert!(matches!(
        audit.verify(),
        Err(LifecycleError::AuditRecordHashMismatch(0))
    ));
}
