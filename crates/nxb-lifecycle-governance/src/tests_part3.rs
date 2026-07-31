#[test]
fn full_p13_p15_lifecycle_closure_succeeds() {
    let (final_assurance, roadmap, maintenance, _, _, _, _, _, continuity) = continuity_chain();
    let sample_plan = EvidenceSamplePlan::new(
        "sample-97",
        &final_assurance,
        &roadmap,
        &maintenance,
        &continuity,
        hex('8'),
        128,
    )
    .unwrap();
    let verifiers = [
        IndependentVerifierManifest::strict("verifier-a", hex('9'), hex('a'), hex('b')).unwrap(),
        IndependentVerifierManifest::strict("verifier-b", hex('c'), hex('d'), hex('e')).unwrap(),
        IndependentVerifierManifest::strict("verifier-c", hex('f'), hex('0'), hex('1')).unwrap(),
    ];
    let receipts = verifiers
        .iter()
        .enumerate()
        .map(|(index, verifier)| {
            IndependentVerificationReceipt::new(
                format!("verification-receipt-{index}"),
                verifier,
                &sample_plan,
                hex('2'),
                0,
                false,
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let verification_quorum = IndependentVerificationQuorum::new(&receipts, 3).unwrap();
    let decommission = DecommissionPlan::canonical(
        "decommission-99",
        &final_assurance,
        &roadmap,
        &maintenance,
        &continuity,
    )
    .unwrap();
    let step_receipts = BTreeMap::from([
        (DecommissionStep::FreezeIntake, hex('3')),
        (DecommissionStep::RevokeGrants, hex('4')),
        (DecommissionStep::PurgeSecrets, hex('5')),
        (DecommissionStep::ArchiveMetadata, hex('6')),
        (DecommissionStep::VerifyTombstone, hex('7')),
        (DecommissionStep::SealLifecycle, hex('8')),
    ]);
    let mut tombstone_authority = TombstoneAuthority::new("tombstone-authority", hex('9')).unwrap();
    let tombstone = tombstone_authority
        .certify(&decommission, &continuity, step_receipts, 0, 0, 0, hex('a'))
        .unwrap();
    let mut lifecycle_authority = LifecycleClosureAuthority::new(
        "lifecycle-authority",
        &final_assurance.policy_snapshot_sha256,
        hex('b'),
    )
    .unwrap();
    let closure = lifecycle_authority
        .certify(
            &final_assurance,
            &roadmap,
            &maintenance,
            &continuity,
            &sample_plan,
            &verification_quorum,
            &decommission,
            &tombstone,
        )
        .unwrap();
    closure.verify().unwrap();
    lifecycle_authority.audit().verify().unwrap();
    assert_eq!(closure.closed_milestones.len(), 102);
    assert_eq!(closure.closed_milestones.first(), Some(&0));
    assert_eq!(closure.closed_milestones.last(), Some(&101));
}

#[test]
fn noncanonical_maintenance_steps_are_rejected() {
    let final_assurance = final_assurance();
    let roadmap = RoadmapClosureCertificate::new(&final_assurance, 0, 83).unwrap();
    let identity = MaintenanceIdentity::new("maintenance", &final_assurance, &roadmap).unwrap();
    let proposal = ChangeProposal::new(
        "proposal",
        &identity,
        ChangeClass::Compatibility,
        BTreeMap::from([("component".into(), hex('1'))]),
        hex('2'),
        hex('3'),
        true,
    )
    .unwrap();
    let assessment = ImpactAssessment::new(
        "assessment",
        &proposal,
        BTreeSet::from(["component".into()]),
        BTreeSet::new(),
        ImpactLevel::Moderate,
        false,
    )
    .unwrap();
    let window = MaintenanceWindow::new(
        "window",
        &proposal,
        0,
        10,
        10,
        BTreeSet::from([hex('4'), hex('5')]),
    )
    .unwrap();
    let result = PatchAdmissionPlan::new(
        "plan",
        &identity,
        &proposal,
        &assessment,
        &window,
        vec![MaintenanceStep::SealMaintenance],
    );
    assert!(matches!(result, Err(LifecycleError::InvalidMaintenance(_))));
}

#[test]
fn indefinite_retention_is_rejected() {
    let result = RetentionPolicy::new("retention", hex('1'), 30, 365, 30, true);
    assert!(matches!(result, Err(LifecycleError::InvalidContinuity(_))));
}
