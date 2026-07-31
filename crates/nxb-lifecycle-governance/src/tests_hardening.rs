#[test]
fn maintenance_window_verify_rejects_oversized_organization_set() {
    let (_, _, _, proposal, _, mut window, _, _) = maintenance_chain();
    window.approver_organization_roots = (0..17)
        .map(|index| hash_bytes(format!("maintenance-org-{index}").as_bytes()))
        .collect();
    window.window_sha256 = hash_serializable(&(
        &window.window_id,
        &proposal.proposal_sha256,
        window.start_tick,
        window.end_tick,
        window.maximum_operations,
        &window.approver_organization_roots,
    ))
    .unwrap();
    assert!(matches!(
        window.verify(),
        Err(LifecycleError::InvalidMaintenance(_))
    ));
}

#[test]
fn maintenance_certification_rechecks_security_patch_assessment() {
    let (final_assurance, _, identity, proposal, mut assessment, window, _, _) =
        maintenance_chain();
    assessment.safety_critical = false;
    assessment.assessment_sha256 = hash_serializable(&(
        &assessment.assessment_id,
        &assessment.proposal_sha256,
        &assessment.affected_components,
        &assessment.affected_invariants,
        assessment.level,
        assessment.safety_critical,
    ))
    .unwrap();
    let plan = PatchAdmissionPlan::canonical(
        "security-recheck-plan",
        &identity,
        &proposal,
        &assessment,
        &window,
    )
    .unwrap();
    let mut authority = MaintenanceReleaseAuthority::new(
        "security-recheck-authority",
        &final_assurance.policy_snapshot_sha256,
        hex('1'),
    )
    .unwrap();
    assert!(matches!(
        authority.certify(
            &identity,
            &proposal,
            &assessment,
            &window,
            &plan,
            hex('2'),
            hex('3'),
            hex('4'),
            0,
        ),
        Err(LifecycleError::InvalidMaintenance(_))
    ));
}

#[test]
fn archive_verify_rejects_duplicate_object_ids() {
    let (_, _, _, mut archive, _, _, _, _, _) = continuity_chain();
    archive.objects[1] = archive.objects[0].clone();
    archive.object_ids = archive
        .objects
        .iter()
        .map(|object| object.object_id.clone())
        .collect();
    archive.total_bytes = archive.objects.iter().map(|object| object.bytes).sum();
    archive.bundle_sha256 = hash_serializable(&(
        &archive.bundle_id,
        &archive.policy_snapshot_sha256,
        &archive.maintenance_release_certificate_sha256,
        &archive.objects,
        &archive.object_ids,
        archive.total_bytes,
    ))
    .unwrap();
    assert!(matches!(
        archive.verify(),
        Err(LifecycleError::InvalidContinuity(_))
    ));
}

#[test]
fn continuity_rejects_recovery_time_beyond_plan_budget() {
    let (_, _, maintenance, archive, retention, redaction, recovery, mut quorum, _) =
        continuity_chain();
    quorum.maximum_final_virtual_tick = recovery.maximum_virtual_ticks + 1;
    quorum.quorum_sha256 = hash_serializable(&(
        &quorum.recovery_plan_sha256,
        &quorum.archive_bundle_sha256,
        &quorum.result_root_sha256,
        &quorum.engine_ids,
        &quorum.organization_roots,
        &quorum.implementation_roots,
        &quorum.receipt_sha256,
        quorum.maximum_final_virtual_tick,
        quorum.quorum,
    ))
    .unwrap();
    quorum.verify().unwrap();
    let mut authority = ContinuityAuthority::new(
        "recovery-time-authority",
        &maintenance.policy_snapshot_sha256,
        hex('5'),
    )
    .unwrap();
    assert!(matches!(
        authority.certify(
            &maintenance,
            &archive,
            &retention,
            &redaction,
            &recovery,
            &quorum,
        ),
        Err(LifecycleError::InvalidContinuity(_))
    ));
}

#[test]
fn quorum_verification_rejects_mismatched_cardinality() {
    let (_, _, _, _, _, _, _, mut recovery_quorum, _) = continuity_chain();
    recovery_quorum.organization_roots.insert(hex('f'));
    recovery_quorum.quorum_sha256 = hash_serializable(&(
        &recovery_quorum.recovery_plan_sha256,
        &recovery_quorum.archive_bundle_sha256,
        &recovery_quorum.result_root_sha256,
        &recovery_quorum.engine_ids,
        &recovery_quorum.organization_roots,
        &recovery_quorum.implementation_roots,
        &recovery_quorum.receipt_sha256,
        recovery_quorum.maximum_final_virtual_tick,
        recovery_quorum.quorum,
    ))
    .unwrap();
    assert!(matches!(
        recovery_quorum.verify(),
        Err(LifecycleError::InvalidContinuity(_))
    ));

    let (final_assurance, roadmap, maintenance, _, _, _, _, _, continuity) = continuity_chain();
    let plan = EvidenceSamplePlan::new(
        "cardinality-sample",
        &final_assurance,
        &roadmap,
        &maintenance,
        &continuity,
        hex('1'),
        10,
    )
    .unwrap();
    let verifiers = [
        IndependentVerifierManifest::strict("cardinality-a", hex('2'), hex('3'), hex('4'))
            .unwrap(),
        IndependentVerifierManifest::strict("cardinality-b", hex('5'), hex('6'), hex('7'))
            .unwrap(),
        IndependentVerifierManifest::strict("cardinality-c", hex('8'), hex('9'), hex('a'))
            .unwrap(),
    ];
    let receipts = verifiers
        .iter()
        .enumerate()
        .map(|(index, verifier)| {
            IndependentVerificationReceipt::new(
                format!("cardinality-receipt-{index}"),
                verifier,
                &plan,
                hex('b'),
                0,
                false,
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let mut verification_quorum = IndependentVerificationQuorum::new(&receipts, 3).unwrap();
    verification_quorum.organization_roots.insert(hex('c'));
    verification_quorum.quorum_sha256 = hash_serializable(&(
        &verification_quorum.sample_plan_sha256,
        &verification_quorum.result_root_sha256,
        &verification_quorum.verifier_manifest_sha256,
        &verification_quorum.organization_roots,
        &verification_quorum.implementation_roots,
        &verification_quorum.receipt_sha256,
        verification_quorum.quorum,
    ))
    .unwrap();
    assert!(matches!(
        verification_quorum.verify(),
        Err(LifecycleError::InvalidClosure(_))
    ));
}
