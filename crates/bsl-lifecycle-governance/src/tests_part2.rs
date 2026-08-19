fn continuity_chain() -> (
    FinalAssuranceCertificate,
    RoadmapClosureCertificate,
    MaintenanceReleaseCertificate,
    ArchiveBundle,
    RetentionPolicy,
    RedactionManifest,
    RecoveryPlan,
    RecoveryQuorum,
    ContinuityCertificate,
) {
    let (final_assurance, roadmap, _, _, _, _, _, maintenance) = maintenance_chain();
    let objects = vec![
        ArchiveObject::new(
            "object-maintenance",
            ArchiveObjectKind::Certificate,
            &maintenance.certificate_sha256,
            1_024,
            true,
        )
        .unwrap(),
        ArchiveObject::new(
            "object-audit",
            ArchiveObjectKind::AuditTail,
            &maintenance.authority_audit_tail_hash,
            128,
            true,
        )
        .unwrap(),
        ArchiveObject::new(
            "object-freeze",
            ArchiveObjectKind::Manifest,
            &final_assurance.freeze_manifest_sha256,
            512,
            true,
        )
        .unwrap(),
    ];
    let archive = ArchiveBundle::new("archive-90", &maintenance, objects).unwrap();
    let retention = RetentionPolicy::new(
        "retention-91",
        &final_assurance.policy_snapshot_sha256,
        30,
        365,
        30,
        false,
    )
    .unwrap();
    let dispositions = archive
        .object_ids
        .iter()
        .map(|object_id| (object_id.clone(), RedactionDisposition::DigestOnly))
        .collect::<BTreeMap<_, _>>();
    let redaction = RedactionManifest::new("redaction-92", &archive, dispositions).unwrap();
    let recovery =
        RecoveryPlan::canonical("recovery-93", &archive, &retention, &redaction, 10_000).unwrap();
    let receipts = vec![
        RecoveryRehearsalReceipt::new(
            "recovery-receipt-a",
            "engine-a",
            hex('2'),
            hex('3'),
            &recovery,
            hex('4'),
            500,
            true,
        )
        .unwrap(),
        RecoveryRehearsalReceipt::new(
            "recovery-receipt-b",
            "engine-b",
            hex('5'),
            hex('6'),
            &recovery,
            hex('4'),
            510,
            true,
        )
        .unwrap(),
    ];
    let quorum = RecoveryQuorum::new(&receipts, 2).unwrap();
    let mut authority = ContinuityAuthority::new(
        "continuity-authority",
        &final_assurance.policy_snapshot_sha256,
        hex('7'),
    )
    .unwrap();
    let continuity = authority
        .certify(
            &maintenance,
            &archive,
            &retention,
            &redaction,
            &recovery,
            &quorum,
        )
        .unwrap();
    authority.audit().verify().unwrap();
    (
        final_assurance,
        roadmap,
        maintenance,
        archive,
        retention,
        redaction,
        recovery,
        quorum,
        continuity,
    )
}
