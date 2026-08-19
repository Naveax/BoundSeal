fn hex(character: char) -> String {
    std::iter::repeat_n(character, 64).collect()
}

fn final_assurance() -> FinalAssuranceCertificate {
    let certificate_id = "final-assurance-test".to_string();
    let policy_snapshot_sha256 = hex('1');
    let platform_release_certificate_sha256 = hex('2');
    let integration_certificate_sha256 = hex('3');
    let operator_control_certificate_sha256 = hex('4');
    let coverage_matrix_sha256 = hex('5');
    let freeze_manifest_sha256 = hex('6');
    let mandatory_requirement_count = 6;
    let authority_audit_tail_hash = hex('7');
    let certificate_sha256 = hash_serializable(&(
        &certificate_id,
        &policy_snapshot_sha256,
        &platform_release_certificate_sha256,
        &integration_certificate_sha256,
        &operator_control_certificate_sha256,
        &coverage_matrix_sha256,
        &freeze_manifest_sha256,
        mandatory_requirement_count,
        &authority_audit_tail_hash,
    ))
    .unwrap();
    FinalAssuranceCertificate {
        certificate_id,
        policy_snapshot_sha256,
        platform_release_certificate_sha256,
        integration_certificate_sha256,
        operator_control_certificate_sha256,
        coverage_matrix_sha256,
        freeze_manifest_sha256,
        mandatory_requirement_count,
        authority_audit_tail_hash,
        certificate_sha256,
    }
}

fn maintenance_chain() -> (
    FinalAssuranceCertificate,
    RoadmapClosureCertificate,
    MaintenanceIdentity,
    ChangeProposal,
    ImpactAssessment,
    MaintenanceWindow,
    PatchAdmissionPlan,
    MaintenanceReleaseCertificate,
) {
    let final_assurance = final_assurance();
    let roadmap = RoadmapClosureCertificate::new(&final_assurance, 0, 83).unwrap();
    let identity = MaintenanceIdentity::new("maintenance-84", &final_assurance, &roadmap).unwrap();
    let proposal = ChangeProposal::new(
        "proposal-85",
        &identity,
        ChangeClass::SecurityPatch,
        BTreeMap::from([
            ("bsl-platform-assurance".into(), hex('8')),
            ("bsl-release-governance".into(), hex('9')),
        ]),
        hex('a'),
        hex('b'),
        true,
    )
    .unwrap();
    let assessment = ImpactAssessment::new(
        "assessment-86",
        &proposal,
        BTreeSet::from(["bsl-platform-assurance".into()]),
        BTreeSet::from([
            "hard-safety".into(),
            "identity-binding".into(),
            "audit-integrity".into(),
        ]),
        ImpactLevel::High,
        true,
    )
    .unwrap();
    let window = MaintenanceWindow::new(
        "window-87",
        &proposal,
        10,
        1_000,
        100,
        BTreeSet::from([hex('c'), hex('d')]),
    )
    .unwrap();
    let plan =
        PatchAdmissionPlan::canonical("admission-88", &identity, &proposal, &assessment, &window)
            .unwrap();
    let mut authority = MaintenanceReleaseAuthority::new(
        "maintenance-authority",
        &final_assurance.policy_snapshot_sha256,
        hex('e'),
    )
    .unwrap();
    let certificate = authority
        .certify(
            &identity,
            &proposal,
            &assessment,
            &window,
            &plan,
            hex('f'),
            hex('0'),
            hex('1'),
            0,
        )
        .unwrap();
    authority.audit().verify().unwrap();
    (
        final_assurance,
        roadmap,
        identity,
        proposal,
        assessment,
        window,
        plan,
        certificate,
    )
}
