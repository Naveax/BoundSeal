#[test]
fn full_p10_p12_closure_produces_roadmap_certificate() {
    let (release, integration) = integration_fixture();
    let operator = sealed_control(&integration);
    let policy = release.policy_snapshot_sha256.clone();
    let classes = [
        InvariantClass::HardSafety,
        InvariantClass::IdentityBinding,
        InvariantClass::Determinism,
        InvariantClass::AuditIntegrity,
        InvariantClass::OperatorControl,
        InvariantClass::ReleaseClosure,
    ];
    let requirements = classes
        .into_iter()
        .enumerate()
        .map(|(index, class)| {
            AssuranceRequirement::new(
                format!("requirement-{}", index + 1),
                class,
                hex(char::from_digit(index as u32 + 1, 16).unwrap()),
                true,
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let evidence = requirements
        .iter()
        .enumerate()
        .map(|(index, requirement)| {
            let source = match requirement.class {
                InvariantClass::OperatorControl => operator.certificate_sha256.clone(),
                InvariantClass::ReleaseClosure => release.certificate_sha256.clone(),
                _ => integration.certificate_sha256.clone(),
            };
            CoverageEvidence::new(
                format!("evidence-{}", index + 1),
                &requirement.requirement_id,
                source,
                hex(char::from_digit(index as u32 + 7, 16).unwrap()),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let matrix = AssuranceCoverageMatrix::new(&policy, requirements, evidence).unwrap();
    let freeze = SystemFreezeManifest::new(
        "freeze-1",
        &policy,
        &release.certificate_sha256,
        &integration.certificate_sha256,
        &operator.certificate_sha256,
        BTreeMap::from([
            ("workspace".into(), hex('a')),
            ("certificates".into(), hex('b')),
        ]),
        BTreeMap::from([("events".into(), hex('c')), ("reports".into(), hex('d'))]),
    )
    .unwrap();
    let mut authority =
        FinalAssuranceAuthority::new("final-authority-1", &policy, hex('e')).unwrap();
    let final_certificate = authority
        .certify(&release, &integration, &operator, &matrix, &freeze, &[])
        .unwrap();
    final_certificate.verify().unwrap();
    let roadmap = RoadmapClosureCertificate::new(&final_certificate, 0, 83).unwrap();
    roadmap.verify().unwrap();
    assert_eq!(roadmap.closed_milestones.len(), 84);
}
#[test]
fn audit_tampering_is_detected() {
    let mut audit = AssuranceAuditChain::new(hex('0')).unwrap();
    audit
        .append(AssuranceAuditEvent {
            action: "test".into(),
            subject_id: "subject-1".into(),
            outcome: "ok".into(),
            metadata: BTreeMap::new(),
        })
        .unwrap();
    audit.records_mut()[0].event.outcome = "changed".into();
    assert!(matches!(
        audit.verify(),
        Err(AssuranceError::AuditRecordHashMismatch(0))
    ));
}
