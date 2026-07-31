#[test]
fn cross_certificate_policy_mismatch_is_rejected() {
    let adapter = adapter_certificate(&hex('0'));
    let reproducibility = reproducibility_certificate(&hex('1'));
    let release = release_certificate(&hex('0'), &adapter, &reproducibility);
    assert!(matches!(
        CrossCertificateBundle::new(&adapter, &reproducibility, &release),
        Err(AssuranceError::InvalidBinding(_))
    ));
}
#[test]
fn integration_steps_are_exact_and_certified() {
    let (_, integration) = integration_fixture();
    integration.verify().unwrap();
}
#[test]
fn integration_sequence_failure_is_terminal() {
    let policy = hex('0');
    let adapter = adapter_certificate(&policy);
    let reproducibility = reproducibility_certificate(&policy);
    let release = release_certificate(&policy, &adapter, &reproducibility);
    let bundle = CrossCertificateBundle::new(&adapter, &reproducibility, &release).unwrap();
    let identity =
        PlatformIntegrationIdentity::new("integration-2", "run-2", "worker-2", &policy).unwrap();
    let scenario =
        IntegrationScenarioFixture::new("scenario-2", &policy, hex('1'), hex('2')).unwrap();
    let mut harness = IntegrationHarness::new(identity, bundle, scenario, hex('3')).unwrap();
    harness.start().unwrap();
    assert!(matches!(
        harness.execute(IntegrationStep::Finalize, hex('2')),
        Err(AssuranceError::InvalidTransition(_))
    ));
    assert_eq!(harness.state(), IntegrationRunState::Failed);
}
#[test]
fn command_nonce_replay_and_weak_resume_quorum_are_rejected() {
    let (_, integration) = integration_fixture();
    let mut plane = OperatorControlPlane::new(integration.clone(), hex('6')).unwrap();
    let pause = envelope(1, OperatorCommand::Pause, &integration, '1');
    let pause_approval = approval(operator("operator-1", OperatorRole::Operator), &pause);
    plane
        .submit(
            pause.clone(),
            vec![pause_approval],
            pause.issued_at_milliseconds + 2,
        )
        .unwrap();
    let weak_resume = envelope(2, OperatorCommand::Resume, &integration, '2');
    assert!(matches!(
        plane.submit(
            weak_resume.clone(),
            vec![approval(
                operator("supervisor-1", OperatorRole::Supervisor),
                &weak_resume
            )],
            weak_resume.issued_at_milliseconds + 2
        ),
        Err(AssuranceError::ApprovalDenied(_))
    ));
    let replay = OperatorCommandEnvelope::new(
        2,
        OperatorCommand::Resume,
        &integration.certificate_sha256,
        &integration.certificate_id,
        pause.nonce_sha256,
        hex('5'),
        2000,
        100_000,
    )
    .unwrap();
    assert!(matches!(
        plane.submit(
            replay.clone(),
            vec![
                approval(operator("supervisor-1", OperatorRole::Supervisor), &replay),
                approval(operator("safety-1", OperatorRole::SafetyOfficer), &replay)
            ],
            2001
        ),
        Err(AssuranceError::ApprovalDenied(_))
    ));
}
