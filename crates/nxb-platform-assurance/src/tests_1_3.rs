fn envelope(
    sequence: u64,
    command: OperatorCommand,
    integration: &PlatformIntegrationCertificate,
    nonce_character: char,
) -> OperatorCommandEnvelope {
    OperatorCommandEnvelope::new(
        sequence,
        command,
        &integration.certificate_sha256,
        &integration.certificate_id,
        hex(nonce_character),
        hex('5'),
        1000 + sequence,
        100_000 + sequence,
    )
    .unwrap()
}
fn approval(operator: OperatorIdentity, envelope: &OperatorCommandEnvelope) -> OperatorApproval {
    OperatorApproval::new(operator, envelope, envelope.issued_at_milliseconds + 1).unwrap()
}
fn sealed_control(integration: &PlatformIntegrationCertificate) -> OperatorControlCertificate {
    let mut plane = OperatorControlPlane::new(integration.clone(), hex('6')).unwrap();
    let pause = envelope(1, OperatorCommand::Pause, integration, '1');
    plane
        .submit(
            pause.clone(),
            vec![approval(
                operator("operator-1", OperatorRole::Operator),
                &pause,
            )],
            pause.issued_at_milliseconds + 2,
        )
        .unwrap();
    let resume = envelope(2, OperatorCommand::Resume, integration, '2');
    plane
        .submit(
            resume.clone(),
            vec![
                approval(operator("supervisor-1", OperatorRole::Supervisor), &resume),
                approval(operator("safety-1", OperatorRole::SafetyOfficer), &resume),
            ],
            resume.issued_at_milliseconds + 2,
        )
        .unwrap();
    let stop = envelope(3, OperatorCommand::EmergencyStop, integration, '3');
    plane
        .submit(
            stop.clone(),
            vec![approval(
                operator("safety-1", OperatorRole::SafetyOfficer),
                &stop,
            )],
            stop.issued_at_milliseconds + 2,
        )
        .unwrap();
    let acknowledge = envelope(4, OperatorCommand::AcknowledgeIncident, integration, '4');
    plane
        .submit(
            acknowledge.clone(),
            vec![approval(
                operator("supervisor-1", OperatorRole::Supervisor),
                &acknowledge,
            )],
            acknowledge.issued_at_milliseconds + 2,
        )
        .unwrap();
    let seal = envelope(5, OperatorCommand::SealRun, integration, '5');
    plane
        .submit(
            seal.clone(),
            vec![
                approval(operator("supervisor-1", OperatorRole::Supervisor), &seal),
                approval(operator("safety-1", OperatorRole::SafetyOfficer), &seal),
            ],
            seal.issued_at_milliseconds + 2,
        )
        .unwrap();
    assert_eq!(plane.state(), OperatorControlState::Sealed);
    let mut authority = OperatorControlAuthority::new("operator-authority-1", hex('7')).unwrap();
    authority.certify(&plane).unwrap()
}
