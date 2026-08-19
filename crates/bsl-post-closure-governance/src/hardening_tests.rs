#[test]
fn zero_byte_transfer_object_cannot_enter_manifest() {
    let fixture = full_fixture();
    let forged = StateTransferObject {
        object_id: "zero-byte-object".into(),
        metadata_sha256: hex('a'),
        redacted_bytes: 0,
    };
    assert!(StateTransferManifest::new(
        "zero-byte-transfer",
        &fixture.envelope,
        vec![forged],
        hex('b'),
    )
    .is_err());
}

#[test]
fn forged_out_of_window_cutover_receipt_is_denied_by_authority() {
    let fixture = full_fixture();
    let mut forged = fixture.cutover_receipt.clone();
    forged.completed_tick = fixture.cutover_plan.end_tick + 1;
    forged.receipt_sha256 = hash_serializable(&(
        &forged.receipt_id,
        &forged.plan_sha256,
        &forged.step_receipts,
        forged.completed_tick,
        forged.unresolved_object_count,
        forged.rollback_verified,
    ))
    .unwrap();
    forged.verify().unwrap();

    let mut authority = SuccessionAuthority::new(
        "window-hardening-authority",
        &fixture.lifecycle.policy_snapshot_sha256,
        hex('d'),
    )
    .unwrap();
    assert!(authority
        .certify(
            &fixture.lifecycle,
            &fixture.identity,
            &fixture.envelope,
            &fixture.transfer,
            &fixture.cutover_plan,
            &forged,
        )
        .is_err());
}

#[test]
fn forged_assignment_matrix_semantics_are_denied_by_renewal_authority() {
    let fixture = full_fixture();
    let mut matrix = fixture.matrix.clone();
    let evidence_id = matrix.assignments.keys().next().unwrap().clone();
    let assignment = matrix.assignments.get_mut(&evidence_id).unwrap();
    assignment.reviewer_ids = ["unknown-reviewer-a".into(), "unknown-reviewer-b".into()]
        .into_iter()
        .collect();
    assignment.assignment_sha256 =
        hash_serializable(&(&assignment.evidence_id, &assignment.reviewer_ids)).unwrap();
    matrix.matrix_sha256 = hash_serializable(&(
        &matrix.matrix_id,
        &matrix.panel_sha256,
        &matrix.sample_plan_sha256,
        &matrix.assignments,
    ))
    .unwrap();
    matrix.verify().unwrap();

    let mut ledger = fixture.ledger.clone();
    ledger.assignment_matrix_sha256 = matrix.matrix_sha256.clone();
    ledger.ledger_sha256 = hash_serializable(&(
        &ledger.ledger_id,
        &ledger.assignment_matrix_sha256,
        &ledger.findings,
    ))
    .unwrap();
    ledger.verify().unwrap();

    let mut remediation = fixture.remediation.clone();
    remediation.finding_ledger_sha256 = ledger.ledger_sha256.clone();
    remediation.closure_sha256 = hash_serializable(&(
        &remediation.closure_id,
        &remediation.finding_ledger_sha256,
        &remediation.terminal_finding_ids,
        remediation.open_finding_count,
        remediation.critical_unremediated_count,
    ))
    .unwrap();
    remediation.verify().unwrap();

    let mut authority = RenewalAuthority::new(
        "matrix-hardening-authority",
        &fixture.lifecycle.policy_snapshot_sha256,
        hex('e'),
    )
    .unwrap();
    assert!(authority
        .certify(
            &fixture.succession,
            &fixture.panel,
            &fixture.sample_plan,
            &matrix,
            &ledger,
            &remediation,
        )
        .is_err());
}

#[test]
fn forged_remediation_terminal_set_is_denied_by_renewal_authority() {
    let fixture = full_fixture();
    let mut remediation = fixture.remediation.clone();
    remediation.terminal_finding_ids.clear();
    remediation.closure_sha256 = hash_serializable(&(
        &remediation.closure_id,
        &remediation.finding_ledger_sha256,
        &remediation.terminal_finding_ids,
        remediation.open_finding_count,
        remediation.critical_unremediated_count,
    ))
    .unwrap();
    remediation.verify().unwrap();

    let mut authority = RenewalAuthority::new(
        "remediation-hardening-authority",
        &fixture.lifecycle.policy_snapshot_sha256,
        hex('f'),
    )
    .unwrap();
    assert!(authority
        .certify(
            &fixture.succession,
            &fixture.panel,
            &fixture.sample_plan,
            &fixture.matrix,
            &fixture.ledger,
            &remediation,
        )
        .is_err());
}
