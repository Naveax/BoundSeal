#[test]
fn equal_count_but_wrong_rollout_stage_ids_are_denied() {
    let adapter = adapter_certificate();
    let reproducibility = reproducibility_certificate(&adapter);
    let inventory = inventory();
    let compatibility = compatibility(&hex('b'));
    let gates = gates(&hex('b'));
    let (_, attestation) = artifacts(&inventory, &gates);
    let (plan, rollback, mut receipt) = rollout(&attestation);

    receipt.validated_stage_ids.remove("canary-10");
    receipt.validated_stage_ids.insert("forged-stage".into());
    receipt.receipt_sha256 = hash_serializable(&(
        &receipt.rollout_plan_sha256,
        &receipt.artifact_attestation_sha256,
        &receipt.validated_stage_ids,
        &receipt.rollback_certificate_sha256,
        receipt.final_state,
        &receipt.rollout_audit_tail_hash,
    ))
    .unwrap();
    receipt.verify().unwrap();

    let mut authority =
        PlatformReleaseAuthority::new("platform-authority-stage-test", hex('b'), hex('0'))
            .unwrap();
    assert!(matches!(
        authority.certify(
            &adapter,
            &reproducibility,
            &inventory,
            &compatibility,
            &gates,
            &attestation,
            &plan,
            &rollback,
            &receipt,
        ),
        Err(ReleaseError::CertificationDenied(_))
    ));
}
