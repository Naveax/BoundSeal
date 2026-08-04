use std::collections::{BTreeMap, BTreeSet};

use nxb_knowledge_reporting::{
    ExportManifest, ReportBundle, ReportDocument, ReportFinding,
};
use nxb_live_run_host::{
    LiveRunLaunchBundle, LiveRunTeardownOutcome, LIVE_RUN_LAUNCH_BUNDLE_VERSION,
};
use nxb_manual_submission_handoff::*;
use nxb_operator_runtime::{RuntimeCommittedRequest, RuntimeMethod, RuntimeRecovery};
use nxb_operator_state::{
    OperatorCheckpoint, OperatorCounters, OperatorRunStatus, OperatorStateIdentity,
    RecoveredOperatorState, OPERATOR_CHECKPOINT_VERSION,
};
use nxb_passive_analyzers::{Confidence, Severity};
use nxb_resumable_runner::{
    RunnerCandidate, RunnerCheckpoint, RunnerManifest, RunnerStatus, RunnerStopReason,
    RESUMABLE_RUNNER_VERSION,
};
use nxb_run_closure::{
    RunClosureArtifacts, RunClosureCertificate, RunClosureInput, RunClosureManifest,
};
use nxb_unified_operator::{
    UnifiedComponentBinding, UnifiedOperatorPlan, UnifiedOperatorPlanParameters,
};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::Serialize;
use sha2::{Digest, Sha256};

fn sha(character: char) -> String {
    character.to_string().repeat(64)
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn hash_bytes(bytes: &[u8]) -> String {
    lower_hex(&Sha256::digest(bytes))
}

fn hash<T: Serialize>(value: &T) -> String {
    hash_bytes(&serde_json::to_vec(value).expect("serialize fixture"))
}

fn key_pair() -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[41_u8; 32]).expect("deterministic key")
}

fn plan() -> UnifiedOperatorPlan {
    let key_pair = key_pair();
    UnifiedOperatorPlan::build(UnifiedOperatorPlanParameters {
        operator_id: "handoff-test".into(),
        binding: UnifiedComponentBinding {
            discovery_plan_sha256: sha('a'),
            policy_sha256: sha('b'),
            target_origin_sha256: sha('c'),
            discovery_session_id: "discovery-handoff".into(),
            authority: "example.com".into(),
            run_id: "run-handoff".into(),
            worker_id: "worker-handoff".into(),
            account_id: "account-handoff".into(),
            tenant_id: "tenant-handoff".into(),
            role_id: "role-handoff".into(),
            session_injection_manifest_sha256: sha('d'),
            external_vault_plan_sha256: sha('e'),
            external_vault_bootstrap_receipt_sha256: sha('f'),
            external_session_id_sha256: sha('1'),
            provider_id: "provider-handoff".into(),
            provider_instance_sha256: sha('2'),
            provider_capability_sha256: sha('3'),
            secret_binding_root_sha256: sha('4'),
            secret_count: 1,
            allowed_path_prefixes: BTreeSet::from(["/app".into()]),
            maximum_requests: 4,
            maximum_depth: 2,
            maximum_response_body_bytes: 1_024,
            maximum_total_response_bytes: 4_096,
            minimum_request_interval_milliseconds: 200,
            maximum_concurrency: 1,
            component_expires_at_epoch_seconds: 2_000,
        },
        checkpoint_interval_requests: 1,
        maximum_workspace_bytes: 32 * 1024 * 1024,
        created_at_epoch_seconds: 1_000,
        expires_at_epoch_seconds: 1_900,
        activation_public_key: key_pair.public_key().as_ref().to_vec(),
    })
    .expect("plan")
}

fn runner_manifest(plan: &UnifiedOperatorPlan) -> RunnerManifest {
    RunnerManifest::build(
        plan,
        RunnerCandidate::seed(RuntimeMethod::Get, "/app", 0),
        16,
        1_100,
    )
    .expect("runner manifest")
}

fn terminal_components(
    plan: &UnifiedOperatorPlan,
    manifest: &RunnerManifest,
) -> (RunnerCheckpoint, RuntimeRecovery) {
    let committed = RuntimeCommittedRequest {
        request_index: 1,
        method: RuntimeMethod::Get,
        request_target_sha256: sha('2'),
        depth: 1,
        execution_receipt_sha256: sha('3'),
        checkpoint_sequence: 2,
        checkpoint_sha256: sha('4'),
    };
    let mut runner = RunnerCheckpoint {
        version: RESUMABLE_RUNNER_VERSION,
        sequence: 3,
        previous_checkpoint_sha256: sha('5'),
        manifest_sha256: manifest.manifest_sha256.clone(),
        completed_requests: 2,
        pending_queue: Vec::new(),
        visited_target_sha256: BTreeSet::from([sha('1'), sha('2')]),
        rejected_candidates: 0,
        recovery_gap_count: 0,
        last_runtime_request: Some(committed.clone()),
        status: RunnerStatus::Completed,
        stop_reason: Some(RunnerStopReason::RuntimeCompleted),
        created_at_epoch_seconds: 1_200,
        checkpoint_sha256: String::new(),
    };
    runner.checkpoint_sha256 = hash(&runner);

    let mut operator = OperatorCheckpoint {
        version: OPERATOR_CHECKPOINT_VERSION,
        sequence: 3,
        identity: OperatorStateIdentity {
            operator_id: plan.operator_id.clone(),
            plan_sha256: plan.plan_sha256.clone(),
            binding_sha256: plan.binding_sha256.clone(),
            activation_certificate_sha256: sha('6'),
            activation_expires_at_epoch_seconds: 1_800,
        },
        status: OperatorRunStatus::Completed,
        counters: OperatorCounters {
            requests_completed: 2,
            total_response_bytes: 1_024,
            last_response_body_bytes: 512,
            maximum_depth_observed: 1,
            evidence_bytes: 2_048,
        },
        created_at_epoch_seconds: 1_200,
        stop_reason: Some("teardown_complete".into()),
        previous_checkpoint_sha256: Some(sha('7')),
        checkpoint_sha256: String::new(),
    };
    operator.checkpoint_sha256 = hash(&operator);
    (
        runner,
        RuntimeRecovery {
            state: RecoveredOperatorState {
                latest: operator,
                checkpoint_count: 4,
                state_file_bytes: 4_096,
                continuation_allowed: false,
            },
            journal_bytes: 2_048,
            committed_requests: 2,
            last_committed_request: Some(committed),
            unresolved_request: None,
            continuation_allowed: false,
        },
    )
}

fn launch_bundle(plan: &UnifiedOperatorPlan, manifest: &RunnerManifest) -> LiveRunLaunchBundle {
    let mut bundle = LiveRunLaunchBundle {
        version: LIVE_RUN_LAUNCH_BUNDLE_VERSION,
        launch_id: "launch-handoff".into(),
        unified_plan_sha256: plan.plan_sha256.clone(),
        unified_binding_sha256: plan.binding_sha256.clone(),
        runner_manifest_sha256: manifest.manifest_sha256.clone(),
        external_vault_plan_sha256: plan.binding.external_vault_plan_sha256.clone(),
        external_vault_bootstrap_receipt_sha256: plan
            .binding
            .external_vault_bootstrap_receipt_sha256
            .clone(),
        session_injection_manifest_sha256: plan.binding.session_injection_manifest_sha256.clone(),
        policy_snapshot_sha256: plan.binding.policy_sha256.clone(),
        operator_config_sha256: sha('5'),
        live_adapter_config_sha256: sha('6'),
        discovery_plan_sha256: plan.binding.discovery_plan_sha256.clone(),
        target_origin_sha256: plan.binding.target_origin_sha256.clone(),
        authority: plan.binding.authority.clone(),
        run_id: plan.binding.run_id.clone(),
        worker_id: plan.binding.worker_id.clone(),
        account_id: plan.binding.account_id.clone(),
        tenant_id: plan.binding.tenant_id.clone(),
        role_id: plan.binding.role_id.clone(),
        provider_id: plan.binding.provider_id.clone(),
        provider_instance_sha256: plan.binding.provider_instance_sha256.clone(),
        provider_capability_sha256: plan.binding.provider_capability_sha256.clone(),
        external_session_id_sha256: plan.binding.external_session_id_sha256.clone(),
        secret_binding_root_sha256: plan.binding.secret_binding_root_sha256.clone(),
        secret_count: plan.binding.secret_count,
        dns_resolver_id: "resolver-handoff".into(),
        maximum_dns_addresses: 8,
        maximum_dns_ttl_seconds: 300,
        created_at_epoch_seconds: 1_100,
        expires_at_epoch_seconds: 1_800,
        signer_key_id_sha256: plan.activation_key_id_sha256.clone(),
        bundle_sha256: String::new(),
    };
    bundle.bundle_sha256 = bundle.calculate_sha256().expect("bundle digest");
    bundle.validate().expect("bundle");
    bundle
}

fn export_manifest(plan: &UnifiedOperatorPlan) -> ExportManifest {
    let mut export =
        ExportManifest::new("export-handoff", &plan.binding.policy_sha256).expect("export");
    export
        .add_entry("evidence/validated.json", "evidence", sha('5'), 512)
        .expect("entry");
    export
}

fn report_bundle(
    plan: &UnifiedOperatorPlan,
    export: &ExportManifest,
    summary: &str,
) -> ReportBundle {
    let document = ReportDocument {
        report_id: "report-handoff".into(),
        program_name: "example-program".into(),
        policy_snapshot_sha256: plan.binding.policy_sha256.clone(),
        generated_at_epoch_seconds: 1_200,
        findings: vec![ReportFinding {
            finding_id: "finding-001".into(),
            rule_id: "access-control".into(),
            title: "Validated access-control issue".into(),
            severity: Severity::High,
            confidence: Confidence::High,
            origin: "https://example.com".into(),
            endpoint_sha256: sha('8'),
            summary: summary.into(),
            evidence_ids: BTreeSet::from(["evidence-001".into()]),
        }],
        evidence_manifest_sha256: export.root_sha256.clone(),
        source_audit_tail_hash: sha('a'),
    };
    let json = serde_json::to_string_pretty(&document).expect("report json");
    let markdown = "# Validated finding\n\nOperator-reviewed report.\n".to_string();
    ReportBundle {
        document,
        json_sha256: hash_bytes(json.as_bytes()),
        markdown_sha256: hash_bytes(markdown.as_bytes()),
        json,
        markdown,
    }
}

fn closure_certificate(
    plan: &UnifiedOperatorPlan,
    report: &ReportBundle,
    export: &ExportManifest,
    untested_scope_sha256: BTreeSet<String>,
) -> RunClosureCertificate {
    let manifest = runner_manifest(plan);
    let (runner, runtime) = terminal_components(plan, &manifest);
    let bundle = launch_bundle(plan, &manifest);
    let teardown = LiveRunTeardownOutcome::Completed {
        external_teardown_receipt_sha256: sha('d'),
        runtime_checkpoint_sha256: runtime.state.latest.checkpoint_sha256.clone(),
        runner_checkpoint_sha256: runner.checkpoint_sha256.clone(),
    };
    let input = RunClosureInput {
        artifacts: RunClosureArtifacts {
            evidence_export_root_sha256: export.root_sha256.clone(),
            report_json_sha256: report.json_sha256.clone(),
            report_markdown_sha256: report.markdown_sha256.clone(),
            knowledge_audit_tail_sha256: report.document.source_audit_tail_hash.clone(),
            session_audit_tail_sha256: sha('b'),
            vault_audit_tail_sha256: sha('c'),
            external_teardown_evidence_sha256: sha('d'),
            runtime_checkpoint_sha256: runtime.state.latest.checkpoint_sha256.clone(),
            runner_checkpoint_sha256: runner.checkpoint_sha256.clone(),
            additional_artifacts: BTreeMap::new(),
        },
        untested_scope_sha256,
        metadata: BTreeMap::from([("closure_mode".into(), "operator_reviewed".into())]),
        generated_at_epoch_seconds: 1_200,
    };
    let closure = RunClosureManifest::build_from_terminal_host(
        plan, &manifest, &runner, &runtime, &bundle, &teardown, export, input,
    )
    .expect("closure");
    let signature = key_pair().sign(&closure.signing_bytes().expect("closure signing bytes"));
    RunClosureCertificate {
        manifest: closure,
        signature_hex: lower_hex(signature.as_ref()),
    }
}

fn review(acknowledged: BTreeSet<String>) -> ManualReviewAttestation {
    ManualReviewAttestation {
        reviewer_id: "operator-reviewer".into(),
        decision: ManualReviewDecision::ApprovedForManualSubmission,
        reviewed_at_epoch_seconds: 1_250,
        acknowledged_untested_scope_sha256: acknowledged,
        review_note_sha256: Some(sha('f')),
    }
}

fn build_handoff(
    plan: &UnifiedOperatorPlan,
    closure: &RunClosureCertificate,
    report: &ReportBundle,
    export: &ExportManifest,
    review: ManualReviewAttestation,
) -> Result<ManualSubmissionHandoffManifest, ManualHandoffError> {
    ManualSubmissionHandoffManifest::build(
        plan,
        closure,
        key_pair().public_key().as_ref(),
        report,
        export,
        SubmissionPlatform::HackerOne,
        "example-program",
        review,
        BTreeMap::from([("delivery_mode".into(), "manual".into())]),
        1_300,
    )
}

#[test]
fn approved_complete_handoff_is_signed_and_verified() {
    let plan = plan();
    let export = export_manifest(&plan);
    let report = report_bundle(&plan, &export, "Validated access-control boundary.");
    let closure = closure_certificate(&plan, &report, &export, BTreeSet::new());
    let manifest = build_handoff(&plan, &closure, &report, &export, review(BTreeSet::new()))
        .expect("handoff");
    let signature = key_pair().sign(&manifest.signing_bytes().expect("handoff signing bytes"));
    ManualSubmissionHandoffCertificate {
        manifest,
        signature_hex: lower_hex(signature.as_ref()),
    }
    .verify(
        &plan,
        &closure,
        &report,
        &export,
        key_pair().public_key().as_ref(),
    )
    .expect("handoff certificate");
}

#[test]
fn partial_closure_requires_exact_scope_acknowledgement() {
    let plan = plan();
    let export = export_manifest(&plan);
    let report = report_bundle(&plan, &export, "Validated access-control boundary.");
    let untested = BTreeSet::from([sha('e')]);
    let closure = closure_certificate(&plan, &report, &export, untested.clone());
    let error = build_handoff(&plan, &closure, &report, &export, review(BTreeSet::new()))
        .expect_err("scope acknowledgement");
    assert!(matches!(error, ManualHandoffError::UntestedScopeMismatch));
    build_handoff(&plan, &closure, &report, &export, review(untested))
        .expect("acknowledged partial closure");
}

#[test]
fn held_review_is_not_submission_ready() {
    let plan = plan();
    let export = export_manifest(&plan);
    let report = report_bundle(&plan, &export, "Validated access-control boundary.");
    let closure = closure_certificate(&plan, &report, &export, BTreeSet::new());
    let mut held = review(BTreeSet::new());
    held.decision = ManualReviewDecision::Hold;
    let error = build_handoff(&plan, &closure, &report, &export, held)
        .expect_err("held review");
    assert!(matches!(error, ManualHandoffError::ReviewNotApproved));
}

#[test]
fn report_content_tamper_is_rejected() {
    let plan = plan();
    let export = export_manifest(&plan);
    let mut report = report_bundle(&plan, &export, "Validated access-control boundary.");
    let closure = closure_certificate(&plan, &report, &export, BTreeSet::new());
    report.markdown.push_str("tampered");
    let error = build_handoff(&plan, &closure, &report, &export, review(BTreeSet::new()))
        .expect_err("report tamper");
    assert!(matches!(error, ManualHandoffError::ReportDigestMismatch));
}

#[test]
fn secret_like_report_summary_is_rejected() {
    let plan = plan();
    let export = export_manifest(&plan);
    let report = report_bundle(&plan, &export, "access_token=unredacted");
    let closure = closure_certificate(&plan, &report, &export, BTreeSet::new());
    let error = build_handoff(&plan, &closure, &report, &export, review(BTreeSet::new()))
        .expect_err("secret-like summary");
    assert!(matches!(error, ManualHandoffError::InvalidReportDocument));
}

#[test]
fn closure_and_handoff_signature_tamper_are_rejected() {
    let plan = plan();
    let export = export_manifest(&plan);
    let report = report_bundle(&plan, &export, "Validated access-control boundary.");
    let mut closure = closure_certificate(&plan, &report, &export, BTreeSet::new());
    closure.signature_hex.replace_range(0..2, "00");
    let error = build_handoff(&plan, &closure, &report, &export, review(BTreeSet::new()))
        .expect_err("closure signature tamper");
    assert!(matches!(error, ManualHandoffError::Closure(_)));

    let closure = closure_certificate(&plan, &report, &export, BTreeSet::new());
    let manifest = build_handoff(&plan, &closure, &report, &export, review(BTreeSet::new()))
        .expect("handoff");
    let signature = key_pair().sign(&manifest.signing_bytes().expect("signing bytes"));
    let mut certificate = ManualSubmissionHandoffCertificate {
        manifest,
        signature_hex: lower_hex(signature.as_ref()),
    };
    certificate.signature_hex.replace_range(0..2, "00");
    let error = certificate
        .verify(
            &plan,
            &closure,
            &report,
            &export,
            key_pair().public_key().as_ref(),
        )
        .expect_err("handoff signature tamper");
    assert!(matches!(error, ManualHandoffError::InvalidSignature));
}
