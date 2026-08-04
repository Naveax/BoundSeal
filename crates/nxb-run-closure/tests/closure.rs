use std::collections::{BTreeMap, BTreeSet};

use nxb_knowledge_reporting::ExportManifest;
use nxb_operator_runtime::{RuntimeCommittedRequest, RuntimeMethod, RuntimeRecovery};
use nxb_operator_state::{
    OperatorCheckpoint, OperatorCounters, OperatorRunStatus, OperatorStateIdentity,
    RecoveredOperatorState, OPERATOR_CHECKPOINT_VERSION,
};
use nxb_resumable_runner::{
    RunnerCandidate, RunnerCheckpoint, RunnerManifest, RunnerStatus, RunnerStopReason,
    RESUMABLE_RUNNER_VERSION,
};
use nxb_run_closure::*;
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

fn hash_serializable<T: Serialize>(value: &T) -> String {
    lower_hex(&Sha256::digest(
        serde_json::to_vec(value).expect("serialize fixture"),
    ))
}

fn key_pair() -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[31_u8; 32]).expect("deterministic key")
}

fn plan() -> UnifiedOperatorPlan {
    let key_pair = key_pair();
    UnifiedOperatorPlan::build(UnifiedOperatorPlanParameters {
        operator_id: "closure-test".into(),
        binding: UnifiedComponentBinding {
            discovery_plan_sha256: sha('a'),
            policy_sha256: sha('b'),
            target_origin_sha256: sha('c'),
            discovery_session_id: "discovery-closure".into(),
            authority: "example.com".into(),
            run_id: "run-closure".into(),
            worker_id: "worker-closure".into(),
            account_id: "account-closure".into(),
            tenant_id: "tenant-closure".into(),
            role_id: "role-closure".into(),
            session_injection_manifest_sha256: sha('d'),
            external_vault_plan_sha256: sha('e'),
            external_vault_bootstrap_receipt_sha256: sha('f'),
            external_session_id_sha256: sha('1'),
            provider_id: "provider-closure".into(),
            provider_instance_sha256: sha('2'),
            provider_capability_sha256: sha('3'),
            secret_binding_root_sha256: sha('4'),
            secret_count: 1,
            allowed_path_prefixes: BTreeSet::from(["/app".into()]),
            maximum_requests: 4,
            maximum_depth: 2,
            maximum_response_body_bytes: 1024,
            maximum_total_response_bytes: 4096,
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

fn export_manifest(plan: &UnifiedOperatorPlan) -> ExportManifest {
    let mut manifest = ExportManifest::new("export-closure", &plan.binding.policy_sha256)
        .expect("export manifest");
    manifest
        .add_entry("reports/report.json", "report", sha('5'), 512)
        .expect("entry");
    manifest
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
    let mut runner_checkpoint = RunnerCheckpoint {
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
    runner_checkpoint.checkpoint_sha256 = hash_serializable(&runner_checkpoint);

    let mut operator_checkpoint = OperatorCheckpoint {
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
    operator_checkpoint.checkpoint_sha256 = hash_serializable(&operator_checkpoint);

    let runtime = RuntimeRecovery {
        state: RecoveredOperatorState {
            latest: operator_checkpoint,
            checkpoint_count: 4,
            state_file_bytes: 4_096,
            continuation_allowed: false,
        },
        journal_bytes: 2_048,
        committed_requests: 2,
        last_committed_request: Some(committed),
        unresolved_request: None,
        continuation_allowed: false,
    };
    (runner_checkpoint, runtime)
}

fn recompute_runner_checkpoint(checkpoint: &mut RunnerCheckpoint) {
    checkpoint.checkpoint_sha256.clear();
    checkpoint.checkpoint_sha256 = hash_serializable(checkpoint);
}

fn recompute_runtime_checkpoint(runtime: &mut RuntimeRecovery) {
    runtime.state.latest.checkpoint_sha256.clear();
    runtime.state.latest.checkpoint_sha256 = hash_serializable(&runtime.state.latest);
}

fn artifacts(
    export: &ExportManifest,
    runner_checkpoint: &RunnerCheckpoint,
    runtime: &RuntimeRecovery,
) -> RunClosureArtifacts {
    RunClosureArtifacts {
        evidence_export_root_sha256: export.root_sha256.clone(),
        report_json_sha256: sha('8'),
        report_markdown_sha256: sha('9'),
        knowledge_audit_tail_sha256: sha('a'),
        session_audit_tail_sha256: sha('b'),
        vault_audit_tail_sha256: sha('c'),
        provider_teardown_receipt_sha256: sha('d'),
        runtime_checkpoint_sha256: runtime.state.latest.checkpoint_sha256.clone(),
        runner_checkpoint_sha256: runner_checkpoint.checkpoint_sha256.clone(),
        additional_artifacts: BTreeMap::new(),
    }
}

fn complete_input(
    export: &ExportManifest,
    runner_checkpoint: &RunnerCheckpoint,
    runtime: &RuntimeRecovery,
) -> RunClosureInput {
    RunClosureInput {
        artifacts: artifacts(export, runner_checkpoint, runtime),
        untested_scope_sha256: BTreeSet::new(),
        metadata: BTreeMap::from([("closure_mode".into(), "operator_reviewed".into())]),
        generated_at_epoch_seconds: 1_200,
    }
}

fn build_complete() -> (
    UnifiedOperatorPlan,
    RunnerManifest,
    RunnerCheckpoint,
    RuntimeRecovery,
    ExportManifest,
    RunClosureManifest,
) {
    let plan = plan();
    let runner_manifest = runner_manifest(&plan);
    let (runner_checkpoint, runtime) = terminal_components(&plan, &runner_manifest);
    let export = export_manifest(&plan);
    let closure = RunClosureManifest::build(
        &plan,
        &runner_manifest,
        &runner_checkpoint,
        &runtime,
        &export,
        complete_input(&export, &runner_checkpoint, &runtime),
    )
    .expect("closure manifest");
    (
        plan,
        runner_manifest,
        runner_checkpoint,
        runtime,
        export,
        closure,
    )
}

#[test]
fn complete_closure_is_signed_and_verified_against_components() {
    let (plan, runner_manifest, runner_checkpoint, runtime, export, manifest) = build_complete();
    assert_eq!(manifest.disposition, ClosureDisposition::Complete);
    manifest
        .verify_components(
            &plan,
            &runner_manifest,
            &runner_checkpoint,
            &runtime,
            &export,
        )
        .expect("component verification");
    let signature = key_pair().sign(&manifest.signing_bytes().expect("signing bytes"));
    let certificate = RunClosureCertificate {
        manifest,
        signature_hex: lower_hex(signature.as_ref()),
    };
    certificate
        .verify(&plan, key_pair().public_key().as_ref())
        .expect("certificate");
}

#[test]
fn partial_closure_requires_untested_scope() {
    let plan = plan();
    let runner_manifest = runner_manifest(&plan);
    let (mut runner_checkpoint, runtime) = terminal_components(&plan, &runner_manifest);
    let pending = RunnerCandidate::child(RuntimeMethod::Get, "/app/pending", 1, sha('2'));
    runner_checkpoint
        .visited_target_sha256
        .insert(pending.target_sha256());
    runner_checkpoint.pending_queue.push(pending);
    recompute_runner_checkpoint(&mut runner_checkpoint);
    let export = export_manifest(&plan);
    let error = RunClosureManifest::build(
        &plan,
        &runner_manifest,
        &runner_checkpoint,
        &runtime,
        &export,
        complete_input(&export, &runner_checkpoint, &runtime),
    )
    .expect_err("missing untested scope");
    assert!(matches!(error, RunClosureError::MissingUntestedScope));
}

#[test]
fn terminal_state_mismatch_is_rejected() {
    let plan = plan();
    let runner_manifest = runner_manifest(&plan);
    let (runner_checkpoint, mut runtime) = terminal_components(&plan, &runner_manifest);
    runtime.state.latest.status = OperatorRunStatus::Aborted;
    recompute_runtime_checkpoint(&mut runtime);
    let export = export_manifest(&plan);
    let error = RunClosureManifest::build(
        &plan,
        &runner_manifest,
        &runner_checkpoint,
        &runtime,
        &export,
        complete_input(&export, &runner_checkpoint, &runtime),
    )
    .expect_err("terminal mismatch");
    assert!(matches!(error, RunClosureError::TerminalStateMismatch));
}

#[test]
fn component_checkpoint_digest_tamper_is_rejected() {
    let plan = plan();
    let runner_manifest = runner_manifest(&plan);
    let (mut runner_checkpoint, runtime) = terminal_components(&plan, &runner_manifest);
    runner_checkpoint.checkpoint_sha256 = sha('f');
    let export = export_manifest(&plan);
    let error = RunClosureManifest::build(
        &plan,
        &runner_manifest,
        &runner_checkpoint,
        &runtime,
        &export,
        complete_input(&export, &runner_checkpoint, &runtime),
    )
    .expect_err("runner checkpoint tamper");
    assert!(matches!(error, RunClosureError::ComponentDigestMismatch));
}

#[test]
fn secret_like_metadata_is_rejected() {
    let plan = plan();
    let runner_manifest = runner_manifest(&plan);
    let (runner_checkpoint, runtime) = terminal_components(&plan, &runner_manifest);
    let export = export_manifest(&plan);
    let mut input = complete_input(&export, &runner_checkpoint, &runtime);
    input
        .metadata
        .insert("note".into(), "authorization: bearer hidden".into());
    let error = RunClosureManifest::build(
        &plan,
        &runner_manifest,
        &runner_checkpoint,
        &runtime,
        &export,
        input,
    )
    .expect_err("secret-like metadata");
    assert!(matches!(error, RunClosureError::UnsafeMetadata));
}

#[test]
fn closure_id_tamper_is_rejected() {
    let (plan, _, _, _, _, mut manifest) = build_complete();
    manifest.closure_id = "closure-000000000000000000000000".into();
    let error = manifest.verify(&plan).expect_err("closure id tamper");
    assert!(matches!(error, RunClosureError::ClosureIdMismatch));
}

#[test]
fn signature_tamper_is_rejected() {
    let (plan, _, _, _, _, manifest) = build_complete();
    let signature = key_pair().sign(&manifest.signing_bytes().expect("signing bytes"));
    let mut certificate = RunClosureCertificate {
        manifest,
        signature_hex: lower_hex(signature.as_ref()),
    };
    certificate.signature_hex.replace_range(0..2, "00");
    let error = certificate
        .verify(&plan, key_pair().public_key().as_ref())
        .expect_err("tampered signature");
    assert!(matches!(error, RunClosureError::InvalidSignature));
}
