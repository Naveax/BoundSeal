use std::collections::{BTreeMap, BTreeSet};

use nxb_knowledge_reporting::ExportManifest;
use nxb_live_run_host::{
    LiveRunLaunchBundle, LiveRunTeardownOutcome, LIVE_RUN_LAUNCH_BUNDLE_VERSION,
};
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

fn hash<T: Serialize>(value: &T) -> String {
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
        launch_id: "launch-closure".into(),
        unified_plan_sha256: plan.plan_sha256.clone(),
        unified_binding_sha256: plan.binding_sha256.clone(),
        runner_manifest_sha256: manifest.manifest_sha256.clone(),
        external_vault_plan_sha256: plan.binding.external_vault_plan_sha256.clone(),
        external_vault_bootstrap_receipt_sha256: plan
            .binding
            .external_vault_bootstrap_receipt_sha256
            .clone(),
        session_injection_manifest_sha256: plan
            .binding
            .session_injection_manifest_sha256
            .clone(),
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
        dns_resolver_id: "resolver-closure".into(),
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
        ExportManifest::new("export-closure", &plan.binding.policy_sha256).expect("export");
    export
        .add_entry("reports/report.json", "report", sha('5'), 512)
        .expect("entry");
    export
}

fn input(
    export: &ExportManifest,
    runner: &RunnerCheckpoint,
    runtime: &RuntimeRecovery,
    teardown_sha256: String,
) -> RunClosureInput {
    RunClosureInput {
        artifacts: RunClosureArtifacts {
            evidence_export_root_sha256: export.root_sha256.clone(),
            report_json_sha256: sha('8'),
            report_markdown_sha256: sha('9'),
            knowledge_audit_tail_sha256: sha('a'),
            session_audit_tail_sha256: sha('b'),
            vault_audit_tail_sha256: sha('c'),
            external_teardown_evidence_sha256: teardown_sha256,
            runtime_checkpoint_sha256: runtime.state.latest.checkpoint_sha256.clone(),
            runner_checkpoint_sha256: runner.checkpoint_sha256.clone(),
            additional_artifacts: BTreeMap::new(),
        },
        untested_scope_sha256: BTreeSet::new(),
        metadata: BTreeMap::from([("closure_mode".into(), "operator_reviewed".into())]),
        generated_at_epoch_seconds: 1_200,
    }
}

#[allow(clippy::type_complexity)]
fn complete_fixture() -> (
    UnifiedOperatorPlan,
    RunnerManifest,
    RunnerCheckpoint,
    RuntimeRecovery,
    LiveRunLaunchBundle,
    LiveRunTeardownOutcome,
    ExportManifest,
) {
    let plan = plan();
    let manifest = runner_manifest(&plan);
    let (runner, runtime) = terminal_components(&plan, &manifest);
    let bundle = launch_bundle(&plan, &manifest);
    let teardown = LiveRunTeardownOutcome::Completed {
        external_teardown_receipt_sha256: sha('d'),
        runtime_checkpoint_sha256: runtime.state.latest.checkpoint_sha256.clone(),
        runner_checkpoint_sha256: runner.checkpoint_sha256.clone(),
    };
    let export = export_manifest(&plan);
    (plan, manifest, runner, runtime, bundle, teardown, export)
}

#[test]
fn complete_closure_is_signed_and_component_verified() {
    let (plan, runner_manifest, runner, runtime, bundle, teardown, export) = complete_fixture();
    let manifest = RunClosureManifest::build_from_terminal_host(
        &plan,
        &runner_manifest,
        &runner,
        &runtime,
        &bundle,
        &teardown,
        &export,
        input(&export, &runner, &runtime, sha('d')),
    )
    .expect("closure");
    assert_eq!(manifest.disposition, ClosureDisposition::Complete);
    manifest
        .verify_components(
            &plan,
            &runner_manifest,
            &runner,
            &runtime,
            &bundle,
            &teardown,
            &export,
        )
        .expect("components");
    let signature = key_pair().sign(&manifest.signing_bytes().expect("signing bytes"));
    RunClosureCertificate {
        manifest,
        signature_hex: lower_hex(signature.as_ref()),
    }
    .verify(&plan, key_pair().public_key().as_ref())
    .expect("certificate");
}

#[test]
fn continuation_allowed_runtime_is_rejected() {
    let (plan, runner_manifest, runner, mut runtime, bundle, teardown, export) = complete_fixture();
    runtime.continuation_allowed = true;
    let error = RunClosureManifest::build_from_terminal_host(
        &plan,
        &runner_manifest,
        &runner,
        &runtime,
        &bundle,
        &teardown,
        &export,
        input(&export, &runner, &runtime, sha('d')),
    )
    .expect_err("continuation allowed");
    assert!(matches!(error, RunClosureError::ComponentMismatch));
}

#[test]
fn teardown_checkpoint_mismatch_is_rejected() {
    let (plan, runner_manifest, runner, runtime, bundle, _, export) = complete_fixture();
    let teardown = LiveRunTeardownOutcome::Completed {
        external_teardown_receipt_sha256: sha('d'),
        runtime_checkpoint_sha256: sha('f'),
        runner_checkpoint_sha256: runner.checkpoint_sha256.clone(),
    };
    let error = RunClosureManifest::build_from_terminal_host(
        &plan,
        &runner_manifest,
        &runner,
        &runtime,
        &bundle,
        &teardown,
        &export,
        input(&export, &runner, &runtime, sha('d')),
    )
    .expect_err("teardown mismatch");
    assert!(matches!(error, RunClosureError::TeardownOutcomeMismatch));
}

#[test]
fn raw_aborted_failure_is_not_serialized() {
    let (plan, runner_manifest, mut runner, mut runtime, bundle, _, export) = complete_fixture();
    runner.status = RunnerStatus::Aborted;
    runner.stop_reason = Some(RunnerStopReason::RuntimeAborted);
    runner.checkpoint_sha256.clear();
    runner.checkpoint_sha256 = hash(&runner);
    runtime.state.latest.status = OperatorRunStatus::Aborted;
    runtime.state.latest.stop_reason = Some("external_teardown_failed".into());
    runtime.state.latest.checkpoint_sha256.clear();
    runtime.state.latest.checkpoint_sha256 = hash(&runtime.state.latest);
    let failure = "provider_teardown_failed";
    let failure_sha256 = lower_hex(&Sha256::digest(failure.as_bytes()));
    let teardown = LiveRunTeardownOutcome::Aborted {
        reason: failure.into(),
        runtime_checkpoint_sha256: runtime.state.latest.checkpoint_sha256.clone(),
        runner_checkpoint_sha256: runner.checkpoint_sha256.clone(),
    };
    let mut closure_input = input(&export, &runner, &runtime, failure_sha256.clone());
    closure_input.untested_scope_sha256.insert(sha('e'));
    let manifest = RunClosureManifest::build_from_terminal_host(
        &plan,
        &runner_manifest,
        &runner,
        &runtime,
        &bundle,
        &teardown,
        &export,
        closure_input,
    )
    .expect("aborted closure");
    assert_eq!(manifest.disposition, ClosureDisposition::Aborted);
    assert_eq!(
        manifest.artifacts.external_teardown_evidence_sha256,
        failure_sha256
    );
    assert!(!serde_json::to_string(&manifest)
        .expect("serialize")
        .contains(failure));
}

#[test]
fn secret_like_metadata_is_rejected() {
    let (plan, runner_manifest, runner, runtime, bundle, teardown, export) = complete_fixture();
    let mut closure_input = input(&export, &runner, &runtime, sha('d'));
    closure_input
        .metadata
        .insert("note".into(), "authorization: bearer hidden".into());
    let error = RunClosureManifest::build_from_terminal_host(
        &plan,
        &runner_manifest,
        &runner,
        &runtime,
        &bundle,
        &teardown,
        &export,
        closure_input,
    )
    .expect_err("secret metadata");
    assert!(matches!(error, RunClosureError::UnsafeMetadata));
}
