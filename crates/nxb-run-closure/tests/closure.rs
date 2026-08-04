use std::collections::{BTreeMap, BTreeSet};

use nxb_knowledge_reporting::ExportManifest;
use nxb_operator_state::OperatorRunStatus;
use nxb_resumable_runner::{RunnerCandidate, RunnerManifest, RunnerStatus};
use nxb_run_closure::*;
use nxb_unified_operator::{
    UnifiedComponentBinding, UnifiedOperatorPlan, UnifiedOperatorPlanParameters,
};
use ring::signature::{Ed25519KeyPair, KeyPair};

fn sha(character: char) -> String {
    character.to_string().repeat(64)
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
        RunnerCandidate::seed(nxb_operator_runtime::RuntimeMethod::Get, "/app", 0),
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

fn artifacts(export: &ExportManifest) -> RunClosureArtifacts {
    RunClosureArtifacts {
        evidence_export_root_sha256: export.root_sha256.clone(),
        report_json_sha256: sha('5'),
        report_markdown_sha256: sha('6'),
        knowledge_audit_tail_sha256: sha('7'),
        session_audit_tail_sha256: sha('8'),
        vault_audit_tail_sha256: sha('9'),
        provider_teardown_receipt_sha256: sha('a'),
        runtime_checkpoint_sha256: sha('b'),
        runner_checkpoint_sha256: sha('c'),
        additional_artifacts: BTreeMap::new(),
    }
}

fn complete_input(export: &ExportManifest, manifest: &RunnerManifest) -> RunClosureInput {
    RunClosureInput {
        snapshot: TerminalRunSnapshot {
            runner_manifest_sha256: manifest.manifest_sha256.clone(),
            runner_checkpoint_sha256: sha('c'),
            runner_status: RunnerStatus::Completed,
            runner_stop_reason: ClosureReason::RuntimeCompleted,
            completed_requests: 2,
            visited_targets: 2,
            pending_targets: 0,
            rejected_candidates: 0,
            recovery_gap_count: 0,
            runtime_checkpoint_sha256: sha('b'),
            runtime_status: OperatorRunStatus::Completed,
            maximum_depth_observed: 1,
            total_response_bytes: 1024,
            evidence_bytes: 2048,
        },
        artifacts: artifacts(export),
        untested_scope_sha256: BTreeSet::new(),
        metadata: BTreeMap::from([("closure_mode".into(), "operator_reviewed".into())]),
        generated_at_epoch_seconds: 1_200,
    }
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

#[test]
fn complete_closure_is_signed_and_verified() {
    let plan = plan();
    let runner_manifest = runner_manifest(&plan);
    let export = export_manifest(&plan);
    let manifest = RunClosureManifest::build(
        &plan,
        &runner_manifest,
        &export,
        complete_input(&export, &runner_manifest),
    )
    .expect("closure manifest");
    assert_eq!(manifest.disposition, ClosureDisposition::Complete);
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
    let export = export_manifest(&plan);
    let mut input = complete_input(&export, &runner_manifest);
    input.snapshot.pending_targets = 1;
    let error = RunClosureManifest::build(&plan, &runner_manifest, &export, input)
        .expect_err("missing untested scope");
    assert!(matches!(error, RunClosureError::MissingUntestedScope));
}

#[test]
fn terminal_state_mismatch_is_rejected() {
    let plan = plan();
    let runner_manifest = runner_manifest(&plan);
    let export = export_manifest(&plan);
    let mut input = complete_input(&export, &runner_manifest);
    input.snapshot.runtime_status = OperatorRunStatus::Aborted;
    let error = RunClosureManifest::build(&plan, &runner_manifest, &export, input)
        .expect_err("terminal mismatch");
    assert!(matches!(error, RunClosureError::TerminalStateMismatch));
}

#[test]
fn secret_like_metadata_is_rejected() {
    let plan = plan();
    let runner_manifest = runner_manifest(&plan);
    let export = export_manifest(&plan);
    let mut input = complete_input(&export, &runner_manifest);
    input
        .metadata
        .insert("note".into(), "authorization: bearer hidden".into());
    let error = RunClosureManifest::build(&plan, &runner_manifest, &export, input)
        .expect_err("secret-like metadata");
    assert!(matches!(error, RunClosureError::UnsafeMetadata));
}

#[test]
fn signature_tamper_is_rejected() {
    let plan = plan();
    let runner_manifest = runner_manifest(&plan);
    let export = export_manifest(&plan);
    let manifest = RunClosureManifest::build(
        &plan,
        &runner_manifest,
        &export,
        complete_input(&export, &runner_manifest),
    )
    .expect("closure manifest");
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
