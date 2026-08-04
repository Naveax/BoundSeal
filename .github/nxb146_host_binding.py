from pathlib import Path
import re

SOURCE = Path("crates/nxb-run-closure/src/lib.rs")
TESTS = Path("crates/nxb-run-closure/tests/closure.rs")


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"NXB-146 {label} anchor mismatch: {count}")
    return text.replace(old, new, 1)


source = SOURCE.read_text(encoding="utf-8")
source = replace_once(
    source,
    "use nxb_knowledge_reporting::ExportManifest;\n",
    "use nxb_knowledge_reporting::ExportManifest;\nuse nxb_live_run_host::{LiveRunLaunchBundle, LiveRunTeardownOutcome};\n",
    "live-host import",
)
source = source.replace(
    "provider_teardown_receipt_sha256",
    "external_teardown_evidence_sha256",
)

terminal_struct_anchor = '''#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TerminalRunSnapshot {
'''
terminal_struct_replacement = '''#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "outcome")]
pub enum ExternalTeardownEvidence {
    Completed { receipt_sha256: String },
    Failed { failure_sha256: String },
}

impl ExternalTeardownEvidence {
    fn validate(&self) -> Result<(), RunClosureError> {
        validate_sha256(self.digest())
    }

    fn digest(&self) -> &str {
        match self {
            Self::Completed { receipt_sha256 } => receipt_sha256,
            Self::Failed { failure_sha256 } => failure_sha256,
        }
    }

    fn succeeded(&self) -> bool {
        matches!(self, Self::Completed { .. })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TerminalRunSnapshot {
    pub live_run_bundle_sha256: String,
'''
source = replace_once(
    source,
    terminal_struct_anchor,
    terminal_struct_replacement,
    "terminal struct",
)
source = replace_once(
    source,
    "    pub evidence_bytes: u64,\n}\n\nimpl TerminalRunSnapshot {",
    "    pub evidence_bytes: u64,\n    pub external_teardown: ExternalTeardownEvidence,\n}\n\nimpl TerminalRunSnapshot {",
    "terminal teardown field",
)

terminal_impl = r'''impl TerminalRunSnapshot {
    #[allow(clippy::too_many_arguments)]
    pub fn from_components(
        plan: &UnifiedOperatorPlan,
        runner_manifest: &RunnerManifest,
        runner_checkpoint: &RunnerCheckpoint,
        runtime: &RuntimeRecovery,
        launch_bundle: &LiveRunLaunchBundle,
        teardown: &LiveRunTeardownOutcome,
    ) -> Result<Self, RunClosureError> {
        plan.validate()?;
        runner_manifest.validate_binding(plan)?;
        launch_bundle.validate()?;
        if launch_bundle.bundle_sha256 != launch_bundle.calculate_sha256()?
            || launch_bundle.unified_plan_sha256 != plan.plan_sha256
            || launch_bundle.unified_binding_sha256 != plan.binding_sha256
            || launch_bundle.runner_manifest_sha256 != runner_manifest.manifest_sha256
            || launch_bundle.policy_snapshot_sha256 != plan.binding.policy_sha256
        {
            return Err(RunClosureError::ComponentMismatch);
        }
        if runner_checkpoint.version != RESUMABLE_RUNNER_VERSION
            || runner_checkpoint.manifest_sha256 != runner_manifest.manifest_sha256
            || runner_checkpoint.completed_requests != runtime.committed_requests
            || runner_checkpoint.completed_requests
                != runtime.state.latest.counters.requests_completed
            || runtime.unresolved_request.is_some()
            || runtime.continuation_allowed
            || runtime.state.continuation_allowed
        {
            return Err(RunClosureError::ComponentMismatch);
        }
        let mut runner_material = runner_checkpoint.clone();
        runner_material.checkpoint_sha256.clear();
        if runner_checkpoint.checkpoint_sha256 != hash_serializable(&runner_material)? {
            return Err(RunClosureError::ComponentDigestMismatch);
        }
        let runtime_checkpoint = &runtime.state.latest;
        if runtime_checkpoint.version != OPERATOR_CHECKPOINT_VERSION
            || runtime_checkpoint.identity.operator_id != plan.operator_id
            || runtime_checkpoint.identity.plan_sha256 != plan.plan_sha256
            || runtime_checkpoint.identity.binding_sha256 != plan.binding_sha256
        {
            return Err(RunClosureError::ComponentMismatch);
        }
        let mut runtime_material = runtime_checkpoint.clone();
        runtime_material.checkpoint_sha256.clear();
        if runtime_checkpoint.checkpoint_sha256 != hash_serializable(&runtime_material)? {
            return Err(RunClosureError::ComponentDigestMismatch);
        }
        let reason = runner_checkpoint
            .stop_reason
            .ok_or(RunClosureError::MissingStopReason)?;
        let external_teardown = match teardown {
            LiveRunTeardownOutcome::Completed {
                external_teardown_receipt_sha256,
                runtime_checkpoint_sha256,
                runner_checkpoint_sha256,
            } => {
                validate_sha256(external_teardown_receipt_sha256)?;
                if runtime_checkpoint_sha256 != &runtime_checkpoint.checkpoint_sha256
                    || runner_checkpoint_sha256 != &runner_checkpoint.checkpoint_sha256
                    || runner_checkpoint.status != RunnerStatus::Completed
                    || runtime_checkpoint.status != OperatorRunStatus::Completed
                    || reason != RunnerStopReason::RuntimeCompleted
                {
                    return Err(RunClosureError::TeardownOutcomeMismatch);
                }
                ExternalTeardownEvidence::Completed {
                    receipt_sha256: external_teardown_receipt_sha256.clone(),
                }
            }
            LiveRunTeardownOutcome::Aborted {
                reason: failure,
                runtime_checkpoint_sha256,
                runner_checkpoint_sha256,
            } => {
                if failure.is_empty()
                    || failure.len() > 2_048
                    || runtime_checkpoint_sha256 != &runtime_checkpoint.checkpoint_sha256
                    || runner_checkpoint_sha256 != &runner_checkpoint.checkpoint_sha256
                    || runner_checkpoint.status != RunnerStatus::Aborted
                    || runtime_checkpoint.status != OperatorRunStatus::Aborted
                    || reason != RunnerStopReason::RuntimeAborted
                {
                    return Err(RunClosureError::TeardownOutcomeMismatch);
                }
                ExternalTeardownEvidence::Failed {
                    failure_sha256: hash_bytes(failure.as_bytes()),
                }
            }
        };
        let snapshot = Self {
            live_run_bundle_sha256: launch_bundle.bundle_sha256.clone(),
            runner_manifest_sha256: runner_manifest.manifest_sha256.clone(),
            runner_checkpoint_sha256: runner_checkpoint.checkpoint_sha256.clone(),
            runner_status: runner_checkpoint.status,
            runner_stop_reason: ClosureReason::from_runner(reason),
            completed_requests: runner_checkpoint.completed_requests,
            visited_targets: runner_checkpoint.visited_target_sha256.len() as u64,
            pending_targets: runner_checkpoint.pending_queue.len() as u64,
            rejected_candidates: runner_checkpoint.rejected_candidates,
            recovery_gap_count: runner_checkpoint.recovery_gap_count,
            runtime_checkpoint_sha256: runtime_checkpoint.checkpoint_sha256.clone(),
            runtime_status: runtime_checkpoint.status,
            maximum_depth_observed: runtime_checkpoint.counters.maximum_depth_observed,
            total_response_bytes: runtime_checkpoint.counters.total_response_bytes,
            evidence_bytes: runtime_checkpoint.counters.evidence_bytes,
            external_teardown,
        };
        snapshot.validate_binding(plan, runner_manifest, launch_bundle)?;
        Ok(snapshot)
    }

    fn validate_shape(&self, plan: &UnifiedOperatorPlan) -> Result<(), RunClosureError> {
        for value in [
            &self.live_run_bundle_sha256,
            &self.runner_manifest_sha256,
            &self.runner_checkpoint_sha256,
            &self.runtime_checkpoint_sha256,
        ] {
            validate_sha256(value)?;
        }
        self.external_teardown.validate()?;
        if self.completed_requests > plan.binding.maximum_requests
            || self.completed_requests > self.visited_targets
            || self.pending_targets > self.visited_targets
            || self.recovery_gap_count > self.completed_requests
            || self.maximum_depth_observed > plan.binding.maximum_depth
            || self.total_response_bytes > plan.binding.maximum_total_response_bytes
        {
            return Err(RunClosureError::ComponentMismatch);
        }
        match (
            self.runner_status,
            self.runtime_status,
            self.runner_stop_reason,
            self.external_teardown.succeeded(),
        ) {
            (
                RunnerStatus::Completed,
                OperatorRunStatus::Completed,
                ClosureReason::RuntimeCompleted,
                true,
            )
            | (
                RunnerStatus::Aborted,
                OperatorRunStatus::Aborted,
                ClosureReason::RuntimeAborted,
                false,
            ) => {}
            _ => return Err(RunClosureError::TerminalStateMismatch),
        }
        Ok(())
    }

    fn validate_binding(
        &self,
        plan: &UnifiedOperatorPlan,
        runner_manifest: &RunnerManifest,
        launch_bundle: &LiveRunLaunchBundle,
    ) -> Result<(), RunClosureError> {
        self.validate_shape(plan)?;
        if self.runner_manifest_sha256 != runner_manifest.manifest_sha256
            || self.live_run_bundle_sha256 != launch_bundle.bundle_sha256
        {
            return Err(RunClosureError::ComponentMismatch);
        }
        Ok(())
    }
}
'''
source, count = re.subn(
    r"impl TerminalRunSnapshot \{.*?\n\}\n\n(?=#\[derive\(Debug, Clone, Serialize, Deserialize, PartialEq, Eq\)\]\n#\[serde\(deny_unknown_fields\)\]\npub struct RunClosureInput)",
    terminal_impl + "\n",
    source,
    count=1,
    flags=re.S,
)
if count != 1:
    raise SystemExit(f"NXB-146 terminal impl mismatch: {count}")

source = replace_once(
    source,
    '''        runtime: &RuntimeRecovery,
        export_manifest: &ExportManifest,
        input: RunClosureInput,
''',
    '''        runtime: &RuntimeRecovery,
        launch_bundle: &LiveRunLaunchBundle,
        teardown: &LiveRunTeardownOutcome,
        export_manifest: &ExportManifest,
        input: RunClosureInput,
''',
    "build signature",
)
source = replace_once(
    source,
    '''            runner_checkpoint,
            runtime,
        )?;
        input.artifacts.validate()?;
''',
    '''            runner_checkpoint,
            runtime,
            launch_bundle,
            teardown,
        )?;
        input.artifacts.validate()?;
''',
    "build terminal call",
)
source = replace_once(
    source,
    '''            || input.artifacts.runtime_checkpoint_sha256 != terminal.runtime_checkpoint_sha256
            || export_manifest.policy_snapshot_sha256 != plan.binding.policy_sha256
''',
    '''            || input.artifacts.runtime_checkpoint_sha256 != terminal.runtime_checkpoint_sha256
            || input.artifacts.external_teardown_evidence_sha256
                != terminal.external_teardown.digest()
            || export_manifest.policy_snapshot_sha256 != plan.binding.policy_sha256
''',
    "build teardown artifact",
)
source = replace_once(
    source,
    '''            || self.artifacts.runtime_checkpoint_sha256 != self.terminal.runtime_checkpoint_sha256
            || self.reason != self.terminal.runner_stop_reason
''',
    '''            || self.artifacts.runtime_checkpoint_sha256 != self.terminal.runtime_checkpoint_sha256
            || self.artifacts.external_teardown_evidence_sha256
                != self.terminal.external_teardown.digest()
            || self.reason != self.terminal.runner_stop_reason
''',
    "verify teardown artifact",
)
source = replace_once(
    source,
    '''        runtime: &RuntimeRecovery,
        export_manifest: &ExportManifest,
    ) -> Result<(), RunClosureError> {
''',
    '''        runtime: &RuntimeRecovery,
        launch_bundle: &LiveRunLaunchBundle,
        teardown: &LiveRunTeardownOutcome,
        export_manifest: &ExportManifest,
    ) -> Result<(), RunClosureError> {
''',
    "verify components signature",
)
source = replace_once(
    source,
    '''            runner_checkpoint,
            runtime,
        )?;
        if terminal != self.terminal
''',
    '''            runner_checkpoint,
            runtime,
            launch_bundle,
            teardown,
        )?;
        if terminal != self.terminal
''',
    "verify components terminal call",
)
source = replace_once(
    source,
    '''            &self.terminal.runner_manifest_sha256,
            &self.terminal.runner_checkpoint_sha256,
''',
    '''            &self.terminal.live_run_bundle_sha256,
            &self.terminal.runner_manifest_sha256,
            &self.terminal.runner_checkpoint_sha256,
''',
    "shape bundle digest",
)
source = replace_once(
    source,
    '''    #[error("terminal component checkpoint digest mismatch")]
    ComponentDigestMismatch,
''',
    '''    #[error("terminal component checkpoint digest mismatch")]
    ComponentDigestMismatch,
    #[error("NXB-145 teardown outcome does not match terminal components")]
    TeardownOutcomeMismatch,
''',
    "teardown error",
)
source = replace_once(
    source,
    '''    #[error(transparent)]
    Runner(#[from] nxb_resumable_runner::RunnerError),
''',
    '''    #[error(transparent)]
    LiveHost(#[from] nxb_live_run_host::LiveRunHostError),
    #[error(transparent)]
    Runner(#[from] nxb_resumable_runner::RunnerError),
''',
    "live host error",
)
SOURCE.write_text(source, encoding="utf-8")


tests = TESTS.read_text(encoding="utf-8")
tests = replace_once(
    tests,
    "use nxb_knowledge_reporting::ExportManifest;\n",
    "use nxb_knowledge_reporting::ExportManifest;\nuse nxb_live_run_host::{\n    LiveRunLaunchBundle, LiveRunTeardownOutcome, LIVE_RUN_LAUNCH_BUNDLE_VERSION,\n};\n",
    "test live-host import",
)

bundle_fixture = '''
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

fn completed_teardown(
    runner_checkpoint: &RunnerCheckpoint,
    runtime: &RuntimeRecovery,
) -> LiveRunTeardownOutcome {
    LiveRunTeardownOutcome::Completed {
        external_teardown_receipt_sha256: sha('d'),
        runtime_checkpoint_sha256: runtime.state.latest.checkpoint_sha256.clone(),
        runner_checkpoint_sha256: runner_checkpoint.checkpoint_sha256.clone(),
    }
}
'''
tests = replace_once(
    tests,
    "fn export_manifest(plan: &UnifiedOperatorPlan) -> ExportManifest {",
    bundle_fixture + "\nfn export_manifest(plan: &UnifiedOperatorPlan) -> ExportManifest {",
    "bundle fixture",
)
tests = tests.replace(
    "provider_teardown_receipt_sha256",
    "external_teardown_evidence_sha256",
)
tests = replace_once(
    tests,
    '''fn artifacts(
    export: &ExportManifest,
    runner_checkpoint: &RunnerCheckpoint,
    runtime: &RuntimeRecovery,
) -> RunClosureArtifacts {
''',
    '''fn artifacts(
    export: &ExportManifest,
    runner_checkpoint: &RunnerCheckpoint,
    runtime: &RuntimeRecovery,
    teardown_evidence_sha256: String,
) -> RunClosureArtifacts {
''',
    "artifacts signature",
)
tests = replace_once(
    tests,
    "        external_teardown_evidence_sha256: sha('d'),\n",
    "        external_teardown_evidence_sha256: teardown_evidence_sha256,\n",
    "artifact teardown evidence",
)
tests = replace_once(
    tests,
    '''fn complete_input(
    export: &ExportManifest,
    runner_checkpoint: &RunnerCheckpoint,
    runtime: &RuntimeRecovery,
) -> RunClosureInput {
    RunClosureInput {
        artifacts: artifacts(export, runner_checkpoint, runtime),
''',
    '''fn complete_input(
    export: &ExportManifest,
    runner_checkpoint: &RunnerCheckpoint,
    runtime: &RuntimeRecovery,
    teardown_evidence_sha256: String,
) -> RunClosureInput {
    RunClosureInput {
        artifacts: artifacts(
            export,
            runner_checkpoint,
            runtime,
            teardown_evidence_sha256,
        ),
''',
    "complete input",
)
tests = replace_once(
    tests,
    '''    ExportManifest,
    RunClosureManifest,
) {
''',
    '''    LiveRunLaunchBundle,
    LiveRunTeardownOutcome,
    ExportManifest,
    RunClosureManifest,
) {
''',
    "complete tuple",
)
tests = replace_once(
    tests,
    '''    let (runner_checkpoint, runtime) = terminal_components(&plan, &runner_manifest);
    let export = export_manifest(&plan);
    let closure = RunClosureManifest::build(
''',
    '''    let (runner_checkpoint, runtime) = terminal_components(&plan, &runner_manifest);
    let bundle = launch_bundle(&plan, &runner_manifest);
    let teardown = completed_teardown(&runner_checkpoint, &runtime);
    let export = export_manifest(&plan);
    let closure = RunClosureManifest::build(
''',
    "complete build fixtures",
)
tests = replace_once(
    tests,
    '''        &runner_checkpoint,
        &runtime,
        &export,
        complete_input(&export, &runner_checkpoint, &runtime),
''',
    '''        &runner_checkpoint,
        &runtime,
        &bundle,
        &teardown,
        &export,
        complete_input(&export, &runner_checkpoint, &runtime, sha('d')),
''',
    "complete build call",
)
tests = replace_once(
    tests,
    '''        runtime,
        export,
        closure,
''',
    '''        runtime,
        bundle,
        teardown,
        export,
        closure,
''',
    "complete return",
)
tests = replace_once(
    tests,
    '''    let (plan, runner_manifest, runner_checkpoint, runtime, export, manifest) = build_complete();
''',
    '''    let (
        plan,
        runner_manifest,
        runner_checkpoint,
        runtime,
        bundle,
        teardown,
        export,
        manifest,
    ) = build_complete();
''',
    "complete test destructure",
)
tests = replace_once(
    tests,
    '''            &runner_checkpoint,
            &runtime,
            &export,
''',
    '''            &runner_checkpoint,
            &runtime,
            &bundle,
            &teardown,
            &export,
''',
    "verify components call",
)

# Update all remaining direct build calls in adversarial tests.
tests = tests.replace(
    '''        &runner_checkpoint,
        &runtime,
        &export,
        complete_input(&export, &runner_checkpoint, &runtime),
''',
    '''        &runner_checkpoint,
        &runtime,
        &launch_bundle(&plan, &runner_manifest),
        &completed_teardown(&runner_checkpoint, &runtime),
        &export,
        complete_input(&export, &runner_checkpoint, &runtime, sha('d')),
''',
)
tests = tests.replace(
    '''    let mut input = complete_input(&export, &runner_checkpoint, &runtime);
''',
    '''    let mut input = complete_input(&export, &runner_checkpoint, &runtime, sha('d'));
''',
)
# Tuple destructuring changed from six to eight values.
tests = tests.replace(
    "let (plan, _, _, _, _, mut manifest) = build_complete();",
    "let (plan, _, _, _, _, _, _, mut manifest) = build_complete();",
)
tests = tests.replace(
    "let (plan, _, _, _, _, manifest) = build_complete();",
    "let (plan, _, _, _, _, _, _, manifest) = build_complete();",
)

# Add teardown mismatch and aborted-evidence tests.
if "fn teardown_hash_mismatch_is_rejected()" in tests:
    raise SystemExit("NXB-146 teardown tests already exist")
tests += '''

#[test]
fn teardown_hash_mismatch_is_rejected() {
    let plan = plan();
    let runner_manifest = runner_manifest(&plan);
    let (runner_checkpoint, runtime) = terminal_components(&plan, &runner_manifest);
    let bundle = launch_bundle(&plan, &runner_manifest);
    let teardown = LiveRunTeardownOutcome::Completed {
        external_teardown_receipt_sha256: sha('d'),
        runtime_checkpoint_sha256: sha('f'),
        runner_checkpoint_sha256: runner_checkpoint.checkpoint_sha256.clone(),
    };
    let export = export_manifest(&plan);
    let error = RunClosureManifest::build(
        &plan,
        &runner_manifest,
        &runner_checkpoint,
        &runtime,
        &bundle,
        &teardown,
        &export,
        complete_input(&export, &runner_checkpoint, &runtime, sha('d')),
    )
    .expect_err("teardown mismatch");
    assert!(matches!(error, RunClosureError::TeardownOutcomeMismatch));
}

#[test]
fn aborted_teardown_binds_only_failure_digest() {
    let plan = plan();
    let runner_manifest = runner_manifest(&plan);
    let (mut runner_checkpoint, mut runtime) = terminal_components(&plan, &runner_manifest);
    runner_checkpoint.status = RunnerStatus::Aborted;
    runner_checkpoint.stop_reason = Some(RunnerStopReason::RuntimeAborted);
    recompute_runner_checkpoint(&mut runner_checkpoint);
    runtime.state.latest.status = OperatorRunStatus::Aborted;
    runtime.state.latest.stop_reason = Some("external_teardown_failed".into());
    recompute_runtime_checkpoint(&mut runtime);
    let failure = "provider_teardown_failed";
    let failure_sha256 = lower_hex(&Sha256::digest(failure.as_bytes()));
    let teardown = LiveRunTeardownOutcome::Aborted {
        reason: failure.into(),
        runtime_checkpoint_sha256: runtime.state.latest.checkpoint_sha256.clone(),
        runner_checkpoint_sha256: runner_checkpoint.checkpoint_sha256.clone(),
    };
    let bundle = launch_bundle(&plan, &runner_manifest);
    let export = export_manifest(&plan);
    let mut input = complete_input(
        &export,
        &runner_checkpoint,
        &runtime,
        failure_sha256.clone(),
    );
    input.untested_scope_sha256.insert(sha('e'));
    let manifest = RunClosureManifest::build(
        &plan,
        &runner_manifest,
        &runner_checkpoint,
        &runtime,
        &bundle,
        &teardown,
        &export,
        input,
    )
    .expect("aborted closure");
    assert_eq!(manifest.disposition, ClosureDisposition::Aborted);
    assert_eq!(
        manifest.artifacts.external_teardown_evidence_sha256,
        failure_sha256
    );
    let serialized = serde_json::to_string(&manifest).expect("serialize closure");
    assert!(!serialized.contains(failure));
}
'''
TESTS.write_text(tests, encoding="utf-8")
