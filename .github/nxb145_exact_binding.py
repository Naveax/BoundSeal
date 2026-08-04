from pathlib import Path
import re

path = Path("crates/nxb-run-closure/src/lib.rs")
text = path.read_text(encoding="utf-8")

text = text.replace(
    "use nxb_operator_state::OperatorRunStatus;",
    "use nxb_operator_state::{OperatorRunStatus, OPERATOR_CHECKPOINT_VERSION};",
)
text = text.replace(
    "use nxb_resumable_runner::{RunnerCheckpoint, RunnerManifest, RunnerStatus, RunnerStopReason};",
    "use nxb_resumable_runner::{\n    RunnerCheckpoint, RunnerManifest, RunnerStatus, RunnerStopReason,\n    RESUMABLE_RUNNER_VERSION,\n};",
)

coverage_anchor = "impl RunCoverageSummary {\n    fn validate(&self) -> Result<(), RunClosureError> {"
coverage_replacement = """impl RunCoverageSummary {
    fn from_snapshot(plan: &UnifiedOperatorPlan, snapshot: &TerminalRunSnapshot) -> Self {
        Self {
            maximum_requests: plan.binding.maximum_requests,
            completed_requests: snapshot.completed_requests,
            visited_targets: snapshot.visited_targets,
            pending_targets: snapshot.pending_targets,
            rejected_candidates: snapshot.rejected_candidates,
            recovery_gap_count: snapshot.recovery_gap_count,
            maximum_depth_observed: snapshot.maximum_depth_observed,
            total_response_bytes: snapshot.total_response_bytes,
            evidence_bytes: snapshot.evidence_bytes,
            request_budget_basis_points: snapshot
                .completed_requests
                .saturating_mul(10_000)
                .checked_div(plan.binding.maximum_requests)
                .unwrap_or(0) as u16,
        }
    }

    fn validate(&self) -> Result<(), RunClosureError> {"""
if text.count(coverage_anchor) != 1:
    raise SystemExit("coverage anchor mismatch")
text = text.replace(coverage_anchor, coverage_replacement)

old_coverage_guard = """        if self.maximum_requests == 0
            || self.completed_requests > self.maximum_requests
            || self.request_budget_basis_points > 10_000
        {"""
new_coverage_guard = """        if self.maximum_requests == 0
            || self.completed_requests > self.maximum_requests
            || self.completed_requests > self.visited_targets
            || self.pending_targets > self.visited_targets
            || self.recovery_gap_count > self.completed_requests
            || self.request_budget_basis_points > 10_000
        {"""
if text.count(old_coverage_guard) != 1:
    raise SystemExit("coverage guard mismatch")
text = text.replace(old_coverage_guard, new_coverage_guard)

terminal_impl = r'''impl TerminalRunSnapshot {
    pub fn from_components(
        plan: &UnifiedOperatorPlan,
        runner_manifest: &RunnerManifest,
        runner_checkpoint: &RunnerCheckpoint,
        runtime: &RuntimeRecovery,
    ) -> Result<Self, RunClosureError> {
        plan.validate()?;
        runner_manifest.validate_binding(plan)?;
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
        let snapshot = Self {
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
        };
        snapshot.validate_binding(plan, runner_manifest)?;
        Ok(snapshot)
    }

    fn validate_shape(&self, plan: &UnifiedOperatorPlan) -> Result<(), RunClosureError> {
        for value in [
            &self.runner_manifest_sha256,
            &self.runner_checkpoint_sha256,
            &self.runtime_checkpoint_sha256,
        ] {
            validate_sha256(value)?;
        }
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
        ) {
            (
                RunnerStatus::Completed,
                OperatorRunStatus::Completed,
                ClosureReason::RuntimeCompleted,
            )
            | (
                RunnerStatus::Aborted,
                OperatorRunStatus::Aborted,
                ClosureReason::RuntimeAborted,
            ) => {}
            _ => return Err(RunClosureError::TerminalStateMismatch),
        }
        Ok(())
    }

    fn validate_binding(
        &self,
        plan: &UnifiedOperatorPlan,
        runner_manifest: &RunnerManifest,
    ) -> Result<(), RunClosureError> {
        self.validate_shape(plan)?;
        if self.runner_manifest_sha256 != runner_manifest.manifest_sha256 {
            return Err(RunClosureError::ComponentMismatch);
        }
        Ok(())
    }
}
'''
text, count = re.subn(
    r"impl TerminalRunSnapshot \{.*?\n\}\n\n(?=#\[derive\(Debug, Clone, Serialize, Deserialize, PartialEq, Eq\)\]\n#\[serde\(deny_unknown_fields\)\]\npub struct RunClosureInput)",
    terminal_impl + "\n",
    text,
    count=1,
    flags=re.S,
)
if count != 1:
    raise SystemExit("terminal impl mismatch")

text = text.replace("    pub snapshot: TerminalRunSnapshot,\n", "")

manifest_field_anchor = "    pub policy_snapshot_sha256: String,\n    pub disposition: ClosureDisposition,"
manifest_field_replacement = "    pub policy_snapshot_sha256: String,\n    pub terminal: TerminalRunSnapshot,\n    pub disposition: ClosureDisposition,"
if text.count(manifest_field_anchor) != 1:
    raise SystemExit("manifest field anchor mismatch")
text = text.replace(manifest_field_anchor, manifest_field_replacement)

manifest_impl = r'''impl RunClosureManifest {
    pub fn build(
        plan: &UnifiedOperatorPlan,
        runner_manifest: &RunnerManifest,
        runner_checkpoint: &RunnerCheckpoint,
        runtime: &RuntimeRecovery,
        export_manifest: &ExportManifest,
        input: RunClosureInput,
    ) -> Result<Self, RunClosureError> {
        plan.validate()?;
        runner_manifest.validate_binding(plan)?;
        export_manifest.verify()?;
        let terminal = TerminalRunSnapshot::from_components(
            plan,
            runner_manifest,
            runner_checkpoint,
            runtime,
        )?;
        input.artifacts.validate()?;
        if input.artifacts.evidence_export_root_sha256 != export_manifest.root_sha256
            || input.artifacts.runner_checkpoint_sha256
                != terminal.runner_checkpoint_sha256
            || input.artifacts.runtime_checkpoint_sha256
                != terminal.runtime_checkpoint_sha256
            || export_manifest.policy_snapshot_sha256 != plan.binding.policy_sha256
            || input.generated_at_epoch_seconds < runner_manifest.created_at_epoch_seconds
        {
            return Err(RunClosureError::ComponentMismatch);
        }
        validate_untrusted_metadata(&input.metadata)?;
        Self::validate_untested_scope(&input.untested_scope_sha256)?;
        let disposition = Self::expected_disposition(&terminal, &input.untested_scope_sha256)?;
        let coverage = RunCoverageSummary::from_snapshot(plan, &terminal);
        coverage.validate()?;
        let mut manifest = Self {
            version: RUN_CLOSURE_VERSION,
            closure_id: String::new(),
            operator_id: plan.operator_id.clone(),
            plan_sha256: plan.plan_sha256.clone(),
            binding_sha256: plan.binding_sha256.clone(),
            policy_snapshot_sha256: plan.binding.policy_sha256.clone(),
            terminal: terminal.clone(),
            disposition,
            reason: terminal.runner_stop_reason,
            coverage,
            artifacts: input.artifacts,
            untested_scope_sha256: input.untested_scope_sha256,
            metadata: input.metadata,
            generated_at_epoch_seconds: input.generated_at_epoch_seconds,
            manifest_sha256: String::new(),
        };
        manifest.closure_id = manifest.calculate_closure_id()?;
        manifest.manifest_sha256 = manifest.calculate_sha256()?;
        manifest.verify(plan)?;
        Ok(manifest)
    }

    pub fn verify(&self, plan: &UnifiedOperatorPlan) -> Result<(), RunClosureError> {
        plan.validate()?;
        if self.version != RUN_CLOSURE_VERSION
            || self.operator_id != plan.operator_id
            || self.plan_sha256 != plan.plan_sha256
            || self.binding_sha256 != plan.binding_sha256
            || self.policy_snapshot_sha256 != plan.binding.policy_sha256
            || self.generated_at_epoch_seconds <= 0
        {
            return Err(RunClosureError::ComponentMismatch);
        }
        self.terminal.validate_shape(plan)?;
        validate_identifier(&self.closure_id)?;
        validate_sha256(&self.manifest_sha256)?;
        self.coverage.validate()?;
        self.artifacts.validate()?;
        validate_untrusted_metadata(&self.metadata)?;
        Self::validate_untested_scope(&self.untested_scope_sha256)?;
        if self.artifacts.runner_checkpoint_sha256
            != self.terminal.runner_checkpoint_sha256
            || self.artifacts.runtime_checkpoint_sha256
                != self.terminal.runtime_checkpoint_sha256
            || self.reason != self.terminal.runner_stop_reason
            || self.coverage != RunCoverageSummary::from_snapshot(plan, &self.terminal)
        {
            return Err(RunClosureError::ComponentMismatch);
        }
        let expected_disposition =
            Self::expected_disposition(&self.terminal, &self.untested_scope_sha256)?;
        if self.disposition != expected_disposition {
            return Err(RunClosureError::DispositionMismatch);
        }
        if self.closure_id != self.calculate_closure_id()? {
            return Err(RunClosureError::ClosureIdMismatch);
        }
        if self.manifest_sha256 != self.calculate_sha256()? {
            return Err(RunClosureError::ManifestDigestMismatch);
        }
        Ok(())
    }

    pub fn verify_components(
        &self,
        plan: &UnifiedOperatorPlan,
        runner_manifest: &RunnerManifest,
        runner_checkpoint: &RunnerCheckpoint,
        runtime: &RuntimeRecovery,
        export_manifest: &ExportManifest,
    ) -> Result<(), RunClosureError> {
        self.verify(plan)?;
        runner_manifest.validate_binding(plan)?;
        export_manifest.verify()?;
        let terminal = TerminalRunSnapshot::from_components(
            plan,
            runner_manifest,
            runner_checkpoint,
            runtime,
        )?;
        if terminal != self.terminal
            || export_manifest.policy_snapshot_sha256 != self.policy_snapshot_sha256
            || export_manifest.root_sha256 != self.artifacts.evidence_export_root_sha256
        {
            return Err(RunClosureError::ComponentMismatch);
        }
        Ok(())
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, RunClosureError> {
        self.verify_shape_only()?;
        serde_json::to_vec(self).map_err(|error| RunClosureError::Serialization(error.to_string()))
    }

    fn verify_shape_only(&self) -> Result<(), RunClosureError> {
        validate_identifier(&self.closure_id)?;
        validate_sha256(&self.manifest_sha256)?;
        for value in [
            &self.terminal.runner_manifest_sha256,
            &self.terminal.runner_checkpoint_sha256,
            &self.terminal.runtime_checkpoint_sha256,
        ] {
            validate_sha256(value)?;
        }
        self.coverage.validate()?;
        self.artifacts.validate()?;
        validate_untrusted_metadata(&self.metadata)?;
        Self::validate_untested_scope(&self.untested_scope_sha256)?;
        if self.closure_id != self.calculate_closure_id()? {
            return Err(RunClosureError::ClosureIdMismatch);
        }
        if self.manifest_sha256 != self.calculate_sha256()? {
            return Err(RunClosureError::ManifestDigestMismatch);
        }
        Ok(())
    }

    fn expected_disposition(
        terminal: &TerminalRunSnapshot,
        untested_scope_sha256: &BTreeSet<String>,
    ) -> Result<ClosureDisposition, RunClosureError> {
        match terminal.runner_status {
            RunnerStatus::Completed
                if terminal.pending_targets == 0 && untested_scope_sha256.is_empty() =>
            {
                Ok(ClosureDisposition::Complete)
            }
            RunnerStatus::Completed if !untested_scope_sha256.is_empty() => {
                Ok(ClosureDisposition::Partial)
            }
            RunnerStatus::Aborted if !untested_scope_sha256.is_empty() => {
                Ok(ClosureDisposition::Aborted)
            }
            RunnerStatus::Completed | RunnerStatus::Aborted => {
                Err(RunClosureError::MissingUntestedScope)
            }
            _ => Err(RunClosureError::NonTerminalState),
        }
    }

    fn validate_untested_scope(values: &BTreeSet<String>) -> Result<(), RunClosureError> {
        if values.len() > MAX_UNTESTED_SCOPE_ENTRIES {
            return Err(RunClosureError::UntestedScopeLimit);
        }
        for digest in values {
            validate_sha256(digest)?;
        }
        Ok(())
    }

    fn calculate_closure_id(&self) -> Result<String, RunClosureError> {
        let mut material = self.clone();
        material.closure_id.clear();
        material.manifest_sha256.clear();
        let digest = hash_serializable(&material)?;
        Ok(format!("closure-{}", &digest[..24]))
    }

    fn calculate_sha256(&self) -> Result<String, RunClosureError> {
        let mut material = self.clone();
        material.manifest_sha256.clear();
        hash_serializable(&material)
    }
}
'''
text, count = re.subn(
    r"impl RunClosureManifest \{.*?\n\}\n\n(?=#\[derive\(Debug, Clone, Serialize, Deserialize, PartialEq, Eq\)\]\n#\[serde\(deny_unknown_fields\)\]\npub struct RunClosureCertificate)",
    manifest_impl + "\n",
    text,
    count=1,
    flags=re.S,
)
if count != 1:
    raise SystemExit("manifest impl mismatch")

error_anchor = """    #[error("closure manifest digest mismatch")]
    ManifestDigestMismatch,
"""
error_replacement = """    #[error("closure manifest digest mismatch")]
    ManifestDigestMismatch,
    #[error("closure identifier does not match canonical manifest content")]
    ClosureIdMismatch,
    #[error("terminal component checkpoint digest mismatch")]
    ComponentDigestMismatch,
"""
if text.count(error_anchor) != 1:
    raise SystemExit("error anchor mismatch")
text = text.replace(error_anchor, error_replacement)

path.write_text(text, encoding="utf-8")
