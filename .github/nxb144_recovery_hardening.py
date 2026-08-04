from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
path = ROOT / "crates/nxb-resumable-runner/src/lib.rs"
text = path.read_text(encoding="utf-8")

seed_anchor = "        self.seed.validate(plan)?;\n        if self.seed.depth != 0"
seed_replacement = (
    "        self.seed.validate(plan)?;\n"
    "        self.seed.validate_plan_scope(self)?;\n"
    "        if self.seed.depth != 0"
)
if text.count(seed_anchor) != 1:
    raise SystemExit("seed scope anchor missing")
text = text.replace(seed_anchor, seed_replacement, 1)

old_match = '''        match previous {
            None => {
                if self.sequence != 0
                    || self.previous_checkpoint_sha256 != zero_sha256()
                    || self.completed_requests != 0
                {
                    return Err(RunnerError::CheckpointChainMismatch);
                }
            }
            Some(previous) => {
                if self.sequence != previous.sequence + 1
                    || self.previous_checkpoint_sha256 != previous.checkpoint_sha256
                    || self.completed_requests < previous.completed_requests
                    || self.rejected_candidates < previous.rejected_candidates
                    || self.recovery_gap_count < previous.recovery_gap_count
                {
                    return Err(RunnerError::CheckpointChainMismatch);
                }
            }
        }
'''
new_match = '''        match previous {
            None => {
                if self.sequence != 0
                    || self.previous_checkpoint_sha256 != zero_sha256()
                    || self.completed_requests != 0
                    || self.pending_queue != vec![manifest.seed.clone()]
                    || self.visited_target_sha256
                        != BTreeSet::from([manifest.seed.target_sha256()])
                    || self.rejected_candidates != 0
                    || self.recovery_gap_count != 0
                    || self.last_runtime_request.is_some()
                    || self.status != RunnerStatus::Running
                    || self.stop_reason.is_some()
                {
                    return Err(RunnerError::CheckpointChainMismatch);
                }
            }
            Some(previous) => {
                if self.sequence != previous.sequence + 1
                    || self.previous_checkpoint_sha256 != previous.checkpoint_sha256
                    || self.completed_requests < previous.completed_requests
                    || self.rejected_candidates < previous.rejected_candidates
                    || self.recovery_gap_count < previous.recovery_gap_count
                    || self.created_at_epoch_seconds < previous.created_at_epoch_seconds
                    || previous.status.is_terminal()
                    || !previous
                        .visited_target_sha256
                        .is_subset(&self.visited_target_sha256)
                {
                    return Err(RunnerError::CheckpointChainMismatch);
                }
                let completed_delta = self.completed_requests - previous.completed_requests;
                if completed_delta > 1
                    || self.recovery_gap_count - previous.recovery_gap_count > 1
                {
                    return Err(RunnerError::CheckpointChainMismatch);
                }
                match completed_delta {
                    0 => {
                        if !matches!(
                            (previous.status, self.status),
                            (RunnerStatus::Running, RunnerStatus::TeardownPending)
                                | (RunnerStatus::TeardownPending, RunnerStatus::Completed)
                                | (RunnerStatus::TeardownPending, RunnerStatus::Aborted)
                        )
                            || self.pending_queue != previous.pending_queue
                            || self.visited_target_sha256 != previous.visited_target_sha256
                            || self.rejected_candidates != previous.rejected_candidates
                            || self.recovery_gap_count != previous.recovery_gap_count
                            || self.last_runtime_request != previous.last_runtime_request
                        {
                            return Err(RunnerError::CheckpointChainMismatch);
                        }
                    }
                    1 => {
                        if previous.status != RunnerStatus::Running
                            || !matches!(
                                self.status,
                                RunnerStatus::Running | RunnerStatus::TeardownPending
                            )
                        {
                            return Err(RunnerError::CheckpointChainMismatch);
                        }
                        let committed = self
                            .last_runtime_request
                            .as_ref()
                            .ok_or(RunnerError::CheckpointChainMismatch)?;
                        let expected = previous
                            .pending_queue
                            .first()
                            .ok_or(RunnerError::CheckpointChainMismatch)?;
                        verify_committed_candidate(
                            committed,
                            expected,
                            previous.completed_requests,
                        )?;
                    }
                    _ => return Err(RunnerError::CheckpointChainMismatch),
                }
            }
        }
'''
if text.count(old_match) != 1:
    raise SystemExit("checkpoint chain block missing")
text = text.replace(old_match, new_match, 1)

queue_anchor = '''        let mut queue_hashes = BTreeSet::new();
        for candidate in &self.pending_queue {
            candidate.validate(plan)?;
            let target_sha256 = candidate.target_sha256();
'''
queue_replacement = '''        for target_sha256 in &self.visited_target_sha256 {
            validate_sha256(target_sha256)?;
        }
        match (self.completed_requests, self.last_runtime_request.as_ref()) {
            (0, None) => {}
            (0, Some(_)) | (_, None) => return Err(RunnerError::CheckpointChainMismatch),
            (completed, Some(committed)) => {
                if committed.request_index.checked_add(1) != Some(completed) {
                    return Err(RunnerError::CheckpointChainMismatch);
                }
                for value in [
                    &committed.request_target_sha256,
                    &committed.execution_receipt_sha256,
                    &committed.checkpoint_sha256,
                ] {
                    validate_sha256(value)?;
                }
                if committed.depth > manifest.maximum_depth
                    || !self
                        .visited_target_sha256
                        .contains(&committed.request_target_sha256)
                {
                    return Err(RunnerError::CheckpointChainMismatch);
                }
            }
        }
        let mut queue_hashes = BTreeSet::new();
        for candidate in &self.pending_queue {
            candidate.validate(plan)?;
            candidate.validate_plan_scope(manifest)?;
            let target_sha256 = candidate.target_sha256();
'''
if text.count(queue_anchor) != 1:
    raise SystemExit("checkpoint queue validation anchor missing")
text = text.replace(queue_anchor, queue_replacement, 1)

commit_anchor = '''            if candidate.depth != executed.depth.saturating_add(1)
                || candidate.parent_target_sha256 != executed.target_sha256()
                || candidate.validate(&self.plan).is_err()
            {
'''
commit_replacement = '''            if candidate.depth != executed.depth.saturating_add(1)
                || candidate.parent_target_sha256 != executed.target_sha256()
                || candidate.validate(&self.plan).is_err()
                || candidate.validate_plan_scope(&self.manifest).is_err()
            {
'''
if text.count(commit_anchor) != 1:
    raise SystemExit("discovered candidate validation anchor missing")
text = text.replace(commit_anchor, commit_replacement, 1)

test_anchor = "    #[test]\n    fn queue_executes_deterministically_and_resumes() {\n"
tests = '''    #[test]
    fn manifest_rejects_noncanonical_seed_path() {
        let plan = plan();
        let error = RunnerManifest::build(
            &plan,
            RunnerCandidate::seed(RuntimeMethod::Get, "/app/%2fadmin", 0),
            8,
            1_100,
        )
        .expect_err("encoded seed path must fail closed");
        assert!(matches!(error, RunnerError::InvalidCheckpointQueue));
    }

    #[test]
    fn checkpoint_chain_rejects_skipped_runtime_commit() {
        let plan = plan();
        let manifest = RunnerManifest::build(
            &plan,
            RunnerCandidate::seed(RuntimeMethod::Get, "/app", 0),
            8,
            1_100,
        )
        .expect("manifest");
        let previous = RunnerCheckpoint::initial(&manifest, 1_100).expect("checkpoint");
        let mut tampered = previous.clone();
        tampered.sequence = 1;
        tampered.previous_checkpoint_sha256 = previous.checkpoint_sha256.clone();
        tampered.completed_requests = 2;
        tampered.created_at_epoch_seconds = 1_101;
        tampered.checkpoint_sha256 = tampered.calculate_sha256().expect("digest");
        assert!(matches!(
            tampered.verify(Some(&previous), &manifest, &plan),
            Err(RunnerError::CheckpointChainMismatch)
        ));
    }

'''
if text.count(test_anchor) != 1:
    raise SystemExit("runner test anchor missing")
text = text.replace(test_anchor, tests + test_anchor, 1)

path.write_text(text, encoding="utf-8", newline="\n")
