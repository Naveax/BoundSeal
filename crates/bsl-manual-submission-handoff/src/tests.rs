#[cfg(test)]
mod tests {
    use super::*;
    use bsl_knowledge_reporting::ReportFinding;
    use bsl_live_run_host::{
        LiveRunLaunchBundle, LiveRunTeardownOutcome, LIVE_RUN_LAUNCH_BUNDLE_VERSION,
    };
    use bsl_operator_runtime::{RuntimeCommittedRequest, RuntimeMethod, RuntimeRecovery};
    use bsl_operator_state::{
        OperatorCheckpoint, OperatorCounters, OperatorRunStatus, OperatorStateIdentity,
        RecoveredOperatorState, OPERATOR_CHECKPOINT_VERSION,
    };
    use bsl_passive_analyzers::{Confidence, Severity};
    use bsl_resumable_runner::{
        RunnerCandidate, RunnerCheckpoint, RunnerManifest, RunnerStatus, RunnerStopReason,
        RESUMABLE_RUNNER_VERSION,
    };
    use bsl_run_closure::{
        RunClosureArtifacts, RunClosureCertificate, RunClosureInput, RunClosureManifest,
    };
    use bsl_unified_operator::{
        UnifiedComponentBinding, UnifiedOperatorPlanParameters,
    };
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use serde::Serialize;

    fn sha(character: char) -> String {
        character.to_string().repeat(64)
    }

    fn hash<T: Serialize>(value: &T) -> String {
        lower_hex(&Sha256::digest(
            serde_json::to_vec(value).expect("serialize fixture"),
        ))
    }

    fn key_pair() -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[31_u8; 32]).expect("deterministic key")
    }

    fn other_key_pair() -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[47_u8; 32]).expect("alternate key")
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
            maximum_workspace_bytes: 32 * 1_024 * 1_024,
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
            .add_entry("evidence/finding-001.json", "evidence", sha('5'), 512)
            .expect("entry");
        export
    }

    fn report_document(finding_ids: &[&str]) -> ReportDocument {
        let findings = finding_ids
            .iter()
            .enumerate()
            .map(|(index, finding_id)| {
                serde_json::json!({
                    "finding_id": finding_id,
                    "rule_id": format!("rule-{index:03}"),
                    "title": format!("Validated finding {index}"),
                    "severity": "medium",
                    "confidence": "high",
                    "origin": "https://example.com",
                    "endpoint_sha256": sha(char::from(b'a' + index as u8)),
                    "summary": format!("Safely redacted finding summary {index}"),
                    "evidence_ids": [format!("evidence-{index:03}")]
                })
            })
            .collect::<Vec<_>>();
        serde_json::from_value(serde_json::json!({
            "report_id": "report-handoff-test",
            "program_name": "Example Program",
            "policy_snapshot_sha256": sha('b'),
            "generated_at_epoch_seconds": 1_200,
            "findings": findings,
            "evidence_manifest_sha256": sha('c'),
            "source_audit_tail_hash": sha('d')
        }))
        .expect("report fixture")
    }

    fn report_bundle(document: ReportDocument) -> ReportBundle {
        let json = serde_json::to_string_pretty(&document).expect("canonical report JSON");
        let markdown = "# Safely redacted report\n".to_string();
        ReportBundle {
            document,
            markdown_sha256: hash_bytes(markdown.as_bytes()),
            json_sha256: hash_bytes(json.as_bytes()),
            markdown,
            json,
        }
    }

    fn bound_report(plan: &UnifiedOperatorPlan, export: &ExportManifest) -> ReportBundle {
        let document = ReportDocument {
            report_id: "report-handoff-bound".into(),
            program_name: "Example Program".into(),
            policy_snapshot_sha256: plan.binding.policy_sha256.clone(),
            generated_at_epoch_seconds: 1_200,
            findings: vec![ReportFinding {
                finding_id: "finding-001".into(),
                rule_id: "rule-header-policy".into(),
                title: "Validated security policy issue".into(),
                severity: Severity::Medium,
                confidence: Confidence::High,
                origin: "https://example.com".into(),
                endpoint_sha256: sha('8'),
                summary: "Safely redacted validated issue summary".into(),
                evidence_ids: BTreeSet::from(["evidence-001".into()]),
            }],
            evidence_manifest_sha256: export.root_sha256.clone(),
            source_audit_tail_hash: sha('a'),
        };
        report_bundle(document)
    }

    fn closure_certificate(
        untested_scope_sha256: BTreeSet<String>,
    ) -> (
        UnifiedOperatorPlan,
        RunClosureCertificate,
        ReportBundle,
        ExportManifest,
    ) {
        let plan = plan();
        let runner_manifest = runner_manifest(&plan);
        let (runner, runtime) = terminal_components(&plan, &runner_manifest);
        let launch_bundle = launch_bundle(&plan, &runner_manifest);
        let teardown = LiveRunTeardownOutcome::Completed {
            external_teardown_receipt_sha256: sha('d'),
            runtime_checkpoint_sha256: runtime.state.latest.checkpoint_sha256.clone(),
            runner_checkpoint_sha256: runner.checkpoint_sha256.clone(),
        };
        let export = export_manifest(&plan);
        let report = bound_report(&plan, &export);
        let manifest = RunClosureManifest::build_from_terminal_host(
            &plan,
            &runner_manifest,
            &runner,
            &runtime,
            &launch_bundle,
            &teardown,
            &export,
            RunClosureInput {
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
                metadata: BTreeMap::from([(
                    "closure_mode".into(),
                    "operator_reviewed".into(),
                )]),
                generated_at_epoch_seconds: 1_250,
            },
        )
        .expect("closure");
        let signature = key_pair().sign(&manifest.signing_bytes().expect("closure signing bytes"));
        (
            plan,
            RunClosureCertificate {
                manifest,
                signature_hex: lower_hex(signature.as_ref()),
            },
            report,
            export,
        )
    }

    fn approved_review(acknowledged: BTreeSet<String>) -> ManualReviewAttestation {
        ManualReviewAttestation {
            reviewer_id: "reviewer-001".into(),
            decision: ManualReviewDecision::ApprovedForManualSubmission,
            reviewed_at_epoch_seconds: 1_275,
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
            BTreeMap::from([("handoff_mode".into(), "manual_review".into())]),
            1_300,
        )
    }

    #[test]
    fn canonical_report_bundle_is_accepted() {
        verify_report_bundle(&report_bundle(report_document(&["finding-001"])))
            .expect("canonical report");
    }

    #[test]
    fn report_json_must_use_canonical_pretty_encoding() {
        let document = report_document(&["finding-001"]);
        let mut bundle = report_bundle(document.clone());
        bundle.json = serde_json::to_string(&document).expect("compact JSON");
        bundle.json_sha256 = hash_bytes(bundle.json.as_bytes());
        assert!(matches!(
            verify_report_bundle(&bundle),
            Err(ManualHandoffError::ReportDigestMismatch)
        ));
    }

    #[test]
    fn empty_report_is_not_submission_ready() {
        let bundle = report_bundle(report_document(&[]));
        assert!(matches!(
            verify_report_bundle(&bundle),
            Err(ManualHandoffError::InvalidReportDocument)
        ));
    }

    #[test]
    fn finding_order_and_identity_are_canonical() {
        let reversed = report_bundle(report_document(&["finding-002", "finding-001"]));
        assert!(matches!(
            verify_report_bundle(&reversed),
            Err(ManualHandoffError::NonCanonicalFindingOrder)
        ));

        let duplicate = report_bundle(report_document(&["finding-001", "finding-001"]));
        assert!(matches!(
            verify_report_bundle(&duplicate),
            Err(ManualHandoffError::NonCanonicalFindingOrder)
        ));
    }

    #[test]
    fn credential_like_handoff_metadata_is_rejected() {
        for unsafe_value in [
            "client_secret=hidden",
            "access_token=hidden",
            "refresh_token=hidden",
            "api_key=hidden",
            "authorization: bearer hidden",
            "https://example.com/private",
        ] {
            let metadata = BTreeMap::from([("review_context".into(), unsafe_value.into())]);
            assert!(matches!(
                validate_metadata(&metadata),
                Err(ManualHandoffError::UnsafeMetadata)
            ));
        }
    }

    #[test]
    fn credential_like_report_text_is_rejected() {
        let mut document = report_document(&["finding-001"]);
        document.findings[0].summary = "access_token=hidden".into();
        let bundle = report_bundle(document);
        assert!(matches!(
            verify_report_bundle(&bundle),
            Err(ManualHandoffError::InvalidReportDocument)
        ));
    }

    #[test]
    fn program_handle_remains_identifier_only() {
        validate_program_handle("example-program_01.test").expect("safe program handle");
        for invalid in ["", "example/program", "https://example.com", "program name"] {
            assert!(matches!(
                validate_program_handle(invalid),
                Err(ManualHandoffError::InvalidProgramHandle)
            ));
        }
    }

    #[test]
    fn signature_hex_is_lowercase_and_even_length() {
        assert_eq!(decode_hex("00ff").expect("lowercase hex"), vec![0, 255]);
        for invalid in ["", "0", "00FF", "zz"] {
            assert!(matches!(
                decode_hex(invalid),
                Err(ManualHandoffError::InvalidSignature)
            ));
        }
    }

    #[test]
    fn finding_set_digest_binds_evidence_membership() {
        let original = report_document(&["finding-001"]);
        let mut changed = original.clone();
        changed.findings[0]
            .evidence_ids
            .insert("evidence-additional".into());
        assert_ne!(
            calculate_finding_set_sha256(&original).expect("original digest"),
            calculate_finding_set_sha256(&changed).expect("changed digest")
        );
    }

    #[test]
    fn complete_handoff_is_deterministic_and_signature_verified() {
        let (plan, closure, report, export) = closure_certificate(BTreeSet::new());
        let first = build_handoff(
            &plan,
            &closure,
            &report,
            &export,
            approved_review(BTreeSet::new()),
        )
        .expect("handoff");
        let second = build_handoff(
            &plan,
            &closure,
            &report,
            &export,
            approved_review(BTreeSet::new()),
        )
        .expect("deterministic handoff");
        assert_eq!(first, second);
        assert_eq!(first.finding_count, 1);

        let signature = key_pair().sign(&first.signing_bytes().expect("handoff signing bytes"));
        ManualSubmissionHandoffCertificate {
            manifest: first,
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
    fn hold_review_cannot_create_submission_ready_handoff() {
        let (plan, closure, report, export) = closure_certificate(BTreeSet::new());
        let mut review = approved_review(BTreeSet::new());
        review.decision = ManualReviewDecision::Hold;
        assert!(matches!(
            build_handoff(&plan, &closure, &report, &export, review),
            Err(ManualHandoffError::ReviewNotApproved)
        ));
    }

    #[test]
    fn partial_closure_requires_exact_untested_scope_acknowledgement() {
        let untested = BTreeSet::from([sha('e')]);
        let (plan, closure, report, export) = closure_certificate(untested.clone());
        assert!(matches!(
            build_handoff(
                &plan,
                &closure,
                &report,
                &export,
                approved_review(BTreeSet::new())
            ),
            Err(ManualHandoffError::UntestedScopeMismatch)
        ));
        build_handoff(
            &plan,
            &closure,
            &report,
            &export,
            approved_review(untested),
        )
        .expect("exact partial acknowledgement");
    }

    #[test]
    fn report_tampering_is_rejected_before_handoff() {
        let (plan, closure, mut report, export) = closure_certificate(BTreeSet::new());
        report.markdown.push_str("tampered");
        assert!(matches!(
            build_handoff(
                &plan,
                &closure,
                &report,
                &export,
                approved_review(BTreeSet::new())
            ),
            Err(ManualHandoffError::ReportDigestMismatch)
        ));
    }

    #[test]
    fn handoff_signature_and_plan_key_are_fail_closed() {
        let (plan, closure, report, export) = closure_certificate(BTreeSet::new());
        let manifest = build_handoff(
            &plan,
            &closure,
            &report,
            &export,
            approved_review(BTreeSet::new()),
        )
        .expect("handoff");
        let mut certificate = ManualSubmissionHandoffCertificate {
            manifest,
            signature_hex: "00".repeat(64),
        };
        assert!(matches!(
            certificate.verify(
                &plan,
                &closure,
                &report,
                &export,
                key_pair().public_key().as_ref()
            ),
            Err(ManualHandoffError::InvalidSignature)
        ));

        let valid_signature = key_pair()
            .sign(&certificate.manifest.signing_bytes().expect("signing bytes"));
        certificate.signature_hex = lower_hex(valid_signature.as_ref());
        assert!(matches!(
            certificate.verify(
                &plan,
                &closure,
                &report,
                &export,
                other_key_pair().public_key().as_ref()
            ),
            Err(ManualHandoffError::Closure(
                bsl_run_closure::RunClosureError::PublicKeyMismatch
            ))
        ));
    }
}
