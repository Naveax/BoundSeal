fn hex(character: char) -> String {
    std::iter::repeat_n(character, 64).collect()
}

fn node(
    node_id: &str,
    kind: CapabilityNodeKind,
    state: Option<FindingState>,
) -> CapabilityNode {
    CapabilityNode::new(
        node_id,
        kind,
        hex(node_id.chars().last().unwrap_or('a')),
        hex('a'),
        state,
        BTreeMap::new(),
    )
    .unwrap()
}

fn linear_workflow() -> WorkflowDefinition {
    let steps = vec![
        WorkflowStep::new(
            "observe",
            WorkflowAction::Observe,
            BTreeSet::new(),
            None,
            1,
            0,
            false,
            None,
        )
        .unwrap(),
        WorkflowStep::new(
            "compare",
            WorkflowAction::CompareDifferential,
            BTreeSet::from(["observe".into()]),
            None,
            0,
            0,
            false,
            None,
        )
        .unwrap(),
        WorkflowStep::new(
            "oracle",
            WorkflowAction::EvaluateOracle,
            BTreeSet::from(["compare".into()]),
            None,
            0,
            0,
            false,
            None,
        )
        .unwrap(),
        WorkflowStep::new(
            "evidence",
            WorkflowAction::StoreEvidence,
            BTreeSet::from(["oracle".into()]),
            None,
            0,
            0,
            false,
            None,
        )
        .unwrap(),
        WorkflowStep::new(
            "report",
            WorkflowAction::BuildReport,
            BTreeSet::from(["evidence".into()]),
            None,
            0,
            0,
            false,
            None,
        )
        .unwrap(),
        WorkflowStep::new(
            "certify",
            WorkflowAction::CertifyRun,
            BTreeSet::from(["report".into()]),
            None,
            0,
            0,
            false,
            None,
        )
        .unwrap(),
    ];
    WorkflowDefinition::new("workflow-1", "run-1", hex('a'), steps).unwrap()
}

fn confirmed_quorum() -> OracleQuorumResult {
    let coordinator = OracleCoordinator::new("coordinator-1", 2, 4).unwrap();
    coordinator
        .evaluate(
            hex('a'),
            &[
                OracleVote {
                    oracle_id: "oracle-1".into(),
                    decision: OracleDecision::Confirmed,
                    evidence_sha256: hex('1'),
                    repeatable_delta_sha256: Some(hex('d')),
                    policy_snapshot_sha256: hex('a'),
                    validation_audit_tail_hash: hex('2'),
                },
                OracleVote {
                    oracle_id: "oracle-2".into(),
                    decision: OracleDecision::Confirmed,
                    evidence_sha256: hex('3'),
                    repeatable_delta_sha256: Some(hex('d')),
                    policy_snapshot_sha256: hex('a'),
                    validation_audit_tail_hash: hex('4'),
                },
            ],
        )
        .unwrap()
}

#[test]
fn risk_chain_uses_only_validated_finding_nodes_and_is_non_executable() {
    let mut graph = CapabilityGraph::new(hex('a'), hex('0')).unwrap();
    graph
        .add_node(node("endpoint-1", CapabilityNodeKind::Endpoint, None))
        .unwrap();
    graph
        .add_node(node(
            "finding-2",
            CapabilityNodeKind::Finding,
            Some(FindingState::Validated),
        ))
        .unwrap();
    graph
        .add_node(node("evidence-3", CapabilityNodeKind::Evidence, None))
        .unwrap();
    graph
        .add_edge(
            CapabilityEdge::new(
                "endpoint-1",
                "finding-2",
                CapabilityEdgeKind::Produces,
                hex('5'),
            )
            .unwrap(),
        )
        .unwrap();
    graph
        .add_edge(
            CapabilityEdge::new(
                "finding-2",
                "evidence-3",
                CapabilityEdgeKind::ValidatedBy,
                hex('6'),
            )
            .unwrap(),
        )
        .unwrap();
    let chain = graph
        .synthesize_risk_chain("endpoint-1", "evidence-3", 4)
        .unwrap();
    assert_eq!(chain.steps.len(), 3);
    assert!(!chain.executable);
    graph.audit().verify().unwrap();
}

#[test]
fn candidate_finding_cannot_enter_risk_chain() {
    let mut graph = CapabilityGraph::new(hex('a'), hex('0')).unwrap();
    graph
        .add_node(node("endpoint-1", CapabilityNodeKind::Endpoint, None))
        .unwrap();
    graph
        .add_node(node(
            "finding-2",
            CapabilityNodeKind::Finding,
            Some(FindingState::Candidate),
        ))
        .unwrap();
    graph
        .add_edge(
            CapabilityEdge::new(
                "endpoint-1",
                "finding-2",
                CapabilityEdgeKind::Produces,
                hex('5'),
            )
            .unwrap(),
        )
        .unwrap();
    assert_eq!(
        graph.synthesize_risk_chain("endpoint-1", "finding-2", 2),
        Err(WorkflowError::InvalidRiskChain)
    );
}

#[test]
fn workflow_leases_are_exact_once_and_complete_in_dag_order() {
    let definition = linear_workflow();
    let mut engine = WorkflowEngine::new(definition, hex('0')).unwrap();
    engine.start().unwrap();
    for index in 0..6 {
        let lease = engine.lease_next("worker-1", index * 10, 100).unwrap().unwrap();
        let receipt = engine.complete(&lease, index * 10 + 1, hex('b')).unwrap();
        assert_eq!(
            engine.complete(&lease, index * 10 + 2, hex('b')),
            Err(WorkflowError::InvalidLease)
        );
        if index < 5 {
            assert_eq!(receipt.workflow_state, WorkflowState::Running);
        }
    }
    assert_eq!(engine.state(), WorkflowState::Completed);
    assert!(engine.lease_next("worker-1", 100, 100).is_err());
    engine.audit().verify().unwrap();
}

#[test]
fn failed_active_step_enters_cleanup_compensation() {
    let steps = vec![
        WorkflowStep::new(
            "mutate",
            WorkflowAction::GenerateInertMutation,
            BTreeSet::new(),
            Some("capability-1".into()),
            1,
            1,
            false,
            Some("cleanup".into()),
        )
        .unwrap(),
        WorkflowStep::new(
            "cleanup",
            WorkflowAction::CleanupOwnedObject,
            BTreeSet::new(),
            Some("capability-1".into()),
            1,
            0,
            false,
            None,
        )
        .unwrap(),
    ];
    let definition = WorkflowDefinition::new("workflow-2", "run-2", hex('a'), steps).unwrap();
    let mut engine = WorkflowEngine::new(definition, hex('0')).unwrap();
    engine.start().unwrap();
    let mutation = engine.lease_next("worker-1", 10, 100).unwrap().unwrap();
    engine.fail(&mutation, 11, hex('c')).unwrap();
    assert_eq!(engine.state(), WorkflowState::Cancelling);
    let cleanup = engine.lease_next("worker-1", 20, 100).unwrap().unwrap();
    assert!(cleanup.compensation);
    engine.complete(&cleanup, 21, hex('d')).unwrap();
    assert_eq!(engine.state(), WorkflowState::Failed);
}

#[test]
fn oracle_coordinator_detects_delta_drift() {
    let coordinator = OracleCoordinator::new("coordinator-1", 2, 4).unwrap();
    let result = coordinator
        .evaluate(
            hex('a'),
            &[
                OracleVote {
                    oracle_id: "oracle-1".into(),
                    decision: OracleDecision::Confirmed,
                    evidence_sha256: hex('1'),
                    repeatable_delta_sha256: Some(hex('d')),
                    policy_snapshot_sha256: hex('a'),
                    validation_audit_tail_hash: hex('2'),
                },
                OracleVote {
                    oracle_id: "oracle-2".into(),
                    decision: OracleDecision::Confirmed,
                    evidence_sha256: hex('3'),
                    repeatable_delta_sha256: Some(hex('e')),
                    policy_snapshot_sha256: hex('a'),
                    validation_audit_tail_hash: hex('4'),
                },
            ],
        )
        .unwrap();
    assert_eq!(result.decision, QuorumDecision::Drift);
}

#[test]
fn run_certificate_requires_full_cleanup_audit_and_policy_closure() {
    let definition = linear_workflow();
    let mut authority = RunCertificationAuthority::new("authority-1", hex('0')).unwrap();
    let input = CertificationInput {
        run_id: definition.run_id.clone(),
        policy_snapshot_sha256: definition.policy_snapshot_sha256.clone(),
        workflow_id: definition.workflow_id.clone(),
        workflow_definition_sha256: definition.definition_sha256.clone(),
        workflow_state: WorkflowState::Completed,
        workflow_audit_tail_hash: hex('1'),
        validation_audit_tail_hash: hex('2'),
        knowledge_audit_tail_hash: hex('3'),
        export_manifest_root_sha256: hex('4'),
        quorum: confirmed_quorum(),
        unresolved_cleanup_objects: 0,
        failed_steps: 0,
        all_audits_verified: true,
        policy_drift_detected: false,
    };
    let certificate = authority.certify(input.clone()).unwrap();
    assert!(certificate.safe_boundary.contains("inert_mutations"));
    let mut unsafe_input = input;
    unsafe_input.unresolved_cleanup_objects = 1;
    assert!(matches!(
        authority.certify(unsafe_input),
        Err(WorkflowError::CertificationDenied(_))
    ));
    authority.audit().verify().unwrap();
}

#[test]
fn workflow_audit_tampering_is_detected() {
    let mut chain = WorkflowAuditChain::new(hex('0')).unwrap();
    chain
        .append(WorkflowAuditEvent {
            action: "test".into(),
            subject_id: "subject-1".into(),
            outcome: "ok".into(),
            metadata: BTreeMap::new(),
        })
        .unwrap();
    chain.records_mut()[0].event.outcome = "modified".into();
    assert_eq!(
        chain.verify(),
        Err(WorkflowError::AuditRecordHashMismatch { record_index: 0 })
    );
}
