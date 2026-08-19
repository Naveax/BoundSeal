#[test]
fn candidate_finding_cannot_start_a_risk_chain() {
    let mut graph = CapabilityGraph::new(hex('a'), hex('0')).unwrap();
    graph
        .add_node(node(
            "finding-1",
            CapabilityNodeKind::Finding,
            Some(FindingState::Candidate),
        ))
        .unwrap();
    graph
        .add_node(node("evidence-2", CapabilityNodeKind::Evidence, None))
        .unwrap();
    graph
        .add_edge(
            CapabilityEdge::new(
                "finding-1",
                "evidence-2",
                CapabilityEdgeKind::ValidatedBy,
                hex('5'),
            )
            .unwrap(),
        )
        .unwrap();
    assert_eq!(
        graph.synthesize_risk_chain("finding-1", "evidence-2", 2),
        Err(WorkflowError::InvalidRiskChain)
    );
}
