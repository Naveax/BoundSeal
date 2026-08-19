fn hex(character: char) -> String {
    std::iter::repeat_n(character, 64).collect()
}

fn validated_finding() -> ValidatedFinding {
    ValidatedFinding {
        finding_id: "validated-1".into(),
        candidate_id: "candidate-1".into(),
        rule_id: "BSL-VALID-001".into(),
        origin: "https://app.example.com:443".into(),
        endpoint_sha256: hex('a'),
        mutation_id: "mutation-1".into(),
        oracle_evidence_sha256: hex('b'),
        repeatable_delta_sha256: hex('c'),
        state: PromotionState::Validated,
        summary: "A repeatable authorization boundary difference was confirmed.".into(),
    }
}

fn validated_envelope() -> FindingEnvelope {
    FindingEnvelope::from_validated(
        &validated_finding(),
        hex('d'),
        "Repeatable authorization boundary difference",
        Severity::High,
        Confidence::High,
        BTreeMap::new(),
    )
    .unwrap()
}

#[test]
fn graph_enforces_policy_snapshot_and_provenance() {
    let policy = hex('d');
    let mut graph = ApplicationKnowledgeGraph::new(policy.clone(), hex('0')).unwrap();
    graph
        .add_node(
            KnowledgeNode::new(
                "origin-1",
                KnowledgeNodeKind::Origin,
                hex('1'),
                policy.clone(),
                hex('2'),
                BTreeMap::new(),
            )
            .unwrap(),
        )
        .unwrap();
    graph
        .add_node(
            KnowledgeNode::new(
                "endpoint-1",
                KnowledgeNodeKind::Endpoint,
                hex('3'),
                policy,
                hex('4'),
                BTreeMap::new(),
            )
            .unwrap(),
        )
        .unwrap();
    let edge = KnowledgeEdge::new(
        "origin-1",
        "endpoint-1",
        KnowledgeEdgeKind::Produces,
        hex('5'),
        hex('6'),
    )
    .unwrap();
    graph.add_edge(edge).unwrap();
    assert_eq!(graph.outgoing_edges("origin-1").len(), 1);
    graph.audit().verify().unwrap();
}

#[test]
fn evidence_store_rejects_secret_like_material_and_deduplicates() {
    let policy = hex('d');
    let mut store = EvidenceStore::new(policy.clone(), hex('0')).unwrap();
    let input = EvidenceInput {
        class: EvidenceClass::Differential,
        subject_id: "validated-1".into(),
        summary: "Two bounded samples produced the same status and body-hash delta.".into(),
        metadata: BTreeMap::from([("delta_sha256".into(), hex('c'))]),
        provenance_sha256: hex('e'),
        policy_snapshot_sha256: policy.clone(),
        redaction_count: 2,
        redaction_verified: true,
    };
    let first = store.insert(input.clone()).unwrap().evidence_id.clone();
    let second = store.insert(input).unwrap().evidence_id.clone();
    assert_eq!(first, second);
    assert_eq!(store.records().len(), 1);
    assert!(matches!(
        store.insert(EvidenceInput {
            class: EvidenceClass::Observation,
            subject_id: "bad-1".into(),
            summary: "Authorization: Bearer secret".into(),
            metadata: BTreeMap::new(),
            provenance_sha256: hex('e'),
            policy_snapshot_sha256: policy,
            redaction_count: 0,
            redaction_verified: true,
        }),
        Err(KnowledgeError::InvalidEvidence(_))
    ));
    store.audit().verify().unwrap();
}

#[test]
fn deduplication_merges_same_policy_rule_origin_and_endpoint() {
    let passive = Finding {
        finding_id: "passive-1".into(),
        rule_id: "BSL-VALID-001".into(),
        title: "Candidate".into(),
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        origin: "https://app.example.com:443".into(),
        endpoint_sha256: hex('a'),
        evidence_sha256: hex('f'),
        summary: "A passive candidate was observed.".into(),
        metadata: BTreeMap::new(),
    };
    let passive = FindingEnvelope::from_passive(&passive, hex('d')).unwrap();
    let validated = validated_envelope();
    let mut dedup = FindingDeduplicator::default();
    dedup.insert(&passive).unwrap();
    let cluster = dedup.insert(&validated).unwrap();
    assert_eq!(cluster.member_finding_ids.len(), 2);
    assert!(cluster.validated);
    assert_eq!(cluster.severity, Severity::High);
}

#[test]
fn evidence_with_different_policy_cannot_attach_to_finding() {
    let mut wrong_store = EvidenceStore::new(hex('e'), hex('0')).unwrap();
    let evidence = wrong_store
        .insert(EvidenceInput {
            class: EvidenceClass::Differential,
            subject_id: "validated-1".into(),
            summary: "Repeatable differential evidence.".into(),
            metadata: BTreeMap::new(),
            provenance_sha256: hex('1'),
            policy_snapshot_sha256: hex('e'),
            redaction_count: 1,
            redaction_verified: true,
        })
        .unwrap()
        .clone();
    let mut registry = FindingRegistry::new(hex('0')).unwrap();
    registry.register(validated_envelope()).unwrap();
    assert!(matches!(
        registry.attach_evidence("validated-1", &evidence),
        Err(KnowledgeError::InvalidEvidence(_))
    ));
}

#[test]
fn report_requires_validation_evidence_and_cleanup_clearance() {
    let policy = hex('d');
    let mut store = EvidenceStore::new(policy.clone(), hex('0')).unwrap();
    let evidence = store
        .insert(EvidenceInput {
            class: EvidenceClass::Differential,
            subject_id: "validated-1".into(),
            summary: "Repeatable differential evidence.".into(),
            metadata: BTreeMap::from([("delta_sha256".into(), hex('c'))]),
            provenance_sha256: hex('e'),
            policy_snapshot_sha256: policy.clone(),
            redaction_count: 1,
            redaction_verified: true,
        })
        .unwrap()
        .clone();
    let mut registry = FindingRegistry::new(hex('0')).unwrap();
    registry.register(validated_envelope()).unwrap();
    registry.attach_evidence("validated-1", &evidence).unwrap();
    assert_eq!(
        registry.transition("validated-1", FindingState::Reportable, None),
        Err(KnowledgeError::FindingNotReportable)
    );
    registry.set_cleanup_clear("validated-1", true).unwrap();
    let record = registry
        .transition("validated-1", FindingState::Reportable, None)
        .unwrap()
        .clone();
    let mut manifest = ExportManifest::new("export-1", policy.clone()).unwrap();
    manifest
        .add_entry(
            format!("evidence/{}.json", evidence.evidence_id),
            "evidence",
            evidence.content_sha256.clone(),
            evidence.serialized_bytes as u64,
        )
        .unwrap();
    manifest.verify().unwrap();
    let mut builder = ReportBuilder::new("fixture-program", policy, 1_800_000_000).unwrap();
    builder.add_finding(&record).unwrap();
    let bundle = builder
        .build(manifest.root_sha256.clone(), registry.audit().tail_hash())
        .unwrap();
    assert!(bundle.markdown.contains("validated-1"));
    assert!(bundle.json.contains("BSL-VALID-001"));
    assert!(!bundle.markdown.to_ascii_lowercase().contains("authorization: bearer"));
    registry.audit().verify().unwrap();
}

#[test]
fn manifest_tampering_is_detected() {
    let mut manifest = ExportManifest::new("export-1", hex('d')).unwrap();
    manifest
        .add_entry("reports/report.json", "report", hex('1'), 100)
        .unwrap();
    manifest.root_sha256 = hex('2');
    assert!(matches!(
        manifest.verify(),
        Err(KnowledgeError::InvalidManifest(_))
    ));
}
