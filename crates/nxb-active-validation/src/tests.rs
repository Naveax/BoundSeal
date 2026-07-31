fn hex(character: char) -> String {
    std::iter::repeat_n(character, 64).collect()
}

fn plan() -> RequestIntentPlan {
    RequestIntentPlan::new(
        "endpoint-1",
        url::Url::parse("https://app.example.com/items?id=1").unwrap(),
        "GET",
        BTreeSet::from(["id".into()]),
        "empty",
        false,
        RiskClass::SafeActive,
        hex('a'),
        hex('b'),
        512,
        4096,
        0,
        0,
        true,
    )
    .unwrap()
}

fn capability(plan: &RequestIntentPlan) -> CapabilityUseReceipt {
    CapabilityUseReceipt {
        capability_id: "capability-1".into(),
        request_number: 1,
        mutations_used: 1,
        remaining_requests: 9,
        remaining_mutations: 9,
        endpoint_sha256: plan.canonical_url_sha256.clone(),
    }
}

fn template() -> MutationTemplate {
    MutationTemplate::new(
        "safe-default",
        BTreeSet::from([
            MutationKind::ReplaceWithMarker,
            MutationKind::TypePreservingMarker,
            MutationKind::BoundedBoundary,
        ]),
        BTreeSet::from([MutationLocation::Query]),
        128,
        8,
    )
    .unwrap()
}

fn target() -> MutationTarget {
    MutationTarget::new(MutationLocation::Query, "id", hex('c'), ValueClass::Integer).unwrap()
}

fn mutation() -> MutationReceipt {
    let plan = plan();
    let mut engine = SafeMutationEngine::new("engine-1", hex('0')).unwrap();
    engine
        .generate(
            &plan,
            &capability(&plan),
            target(),
            &template(),
            MutationKind::TypePreservingMarker,
            0,
        )
        .unwrap()
        .receipt()
}

fn sample(
    id: &str,
    mutation_id: Option<String>,
    status: u16,
    body: char,
    token: &str,
) -> DifferentialSample {
    DifferentialSample::new(
        id,
        plan().canonical_url_sha256,
        mutation_id,
        status,
        hex('d'),
        hex(body),
        64,
        BTreeSet::from([token.into()]),
        10,
        1,
        hex('e'),
    )
    .unwrap()
}

#[test]
fn safe_mutation_is_capability_bound_and_inert() {
    let plan = plan();
    let mut engine = SafeMutationEngine::new("engine-1", hex('0')).unwrap();
    let generated = engine
        .generate(
            &plan,
            &capability(&plan),
            target(),
            &template(),
            MutationKind::ReplaceWithMarker,
            0,
        )
        .unwrap();
    let value = String::from_utf8(generated.value().to_vec()).unwrap();
    assert!(value.starts_with("nxb_"));
    assert!(!value.contains("http"));
    assert!(!format!("{generated:?}").contains(&value));
    assert_eq!(generated.receipt().value_sha256, hash_bytes(generated.value()));
    engine.audit().verify().unwrap();
}

#[test]
fn forbidden_or_passive_plan_cannot_generate_mutation() {
    let mut passive = plan();
    passive.risk_class = RiskClass::Passive;
    let mut engine = SafeMutationEngine::new("engine-1", hex('0')).unwrap();
    assert!(matches!(
        engine.generate(
            &passive,
            &capability(&passive),
            target(),
            &template(),
            MutationKind::ReplaceWithMarker,
            0,
        ),
        Err(ValidationError::MutationDenied)
    ));
}

#[test]
fn owned_objects_require_exact_cleanup_lifecycle() {
    let mutation = mutation();
    let cleanup = CleanupRecipe::new("DELETE", mutation.endpoint_sha256.clone(), hex('f')).unwrap();
    let mut ledger = OwnershipLedger::new("run-1", hex('0')).unwrap();
    ledger
        .register("object-1", &mutation, hex('1'), 10, 100, cleanup)
        .unwrap();
    ledger.authorize_write("object-1", 20).unwrap();
    ledger.begin_cleanup("object-1").unwrap();
    ledger.complete_cleanup("object-1", hex('2')).unwrap();
    assert!(ledger.unresolved_objects().is_empty());
    assert_eq!(
        ledger.begin_cleanup("object-1"),
        Err(ValidationError::InvalidOwnedObjectState)
    );
    ledger.audit().verify().unwrap();
}

#[test]
fn repeated_differential_promotes_validated_finding() {
    let mutation = mutation();
    let baselines = vec![
        sample("base-1", None, 200, '1', "baseline"),
        sample("base-2", None, 200, '1', "baseline"),
    ];
    let mutated = vec![
        sample(
            "mutated-1",
            Some(mutation.mutation_id.clone()),
            403,
            '2',
            "denied",
        ),
        sample(
            "mutated-2",
            Some(mutation.mutation_id.clone()),
            403,
            '2',
            "denied",
        ),
    ];
    let mut oracle =
        DifferentialOracle::new("oracle-1", DifferentialLimits::default(), hex('0')).unwrap();
    let result = oracle
        .evaluate("candidate-1", &mutation, &baselines, &mutated)
        .unwrap();
    assert_eq!(result.decision, OracleDecision::Confirmed);
    let finding = oracle
        .promote(
            &result,
            "NXB-VALID-001",
            "https://app.example.com:443",
            mutation.endpoint_sha256.clone(),
            "Inert input produced a repeatable authorization boundary change.",
        )
        .unwrap();
    assert_eq!(finding.state, PromotionState::Validated);
    oracle.audit().verify().unwrap();
}

#[test]
fn audit_tampering_is_detected() {
    let mut chain = ValidationAuditChain::new(hex('0')).unwrap();
    chain
        .append(ValidationAuditEvent {
            action: "test".into(),
            subject_id: "subject-1".into(),
            outcome: "ok".into(),
            metadata: BTreeMap::new(),
        })
        .unwrap();
    chain.records_mut()[0].event.outcome = "modified".into();
    assert_eq!(
        chain.verify(),
        Err(ValidationError::AuditRecordHashMismatch { record_index: 0 })
    );
}
