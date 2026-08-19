#[cfg(test)]
mod capacity_tests {
    use super::*;

    fn finding(index: u64, endpoint: u64) -> Finding {
        Finding {
            finding_id: format!("{index:064x}"),
            rule_id: format!("BSL-TEST-{index:06}"),
            title: "Synthetic capacity finding".into(),
            severity: Severity::Low,
            confidence: Confidence::High,
            origin: "https://fixture.example:443".into(),
            endpoint_sha256: format!("{endpoint:064x}"),
            evidence_sha256: format!("{:064x}", index.saturating_add(1)),
            summary: "Synthetic metadata-only capacity fixture.".into(),
            metadata: BTreeMap::from([("fixture".into(), "capacity".into())]),
        }
    }

    #[test]
    fn derived_capacity_is_not_tied_to_the_removed_256_ceiling() {
        let capacity = FindingResourceBudget {
            memory_budget_bytes: 4 * 1024 * 1024,
            evidence_budget_bytes: 1024 * 1024,
            endpoint_budget: 1_000,
            rules_per_endpoint_upper_bound: 2,
        }
        .derive()
        .unwrap();

        assert_eq!(capacity.scope_limited_findings, 2_000);
        assert_eq!(capacity.maximum_unique_findings, 2_000);
        assert!(capacity.maximum_unique_findings > 256);

        let mut accumulator = FindingAccumulator::new(capacity);
        for index in 0..1_000 {
            assert_eq!(
                accumulator.ingest(finding(index, index), 64).unwrap(),
                FindingIngestOutcome::Accepted
            );
        }
        assert_eq!(accumulator.receipt().accepted_unique_findings, 1_000);
        assert_eq!(accumulator.receipt().stop_reason, None);
    }

    #[test]
    fn duplicates_do_not_consume_resource_capacity() {
        let capacity = FindingResourceBudget {
            memory_budget_bytes: 4096,
            evidence_budget_bytes: 4096,
            endpoint_budget: 4,
            rules_per_endpoint_upper_bound: 4,
        }
        .derive()
        .unwrap();
        let mut accumulator = FindingAccumulator::new(capacity);
        let item = finding(1, 1);

        assert_eq!(
            accumulator.ingest(item.clone(), 32).unwrap(),
            FindingIngestOutcome::Accepted
        );
        for _ in 0..500 {
            assert_eq!(
                accumulator.ingest(item.clone(), 32).unwrap(),
                FindingIngestOutcome::Duplicate
            );
        }

        let receipt = accumulator.receipt();
        assert_eq!(receipt.accepted_unique_findings, 1);
        assert_eq!(receipt.duplicate_findings, 500);
        assert_eq!(receipt.distinct_endpoints, 1);
    }

    #[test]
    fn accumulator_stops_at_the_first_real_resource_boundary() {
        let capacity = FindingResourceBudget {
            memory_budget_bytes: 64 * 1024,
            evidence_budget_bytes: 64 * 1024,
            endpoint_budget: 2,
            rules_per_endpoint_upper_bound: 10,
        }
        .derive()
        .unwrap();
        let mut accumulator = FindingAccumulator::new(capacity);

        assert_eq!(
            accumulator.ingest(finding(1, 1), 32).unwrap(),
            FindingIngestOutcome::Accepted
        );
        assert_eq!(
            accumulator.ingest(finding(2, 1), 32).unwrap(),
            FindingIngestOutcome::Accepted
        );
        assert_eq!(
            accumulator.ingest(finding(3, 2), 32).unwrap(),
            FindingIngestOutcome::Accepted
        );
        assert_eq!(
            accumulator.ingest(finding(4, 3), 32).unwrap(),
            FindingIngestOutcome::Stopped(FindingStopReason::EndpointBudget)
        );
        assert_eq!(
            accumulator.receipt().stop_reason,
            Some(FindingStopReason::EndpointBudget)
        );
    }
}
