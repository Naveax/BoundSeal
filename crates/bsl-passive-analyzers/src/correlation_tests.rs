#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn finding(index: u64, endpoint: u64, title: &str, severity: Severity) -> Finding {
        Finding {
            finding_id: format!("{index:064x}"),
            rule_id: "BSL-HDR-001".into(),
            title: title.into(),
            severity,
            confidence: Confidence::High,
            origin: "https://fixture.example:443".into(),
            endpoint_sha256: format!("{:064x}", endpoint.saturating_add(100_000)),
            evidence_sha256: format!("{:064x}", index.saturating_add(200_000)),
            summary: "metadata-only correlation fixture".into(),
            metadata: BTreeMap::from([("fixture".into(), "correlation".into())]),
        }
    }

    fn evidence(seed: u64) -> CorrelationEvidence {
        CorrelationEvidence {
            policy_snapshot_sha256: format!("{:064x}", seed.saturating_add(1)),
            normalization_version: "bsl-correlation-v1".into(),
            component_sha256: format!("{:064x}", seed.saturating_add(2)),
            normalized_evidence_sha256: format!("{:064x}", seed.saturating_add(3)),
            response_shape_sha256: format!("{:064x}", seed.saturating_add(4)),
        }
    }

    fn large_limits() -> CorrelationLimits {
        CorrelationResourceBudget {
            cluster_budget_bytes: 32 * 1024 * 1024,
            member_budget_bytes: 32 * 1024 * 1024,
            endpoint_budget_bytes: 32 * 1024 * 1024,
            source_unique_finding_capacity: 100_000,
            source_distinct_endpoint_capacity: 100_000,
        }
        .derive()
        .unwrap()
        .limits
    }

    #[test]
    fn resource_capacity_is_not_tied_to_the_removed_256_ceiling() {
        let derived = CorrelationResourceBudget {
            cluster_budget_bytes: 4 * 1024 * 1024,
            member_budget_bytes: 4 * 1024 * 1024,
            endpoint_budget_bytes: 4 * 1024 * 1024,
            source_unique_finding_capacity: 10_000,
            source_distinct_endpoint_capacity: 10_000,
        }
        .derive()
        .unwrap();
        assert!(derived.limits.maximum_total_members > 256);
        assert!(derived.limits.maximum_endpoints_per_cluster > 256);
    }

    #[test]
    fn five_thousand_endpoints_collapse_to_one_root_cause_without_losing_members() {
        let evidence = evidence(10);
        let root_cause_id = evidence.root_cause_id("BSL-HDR-001").unwrap();
        let mut correlator = RootCauseCorrelator::new(large_limits()).unwrap();

        for index in 1..=5_000 {
            let disposition = correlator
                .correlate(&finding(index, index, "Missing HSTS", Severity::Medium), &evidence)
                .unwrap();
            assert_eq!(
                disposition,
                if index == 1 {
                    CorrelationDisposition::NewRootCause
                } else {
                    CorrelationDisposition::AdditionalAffectedEndpoint
                }
            );
        }

        let cluster = correlator.cluster(&root_cause_id).unwrap();
        assert_eq!(cluster.finding_count(), 5_000);
        assert_eq!(cluster.affected_endpoint_count(), 5_000);
        assert_eq!(cluster.evidence_sha256.len(), 5_000);
        let receipt = correlator.receipt().unwrap();
        assert_eq!(receipt.root_cause_clusters, 1);
        assert_eq!(receipt.total_finding_memberships, 5_000);
        assert_eq!(receipt.total_endpoint_memberships, 5_000);
    }

    #[test]
    fn same_endpoint_additional_finding_is_preserved() {
        let evidence = evidence(20);
        let mut correlator = RootCauseCorrelator::new(large_limits()).unwrap();
        assert_eq!(
            correlator
                .correlate(&finding(1, 7, "Missing HSTS", Severity::Low), &evidence)
                .unwrap(),
            CorrelationDisposition::NewRootCause
        );
        assert_eq!(
            correlator
                .correlate(&finding(2, 7, "Missing HSTS", Severity::High), &evidence)
                .unwrap(),
            CorrelationDisposition::AdditionalFindingSameEndpoint
        );
        let cluster = correlator.clusters().next().unwrap();
        assert_eq!(cluster.finding_count(), 2);
        assert_eq!(cluster.affected_endpoint_count(), 1);
        assert_eq!(cluster.highest_severity, Severity::High);
    }

    #[test]
    fn exact_duplicate_is_counted_but_forged_identity_is_rejected() {
        let evidence = evidence(30);
        let mut correlator = RootCauseCorrelator::new(large_limits()).unwrap();
        let original = finding(1, 1, "Missing HSTS", Severity::Medium);
        assert_eq!(
            correlator.correlate(&original, &evidence).unwrap(),
            CorrelationDisposition::NewRootCause
        );
        assert_eq!(
            correlator.correlate(&original, &evidence).unwrap(),
            CorrelationDisposition::ExactDuplicate
        );

        let mut forged = original.clone();
        forged.endpoint_sha256 = "f".repeat(64);
        assert_eq!(
            correlator.correlate(&forged, &evidence),
            Err(CorrelationError::FindingIdentityConflict)
        );
        let receipt = correlator.receipt().unwrap();
        assert_eq!(receipt.total_finding_memberships, 1);
        assert_eq!(receipt.exact_duplicate_observations, 1);
    }

    #[test]
    fn insertion_order_produces_the_same_cluster_and_receipt() {
        let evidence = evidence(40);
        let alpha = finding(1, 1, "Alpha canonical title", Severity::Low);
        let zulu = finding(2, 2, "Zulu alternate title", Severity::High);

        let mut first = RootCauseCorrelator::new(large_limits()).unwrap();
        first.correlate(&alpha, &evidence).unwrap();
        first.correlate(&zulu, &evidence).unwrap();

        let mut second = RootCauseCorrelator::new(large_limits()).unwrap();
        second.correlate(&zulu, &evidence).unwrap();
        second.correlate(&alpha, &evidence).unwrap();

        assert_eq!(first.export_clusters(), second.export_clusters());
        assert_eq!(first.receipt().unwrap(), second.receipt().unwrap());
        assert_eq!(
            first.clusters().next().unwrap().title,
            "Alpha canonical title"
        );
    }

    #[test]
    fn policy_or_normalized_evidence_changes_create_distinct_roots() {
        let mut correlator = RootCauseCorrelator::new(large_limits()).unwrap();
        correlator
            .correlate(&finding(1, 1, "Missing HSTS", Severity::Medium), &evidence(50))
            .unwrap();
        correlator
            .correlate(&finding(2, 2, "Missing HSTS", Severity::Medium), &evidence(60))
            .unwrap();
        assert_eq!(correlator.receipt().unwrap().root_cause_clusters, 2);
    }

    #[test]
    fn endpoint_budget_failure_does_not_mutate_the_cluster() {
        let limits = CorrelationLimits {
            maximum_clusters: 2,
            maximum_members_per_cluster: 2,
            maximum_endpoints_per_cluster: 1,
            maximum_total_members: 2,
        };
        let evidence = evidence(70);
        let mut correlator = RootCauseCorrelator::new(limits).unwrap();
        correlator
            .correlate(&finding(1, 1, "Missing HSTS", Severity::Medium), &evidence)
            .unwrap();
        assert_eq!(
            correlator.correlate(
                &finding(2, 2, "Missing HSTS", Severity::Medium),
                &evidence
            ),
            Err(CorrelationError::EndpointBudget)
        );
        let receipt = correlator.receipt().unwrap();
        assert_eq!(receipt.total_finding_memberships, 1);
        assert_eq!(receipt.total_endpoint_memberships, 1);
    }
}
