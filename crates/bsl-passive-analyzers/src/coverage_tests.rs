#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(index: u64) -> String {
        format!("{:064x}", index.saturating_add(1))
    }

    fn limits(maximum_pairs: usize) -> CoverageLimits {
        CoverageLimits {
            maximum_endpoints: maximum_pairs.max(1),
            maximum_rules: maximum_pairs.max(1),
            maximum_recorded_pairs: maximum_pairs,
            maximum_windows: 128,
        }
    }

    fn budget() -> CoverageResourceBudget {
        CoverageResourceBudget {
            memory_budget_bytes: 1024 * 1024 * 1024,
            evidence_budget_bytes: 1024 * 1024 * 1024,
            disk_budget_bytes: 1024 * 1024 * 1024,
            request_budget: 1_000_000,
            time_budget_milliseconds: 86_400_000,
        }
    }

    fn policy() -> SaturationPolicy {
        SaturationPolicy {
            checks_per_window: 100,
            minimum_completed_checks: 100,
            required_consecutive_low_yield_windows: 3,
            yield_threshold_numerator: 1,
            yield_threshold_denominator: 100,
        }
    }

    fn metrics(unique_findings: u64) -> ExecutionMetrics {
        ExecutionMetrics {
            unique_findings,
            duplicate_findings: 0,
            validated_findings: unique_findings,
            rejected_findings: 0,
            inconclusive_findings: 0,
            resource_delta: ResourceUse {
                accounted_memory_bytes: 128,
                evidence_bytes: unique_findings.saturating_mul(32),
                disk_bytes: unique_findings.saturating_mul(64),
                requests: 1,
                elapsed_milliseconds: 5,
            },
        }
    }

    #[test]
    fn receipt_distinguishes_tested_without_findings_skipped_and_untested() {
        let mut tracker = CoverageTracker::new(limits(16), budget(), policy()).unwrap();
        let first = endpoint(1);
        let second = endpoint(2);
        tracker.admit_endpoint(&first).unwrap();
        tracker.admit_endpoint(&second).unwrap();
        tracker.enable_rule("NXB-RULE-A").unwrap();
        tracker.enable_rule("NXB-RULE-B").unwrap();

        tracker
            .record_execution(&first, "NXB-RULE-A", metrics(0))
            .unwrap();
        tracker
            .record_skip(&first, "NXB-RULE-B", PairSkipReason::NotApplicable)
            .unwrap();

        let receipt = tracker.receipt().unwrap();
        receipt.verify().unwrap();
        assert_eq!(receipt.admitted_endpoints, 2);
        assert_eq!(receipt.considered_endpoints, 1);
        assert_eq!(receipt.analyzed_endpoints, 1);
        assert_eq!(receipt.untested_endpoints, 1);
        assert_eq!(receipt.theoretical_pairs, 4);
        assert_eq!(receipt.executed_pairs, 1);
        assert_eq!(receipt.skipped_pairs, 1);
        assert_eq!(receipt.untested_pairs, 2);
        assert_eq!(receipt.unique_findings, 0);
        assert_eq!(receipt.stop_reason, None);
    }

    #[test]
    fn ten_thousand_pairs_are_accounted_without_a_fixed_256_ceiling() {
        let mut tracker = CoverageTracker::new(limits(10_000), budget(), policy()).unwrap();
        for index in 0..100 {
            tracker.admit_endpoint(&endpoint(index)).unwrap();
        }
        for index in 0..100 {
            tracker.enable_rule(&format!("NXB-RULE-{index:03}")).unwrap();
        }
        for endpoint_index in 0..100 {
            for rule_index in 0..100 {
                tracker
                    .record_skip(
                        &endpoint(endpoint_index),
                        &format!("NXB-RULE-{rule_index:03}"),
                        PairSkipReason::NotApplicable,
                    )
                    .unwrap();
            }
        }
        tracker.mark_completed().unwrap();
        let receipt = tracker.receipt().unwrap();
        assert_eq!(receipt.recorded_pairs, 10_000);
        assert_eq!(receipt.skipped_pairs, 10_000);
        assert_eq!(receipt.untested_pairs, 0);
        assert_eq!(receipt.stop_reason, Some(RunStopReason::Completed));
        receipt.verify().unwrap();
    }

    #[test]
    fn low_yield_windows_saturate_only_after_the_required_sequence() {
        let saturation = SaturationPolicy {
            checks_per_window: 2,
            minimum_completed_checks: 6,
            required_consecutive_low_yield_windows: 3,
            yield_threshold_numerator: 1,
            yield_threshold_denominator: 10,
        };
        let mut tracker = CoverageTracker::new(limits(16), budget(), saturation).unwrap();
        tracker.enable_rule("NXB-RULE-A").unwrap();
        for index in 0..6 {
            let current = endpoint(index);
            tracker.admit_endpoint(&current).unwrap();
            tracker
                .record_execution(&current, "NXB-RULE-A", metrics(0))
                .unwrap();
            if index < 5 {
                assert_eq!(tracker.stop_reason(), None);
            }
        }
        assert_eq!(tracker.stop_reason(), Some(RunStopReason::Saturated));
        let receipt = tracker.receipt().unwrap();
        assert_eq!(receipt.saturation_windows.len(), 3);
        assert!(receipt
            .saturation_windows
            .iter()
            .all(|window| window.below_yield_threshold));
    }

    #[test]
    fn pending_high_priority_or_validation_work_blocks_saturation() {
        let saturation = SaturationPolicy {
            checks_per_window: 2,
            minimum_completed_checks: 6,
            required_consecutive_low_yield_windows: 3,
            yield_threshold_numerator: 1,
            yield_threshold_denominator: 10,
        };
        let mut tracker = CoverageTracker::new(limits(16), budget(), saturation).unwrap();
        tracker.enable_rule("NXB-RULE-A").unwrap();
        tracker
            .set_queue_telemetry(QueueTelemetry {
                high_priority_unexplored_pairs: 1,
                validation_queue: 1,
                cleanup_queue: 0,
            })
            .unwrap();
        for index in 0..6 {
            let current = endpoint(index);
            tracker.admit_endpoint(&current).unwrap();
            tracker
                .record_execution(&current, "NXB-RULE-A", metrics(0))
                .unwrap();
        }
        assert_eq!(tracker.stop_reason(), None);
        tracker
            .set_queue_telemetry(QueueTelemetry::default())
            .unwrap();
        assert_eq!(tracker.stop_reason(), Some(RunStopReason::Saturated));
    }

    #[test]
    fn resource_boundary_is_transactional_and_explicit() {
        let constrained = CoverageResourceBudget {
            memory_budget_bytes: 1024,
            evidence_budget_bytes: 1024,
            disk_budget_bytes: 1024,
            request_budget: 1,
            time_budget_milliseconds: 100,
        };
        let mut tracker = CoverageTracker::new(limits(4), constrained, policy()).unwrap();
        let current = endpoint(1);
        tracker.admit_endpoint(&current).unwrap();
        tracker.enable_rule("NXB-RULE-A").unwrap();
        let mut over_budget = metrics(0);
        over_budget.resource_delta.requests = 2;

        assert_eq!(
            tracker.record_execution(&current, "NXB-RULE-A", over_budget),
            Err(CoverageError::ResourceBoundary(
                RunStopReason::RequestBudget
            ))
        );
        let receipt = tracker.receipt().unwrap();
        assert_eq!(receipt.recorded_pairs, 0);
        assert_eq!(receipt.resource_use, ResourceUse::default());
        assert_eq!(receipt.stop_reason, Some(RunStopReason::RequestBudget));
    }

    #[test]
    fn receipt_is_deterministic_across_insertion_order() {
        let first_endpoint = endpoint(1);
        let second_endpoint = endpoint(2);
        let mut first = CoverageTracker::new(limits(8), budget(), policy()).unwrap();
        first.admit_endpoint(&first_endpoint).unwrap();
        first.admit_endpoint(&second_endpoint).unwrap();
        first.enable_rule("NXB-RULE-A").unwrap();
        first.enable_rule("NXB-RULE-B").unwrap();
        first
            .record_execution(&first_endpoint, "NXB-RULE-A", metrics(2))
            .unwrap();
        first
            .record_skip(
                &second_endpoint,
                "NXB-RULE-B",
                PairSkipReason::NotApplicable,
            )
            .unwrap();

        let mut second = CoverageTracker::new(limits(8), budget(), policy()).unwrap();
        second.admit_endpoint(&second_endpoint).unwrap();
        second.admit_endpoint(&first_endpoint).unwrap();
        second.enable_rule("NXB-RULE-B").unwrap();
        second.enable_rule("NXB-RULE-A").unwrap();
        second
            .record_skip(
                &second_endpoint,
                "NXB-RULE-B",
                PairSkipReason::NotApplicable,
            )
            .unwrap();
        second
            .record_execution(&first_endpoint, "NXB-RULE-A", metrics(2))
            .unwrap();

        assert_eq!(first.receipt().unwrap(), second.receipt().unwrap());
    }

    #[test]
    fn completion_requires_every_pair_and_empty_queues() {
        let mut tracker = CoverageTracker::new(limits(4), budget(), policy()).unwrap();
        let current = endpoint(1);
        tracker.admit_endpoint(&current).unwrap();
        tracker.enable_rule("NXB-RULE-A").unwrap();
        assert_eq!(tracker.mark_completed(), Err(CoverageError::IncompleteCoverage));
        tracker
            .record_execution(&current, "NXB-RULE-A", metrics(1))
            .unwrap();
        tracker
            .set_queue_telemetry(QueueTelemetry {
                high_priority_unexplored_pairs: 0,
                validation_queue: 1,
                cleanup_queue: 0,
            })
            .unwrap();
        assert_eq!(tracker.mark_completed(), Err(CoverageError::IncompleteCoverage));
        tracker
            .set_queue_telemetry(QueueTelemetry::default())
            .unwrap();
        tracker.mark_completed().unwrap();
        assert_eq!(tracker.stop_reason(), Some(RunStopReason::Completed));
    }

    #[test]
    fn receipt_tampering_is_rejected() {
        let mut tracker = CoverageTracker::new(limits(4), budget(), policy()).unwrap();
        let current = endpoint(1);
        tracker.admit_endpoint(&current).unwrap();
        tracker.enable_rule("NXB-RULE-A").unwrap();
        tracker
            .record_execution(&current, "NXB-RULE-A", metrics(1))
            .unwrap();
        let mut receipt = tracker.receipt().unwrap();
        receipt.unique_findings = receipt.unique_findings.saturating_add(1);
        assert_eq!(receipt.verify(), Err(CoverageError::ReceiptDigest));
    }
}
