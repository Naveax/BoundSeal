#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(index: u64) -> String {
        format!("{:064x}", index.saturating_add(1))
    }

    fn limits(maximum_pairs: usize) -> SchedulerLimits {
        SchedulerLimits {
            maximum_rules: 1_000,
            maximum_known_pairs: maximum_pairs,
            maximum_queued_pairs: maximum_pairs,
            maximum_in_flight: 1_000,
            maximum_outstanding_request_reservations: maximum_pairs as u64 * 4,
            maximum_outstanding_mutation_reservations: maximum_pairs as u64 * 4,
            lease_seconds: 60,
        }
    }

    fn profile(rule_id: &str) -> RuleProfile {
        RuleProfile {
            rule_id: rule_id.into(),
            severity_weight: 100,
            confidence_weight: 100,
            base_priority_weight: 100,
            minimum_cost_units: 10,
        }
    }

    fn item(index: u64, rule_id: &str, expires_at: i64) -> AuthorizedWorkItem {
        AuthorizedWorkItem {
            pair: PairKey::new(&endpoint(index), rule_id).unwrap(),
            plan_sha256: format!("{:064x}", index.saturating_add(10_000)),
            capability_sha256: format!("{:064x}", index.saturating_add(20_000)),
            authorization_sha256: format!("{:064x}", index.saturating_add(30_000)),
            authorization_expires_at_epoch_seconds: expires_at,
            estimated_requests: 1,
            estimated_mutations: 0,
            estimated_cost_units: 10,
            item_priority_weight: 100,
        }
    }

    fn observation(
        unique: u64,
        duplicate: u64,
        validated: u64,
        rejected: u64,
        cost: u64,
    ) -> RuleObservation {
        RuleObservation {
            unique_findings: unique,
            duplicate_findings: duplicate,
            validated_findings: validated,
            rejected_findings: rejected,
            inconclusive_findings: 0,
            requests: 1,
            evidence_bytes: unique.saturating_mul(32),
            elapsed_milliseconds: cost,
            cost_units: cost,
        }
    }

    fn complete_single(
        scheduler: &mut AdaptiveRuleScheduler,
        work: AuthorizedWorkItem,
        metrics: RuleObservation,
        now: i64,
    ) {
        scheduler.enqueue(work, now).unwrap();
        let lease = scheduler.lease_next(now).unwrap();
        scheduler
            .complete_lease(&lease.lease_id, metrics, now.saturating_add(1))
            .unwrap();
    }

    #[test]
    fn validated_low_cost_rule_is_ranked_above_noisy_expensive_rule() {
        let mut scheduler = AdaptiveRuleScheduler::new(limits(16)).unwrap();
        scheduler.register_rule(profile("NXB-GOOD")).unwrap();
        scheduler.register_rule(profile("NXB-NOISY")).unwrap();
        complete_single(
            &mut scheduler,
            item(1, "NXB-GOOD", 1_000),
            observation(5, 0, 5, 0, 10),
            1,
        );
        complete_single(
            &mut scheduler,
            item(2, "NXB-NOISY", 1_000),
            observation(5, 20, 0, 5, 500),
            2,
        );
        scheduler.enqueue(item(3, "NXB-GOOD", 1_000), 3).unwrap();
        scheduler
            .enqueue(item(4, "NXB-NOISY", 1_000), 3)
            .unwrap();
        let ranking = scheduler.ranking_snapshot(3).unwrap();
        assert_eq!(ranking[0].pair.rule_id, "NXB-GOOD");
        assert!(ranking[0].score.fixed_point_score > ranking[1].score.fixed_point_score);
    }

    #[test]
    fn unseen_rule_receives_deterministic_exploration_priority() {
        let mut scheduler = AdaptiveRuleScheduler::new(limits(32)).unwrap();
        scheduler.register_rule(profile("NXB-OLD")).unwrap();
        scheduler.register_rule(profile("NXB-UNSEEN")).unwrap();
        for index in 0..10 {
            complete_single(
                &mut scheduler,
                item(index, "NXB-OLD", 10_000),
                observation(0, 0, 0, 0, 100),
                index as i64 + 1,
            );
        }
        scheduler
            .enqueue(item(100, "NXB-OLD", 10_000), 20)
            .unwrap();
        scheduler
            .enqueue(item(101, "NXB-UNSEEN", 10_000), 20)
            .unwrap();
        let ranking = scheduler.ranking_snapshot(20).unwrap();
        assert_eq!(ranking[0].pair.rule_id, "NXB-UNSEEN");
    }

    #[test]
    fn run_stop_blocks_new_work_and_leases() {
        let mut scheduler = AdaptiveRuleScheduler::new(limits(4)).unwrap();
        scheduler.register_rule(profile("NXB-RULE")).unwrap();
        scheduler.enqueue(item(1, "NXB-RULE", 1_000), 1).unwrap();
        scheduler.apply_run_stop(RunStopReason::Saturated).unwrap();
        assert_eq!(
            scheduler.lease_next(2),
            Err(SchedulerError::RunStopped(RunStopReason::Saturated))
        );
        assert_eq!(
            scheduler.enqueue(item(2, "NXB-RULE", 1_000), 2),
            Err(SchedulerError::RunStopped(RunStopReason::Saturated))
        );
    }

    #[test]
    fn expired_authorization_is_removed_with_reservation_release() {
        let mut scheduler = AdaptiveRuleScheduler::new(limits(4)).unwrap();
        scheduler.register_rule(profile("NXB-RULE")).unwrap();
        let pair = item(1, "NXB-RULE", 100).pair;
        scheduler.enqueue(item(1, "NXB-RULE", 100), 1).unwrap();
        assert_eq!(scheduler.expire_authorizations(100), vec![pair]);
        assert_eq!(scheduler.lease_next(100), Err(SchedulerError::NoWork));
        let receipt = scheduler.receipt().unwrap();
        assert_eq!(receipt.expired_authorizations, 1);
        assert_eq!(receipt.outstanding_request_reservations, 0);
    }

    #[test]
    fn reservation_failure_is_transactional() {
        let constrained = SchedulerLimits {
            maximum_rules: 2,
            maximum_known_pairs: 2,
            maximum_queued_pairs: 2,
            maximum_in_flight: 1,
            maximum_outstanding_request_reservations: 1,
            maximum_outstanding_mutation_reservations: 1,
            lease_seconds: 60,
        };
        let mut scheduler = AdaptiveRuleScheduler::new(constrained).unwrap();
        scheduler.register_rule(profile("NXB-RULE")).unwrap();
        let mut oversized = item(1, "NXB-RULE", 1_000);
        oversized.estimated_requests = 2;
        assert_eq!(
            scheduler.enqueue(oversized, 1),
            Err(SchedulerError::RequestReservationBudget)
        );
        let receipt = scheduler.receipt().unwrap();
        assert_eq!(receipt.known_pairs, 0);
        assert_eq!(receipt.queued_pairs, 0);
        assert_eq!(receipt.outstanding_request_reservations, 0);
    }

    #[test]
    fn ten_thousand_authorized_pairs_rank_without_a_fixed_256_ceiling() {
        let mut scheduler = AdaptiveRuleScheduler::new(limits(10_000)).unwrap();
        scheduler.register_rule(profile("NXB-RULE")).unwrap();
        for index in 0..10_000 {
            scheduler
                .enqueue(item(index, "NXB-RULE", 100_000), 1)
                .unwrap();
        }
        let ranking = scheduler.ranking_snapshot(1).unwrap();
        assert_eq!(ranking.len(), 10_000);
        assert_eq!(ranking[0].pair, item(0, "NXB-RULE", 100_000).pair);
        let receipt = scheduler.receipt().unwrap();
        assert_eq!(receipt.known_pairs, 10_000);
        assert_eq!(receipt.queued_pairs, 10_000);
        receipt.verify().unwrap();
    }

    #[test]
    fn ranking_and_receipt_are_insertion_order_independent() {
        let mut first = AdaptiveRuleScheduler::new(limits(8)).unwrap();
        first.register_rule(profile("NXB-A")).unwrap();
        first.register_rule(profile("NXB-B")).unwrap();
        first.enqueue(item(1, "NXB-A", 1_000), 1).unwrap();
        first.enqueue(item(2, "NXB-B", 1_000), 1).unwrap();

        let mut second = AdaptiveRuleScheduler::new(limits(8)).unwrap();
        second.register_rule(profile("NXB-B")).unwrap();
        second.register_rule(profile("NXB-A")).unwrap();
        second.enqueue(item(2, "NXB-B", 1_000), 1).unwrap();
        second.enqueue(item(1, "NXB-A", 1_000), 1).unwrap();

        assert_eq!(first.ranking_snapshot(1).unwrap(), second.ranking_snapshot(1).unwrap());
        assert_eq!(first.receipt().unwrap(), second.receipt().unwrap());
    }

    #[test]
    fn lease_is_exactly_once_and_updates_only_its_rule_metrics() {
        let mut scheduler = AdaptiveRuleScheduler::new(limits(4)).unwrap();
        scheduler.register_rule(profile("NXB-A")).unwrap();
        scheduler.enqueue(item(1, "NXB-A", 1_000), 1).unwrap();
        let lease = scheduler.lease_next(1).unwrap();
        scheduler
            .complete_lease(&lease.lease_id, observation(2, 1, 1, 0, 10), 2)
            .unwrap();
        assert_eq!(
            scheduler.complete_lease(&lease.lease_id, observation(0, 0, 0, 0, 1), 3),
            Err(SchedulerError::LeaseUnknown)
        );
        let metrics = scheduler.metrics("NXB-A").unwrap();
        assert_eq!(metrics.completed_checks, 1);
        assert_eq!(metrics.unique_findings, 2);
        assert_eq!(metrics.duplicate_findings, 1);
    }

    #[test]
    fn scheduler_receipt_rejects_tampering() {
        let mut scheduler = AdaptiveRuleScheduler::new(limits(4)).unwrap();
        scheduler.register_rule(profile("NXB-A")).unwrap();
        scheduler.enqueue(item(1, "NXB-A", 1_000), 1).unwrap();
        let mut receipt = scheduler.receipt().unwrap();
        receipt.queued_pairs = receipt.queued_pairs.saturating_add(1);
        assert_eq!(receipt.verify(), Err(SchedulerError::ReceiptDigest));
    }
}
