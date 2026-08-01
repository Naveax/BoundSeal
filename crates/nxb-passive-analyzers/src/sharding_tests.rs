#[cfg(test)]
mod tests {
    use super::*;

    fn sha(index: u64) -> String {
        format!("{:064x}", index.saturating_add(1))
    }

    fn pair(index: u64, rule: &str) -> PairKey {
        PairKey::new(&sha(index.saturating_add(10_000)), rule).unwrap()
    }

    fn resources(units: u64) -> ShardResources {
        ShardResources {
            requests: units,
            mutations: 0,
            accounted_memory_bytes: units.saturating_mul(128),
            evidence_bytes: units.saturating_mul(32),
            disk_bytes: units.saturating_mul(64),
            elapsed_milliseconds: units.saturating_mul(10),
        }
    }

    fn limits(shard_count: u32, pairs: usize) -> ShardLimits {
        ShardLimits {
            shard_count,
            maximum_global_pairs: pairs,
            maximum_pairs_per_shard: pairs,
            maximum_in_flight_per_shard: pairs.min(10_000),
            lease_seconds: 60,
            global_resource_budget: resources(pairs as u64 * 4),
            per_shard_resource_budget: resources(pairs as u64 * 4),
        }
    }

    fn item(
        index: u64,
        origin: u64,
        rule: &str,
        expires_at: i64,
    ) -> ShardedWorkItem {
        let work = AuthorizedWorkItem {
            pair: pair(index, rule),
            plan_sha256: sha(index.saturating_add(20_000)),
            capability_sha256: sha(index.saturating_add(30_000)),
            authorization_sha256: sha(index.saturating_add(40_000)),
            authorization_expires_at_epoch_seconds: expires_at,
            estimated_requests: 1,
            estimated_mutations: 0,
            estimated_cost_units: 10,
            item_priority_weight: 100,
        };
        ShardedWorkItem {
            origin_sha256: sha(origin.saturating_add(50_000)),
            session_partition_sha256: sha(origin.saturating_add(60_000)),
            credential_partition_sha256: sha(origin.saturating_add(70_000)),
            work,
            resource_reservation: resources(1),
        }
    }

    fn result(findings: &[u64]) -> ShardExecutionResult {
        ShardExecutionResult {
            usage: resources(1),
            finding_ids: findings
                .iter()
                .map(|index| sha(index.saturating_add(80_000)))
                .collect(),
        }
    }

    fn origins_on_different_shards(
        coordinator: &DeterministicShardCoordinator,
    ) -> (u64, u32, u64, u32) {
        let first_origin = 1_u64;
        let first_assignment = coordinator
            .assignment_for_origin(
                &sha(first_origin.saturating_add(50_000)),
                pair(1, "NXB-A"),
            )
            .unwrap();
        for candidate in 2..10_000 {
            let assignment = coordinator
                .assignment_for_origin(
                    &sha(candidate.saturating_add(50_000)),
                    pair(candidate, "NXB-A"),
                )
                .unwrap();
            if assignment.shard_id != first_assignment.shard_id {
                return (
                    first_origin,
                    first_assignment.shard_id,
                    candidate,
                    assignment.shard_id,
                );
            }
        }
        panic!("test could not find origins on distinct shards");
    }

    #[test]
    fn same_origin_is_pinned_to_one_shard_for_all_pairs() {
        let mut coordinator =
            DeterministicShardCoordinator::new(limits(16, 100), sha(900_000)).unwrap();
        let first = coordinator
            .enqueue(item(1, 77, "NXB-A", 1_000), 1)
            .unwrap();
        let second = coordinator
            .enqueue(item(2, 77, "NXB-B", 1_000), 1)
            .unwrap();
        assert_eq!(first.shard_id, second.shard_id);
        assert_eq!(
            coordinator.shard_for_origin(&first.origin_sha256),
            Some(first.shard_id)
        );
        assert_eq!(coordinator.owner_of(&first.pair), Some(first.shard_id));
        assert_eq!(coordinator.owner_of(&second.pair), Some(second.shard_id));
    }

    #[test]
    fn conflicting_origin_partition_is_rejected_transactionally() {
        let mut coordinator =
            DeterministicShardCoordinator::new(limits(4, 10), sha(900_001)).unwrap();
        coordinator
            .enqueue(item(1, 50, "NXB-A", 1_000), 1)
            .unwrap();
        let mut conflict = item(2, 50, "NXB-B", 1_000);
        conflict.credential_partition_sha256 = sha(999_999);
        assert_eq!(
            coordinator.enqueue(conflict.clone(), 1),
            Err(ShardingError::OriginPartitionConflict)
        );
        assert_eq!(coordinator.owner_of(&conflict.work.pair), None);
        assert_eq!(coordinator.receipt().unwrap().owned_pairs, 1);
    }

    #[test]
    fn duplicate_pair_cannot_be_owned_twice() {
        let mut coordinator =
            DeterministicShardCoordinator::new(limits(4, 10), sha(900_002)).unwrap();
        let original = item(1, 1, "NXB-A", 1_000);
        coordinator.enqueue(original.clone(), 1).unwrap();
        let mut duplicate = original.clone();
        duplicate.origin_sha256 = sha(123_456);
        duplicate.session_partition_sha256 = sha(123_457);
        duplicate.credential_partition_sha256 = sha(123_458);
        assert_eq!(
            coordinator.enqueue(duplicate, 1),
            Err(ShardingError::PairDuplicate)
        );
        assert_eq!(coordinator.receipt().unwrap().owned_pairs, 1);
    }

    #[test]
    fn shard_budget_failure_does_not_claim_pair_ownership() {
        let constrained = ShardLimits {
            shard_count: 1,
            maximum_global_pairs: 10,
            maximum_pairs_per_shard: 10,
            maximum_in_flight_per_shard: 2,
            lease_seconds: 60,
            global_resource_budget: resources(10),
            per_shard_resource_budget: resources(1),
        };
        let mut coordinator =
            DeterministicShardCoordinator::new(constrained, sha(900_003)).unwrap();
        coordinator
            .enqueue(item(1, 1, "NXB-A", 1_000), 1)
            .unwrap();
        let rejected = item(2, 2, "NXB-A", 1_000);
        assert_eq!(
            coordinator.enqueue(rejected.clone(), 1),
            Err(ShardingError::ShardResourceBudget)
        );
        assert_eq!(coordinator.owner_of(&rejected.work.pair), None);
        assert_eq!(coordinator.receipt().unwrap().owned_pairs, 1);
    }

    #[test]
    fn ten_thousand_pairs_are_assigned_exactly_once_without_a_256_ceiling() {
        let mut coordinator =
            DeterministicShardCoordinator::new(limits(64, 10_000), sha(900_004)).unwrap();
        for index in 0..10_000 {
            let assignment = coordinator
                .enqueue(item(index, index % 500, "NXB-A", 100_000), 1)
                .unwrap();
            assert_eq!(
                coordinator.owner_of(&pair(index, "NXB-A")),
                Some(assignment.shard_id)
            );
        }
        let receipt = coordinator.receipt().unwrap();
        assert_eq!(receipt.owned_pairs, 10_000);
        assert_eq!(receipt.queued_pairs, 10_000);
        assert_eq!(receipt.origin_bindings, 500);
        assert_eq!(receipt.shard_summaries.len(), 64);
        receipt.verify().unwrap();
    }

    #[test]
    fn findings_merge_globally_by_exact_identifier_across_shards() {
        let mut coordinator =
            DeterministicShardCoordinator::new(limits(16, 20), sha(900_005)).unwrap();
        let (first_origin, first_shard, second_origin, second_shard) =
            origins_on_different_shards(&coordinator);
        coordinator
            .enqueue(item(1, first_origin, "NXB-A", 1_000), 1)
            .unwrap();
        coordinator
            .enqueue(item(2, second_origin, "NXB-A", 1_000), 1)
            .unwrap();

        let first_lease = coordinator.lease_next(first_shard, 2).unwrap();
        coordinator
            .complete_lease(first_shard, &first_lease.lease_id, result(&[1, 2]), 3)
            .unwrap();

        let second_lease = coordinator.lease_next(second_shard, 2).unwrap();
        coordinator
            .complete_lease(second_shard, &second_lease.lease_id, result(&[2, 3]), 3)
            .unwrap();

        let receipt = coordinator.receipt().unwrap();
        assert_eq!(receipt.global_unique_findings, 3);
        assert_eq!(receipt.global_duplicate_findings, 1);
        assert_eq!(receipt.completed_pairs, 2);
        assert_eq!(
            receipt
                .shard_summaries
                .iter()
                .map(|summary| summary.accepted_unique_findings)
                .sum::<u64>(),
            3
        );
        assert_eq!(
            receipt
                .shard_summaries
                .iter()
                .map(|summary| summary.duplicate_findings)
                .sum::<u64>(),
            1
        );
    }

    #[test]
    fn lease_is_exact_once_and_usage_overrun_fails_closed() {
        let mut coordinator =
            DeterministicShardCoordinator::new(limits(4, 10), sha(900_006)).unwrap();
        let assignment = coordinator
            .enqueue(item(1, 1, "NXB-A", 1_000), 1)
            .unwrap();
        let lease = coordinator.lease_next(assignment.shard_id, 2).unwrap();
        let mut overrun = result(&[1]);
        overrun.usage.requests = 2;
        assert_eq!(
            coordinator.complete_lease(
                assignment.shard_id,
                &lease.lease_id,
                overrun,
                3
            ),
            Err(ShardingError::UsageExceedsReservation)
        );
        assert_eq!(
            coordinator.complete_lease(
                assignment.shard_id,
                &lease.lease_id,
                result(&[1]),
                4
            ),
            Err(ShardingError::LeaseUnknown)
        );
        let receipt = coordinator.receipt().unwrap();
        assert_eq!(receipt.failed_pairs, 1);
        assert_eq!(receipt.global_reserved_resources, ShardResources::default());
    }

    #[test]
    fn emergency_stop_drains_queues_and_in_flight_reservations() {
        let mut coordinator =
            DeterministicShardCoordinator::new(limits(8, 20), sha(900_007)).unwrap();
        let first = coordinator
            .enqueue(item(1, 1, "NXB-A", 1_000), 1)
            .unwrap();
        coordinator
            .enqueue(item(2, 2, "NXB-A", 1_000), 1)
            .unwrap();
        coordinator.lease_next(first.shard_id, 2).unwrap();
        coordinator.emergency_stop().unwrap();

        let receipt = coordinator.receipt().unwrap();
        assert_eq!(receipt.stop_reason, Some(RunStopReason::EmergencyStop));
        assert_eq!(receipt.queued_pairs, 0);
        assert_eq!(receipt.in_flight_pairs, 0);
        assert_eq!(receipt.failed_pairs, 2);
        assert_eq!(receipt.global_reserved_resources, ShardResources::default());
        assert_eq!(
            coordinator.enqueue(item(3, 3, "NXB-A", 1_000), 3),
            Err(ShardingError::RunStopped(
                RunStopReason::EmergencyStop
            ))
        );
    }

    #[test]
    fn queued_and_leased_authorizations_expire_with_reservation_release() {
        let mut coordinator =
            DeterministicShardCoordinator::new(limits(4, 10), sha(900_008)).unwrap();
        let first = coordinator
            .enqueue(item(1, 1, "NXB-A", 100), 1)
            .unwrap();
        coordinator
            .enqueue(item(2, 2, "NXB-A", 50), 1)
            .unwrap();
        coordinator.lease_next(first.shard_id, 2).unwrap();
        let expired = coordinator.expire(100).unwrap();
        assert_eq!(expired, 2);
        let receipt = coordinator.receipt().unwrap();
        assert_eq!(receipt.expired_pairs, 2);
        assert_eq!(receipt.global_reserved_resources, ShardResources::default());
    }

    #[test]
    fn assignments_and_receipts_are_insertion_order_independent() {
        let mut first =
            DeterministicShardCoordinator::new(limits(8, 20), sha(900_009)).unwrap();
        first.enqueue(item(1, 1, "NXB-A", 1_000), 1).unwrap();
        first.enqueue(item(2, 2, "NXB-B", 1_000), 1).unwrap();

        let mut second =
            DeterministicShardCoordinator::new(limits(8, 20), sha(900_009)).unwrap();
        second.enqueue(item(2, 2, "NXB-B", 1_000), 1).unwrap();
        second.enqueue(item(1, 1, "NXB-A", 1_000), 1).unwrap();

        assert_eq!(
            first.owner_of(&pair(1, "NXB-A")),
            second.owner_of(&pair(1, "NXB-A"))
        );
        assert_eq!(
            first.owner_of(&pair(2, "NXB-B")),
            second.owner_of(&pair(2, "NXB-B"))
        );
        assert_eq!(first.receipt().unwrap(), second.receipt().unwrap());
    }

    #[test]
    fn receipt_tampering_is_rejected() {
        let mut coordinator =
            DeterministicShardCoordinator::new(limits(4, 10), sha(900_010)).unwrap();
        coordinator
            .enqueue(item(1, 1, "NXB-A", 1_000), 1)
            .unwrap();
        let mut receipt = coordinator.receipt().unwrap();
        receipt.owned_pairs = receipt.owned_pairs.saturating_add(1);
        assert_eq!(receipt.verify(), Err(ShardingError::ReceiptDigest));
    }
}
