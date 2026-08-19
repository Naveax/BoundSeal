impl DeterministicShardCoordinator {
    pub fn new(
        limits: ShardLimits,
        run_partition_sha256: impl Into<String>,
    ) -> Result<Self, ShardingError> {
        let limits = limits.validate()?;
        let run_partition_sha256 = run_partition_sha256.into();
        validate_shard_sha256(&run_partition_sha256)?;
        let shards = (0..limits.shard_count)
            .map(|shard_id| (shard_id, ShardState::default()))
            .collect::<BTreeMap<_, _>>();
        Ok(Self {
            limits,
            run_partition_sha256,
            shards,
            origin_bindings: BTreeMap::new(),
            pair_owners: BTreeMap::new(),
            global_finding_ids: BTreeSet::new(),
            global_duplicate_findings: 0,
            global_reserved_resources: ShardResources::default(),
            global_used_resources: ShardResources::default(),
            next_lease_sequence: 1,
            stop_reason: None,
        })
    }

    pub fn assignment_for_origin(
        &self,
        origin_sha256: &str,
        pair: PairKey,
    ) -> Result<ShardAssignment, ShardingError> {
        validate_shard_sha256(origin_sha256)?;
        let digest = shard_hash_serializable(&(
            "bsl-shard-v1",
            &self.run_partition_sha256,
            origin_sha256,
        ))?;
        let shard_id = shard_index_from_digest(&digest, self.limits.shard_count)?;
        let assignment_sha256 =
            shard_hash_serializable(&(shard_id, origin_sha256, &pair, &digest))?;
        Ok(ShardAssignment {
            shard_id,
            origin_sha256: origin_sha256.into(),
            pair,
            assignment_sha256,
        })
    }

    pub fn enqueue(
        &mut self,
        item: ShardedWorkItem,
        now_epoch_seconds: i64,
    ) -> Result<ShardAssignment, ShardingError> {
        self.ensure_running()?;
        item.validate()?;
        if item.work.authorization_expires_at_epoch_seconds <= now_epoch_seconds {
            return Err(ShardingError::AuthorizationExpired);
        }
        if self.pair_owners.contains_key(&item.work.pair) {
            return Err(ShardingError::PairDuplicate);
        }
        if self.pair_owners.len() >= self.limits.maximum_global_pairs {
            return Err(ShardingError::GlobalQueueBudget);
        }

        let assignment =
            self.assignment_for_origin(&item.origin_sha256, item.work.pair.clone())?;
        if let Some(binding) = self.origin_bindings.get(&item.origin_sha256) {
            if binding.shard_id != assignment.shard_id
                || binding.session_partition_sha256 != item.session_partition_sha256
                || binding.credential_partition_sha256 != item.credential_partition_sha256
            {
                return Err(ShardingError::OriginPartitionConflict);
            }
        }

        let shard = self
            .shards
            .get(&assignment.shard_id)
            .ok_or(ShardingError::ShardUnknown)?;
        let known_in_shard = shard
            .queued
            .len()
            .saturating_add(shard.in_flight.len())
            .saturating_add(shard.completed_pairs.len())
            .saturating_add(shard.failed_pairs.len())
            .saturating_add(shard.expired_pairs.len());
        if known_in_shard >= self.limits.maximum_pairs_per_shard {
            return Err(ShardingError::ShardQueueBudget);
        }

        let global_committed = self
            .global_used_resources
            .checked_add(self.global_reserved_resources)
            .checked_add(item.resource_reservation);
        if global_committed.exceeds(self.limits.global_resource_budget) {
            return Err(ShardingError::GlobalResourceBudget);
        }
        let shard_committed = shard
            .used_resources
            .checked_add(shard.reserved_resources)
            .checked_add(item.resource_reservation);
        if shard_committed.exceeds(self.limits.per_shard_resource_budget) {
            return Err(ShardingError::ShardResourceBudget);
        }

        self.origin_bindings
            .entry(item.origin_sha256.clone())
            .or_insert_with(|| OriginBinding {
                shard_id: assignment.shard_id,
                session_partition_sha256: item.session_partition_sha256.clone(),
                credential_partition_sha256: item.credential_partition_sha256.clone(),
            });
        self.pair_owners
            .insert(item.work.pair.clone(), assignment.shard_id);
        self.global_reserved_resources = self
            .global_reserved_resources
            .checked_add(item.resource_reservation);
        let shard = self
            .shards
            .get_mut(&assignment.shard_id)
            .ok_or(ShardingError::ShardUnknown)?;
        shard.reserved_resources = shard
            .reserved_resources
            .checked_add(item.resource_reservation);
        shard.queued.insert(item.work.pair.clone(), item);
        Ok(assignment)
    }

    pub fn lease_next(
        &mut self,
        shard_id: u32,
        now_epoch_seconds: i64,
    ) -> Result<ShardLease, ShardingError> {
        self.ensure_running()?;
        self.expire(now_epoch_seconds)?;
        let shard = self
            .shards
            .get(&shard_id)
            .ok_or(ShardingError::ShardUnknown)?;
        if shard.in_flight.len() >= self.limits.maximum_in_flight_per_shard {
            return Err(ShardingError::ShardInFlightBudget);
        }
        let pair = shard
            .queued
            .keys()
            .next()
            .cloned()
            .ok_or(ShardingError::NoWork)?;
        let item = self
            .shards
            .get_mut(&shard_id)
            .ok_or(ShardingError::ShardUnknown)?
            .queued
            .remove(&pair)
            .ok_or(ShardingError::NoWork)?;
        let expires_at_epoch_seconds = item
            .work
            .authorization_expires_at_epoch_seconds
            .min(now_epoch_seconds.saturating_add(self.limits.lease_seconds));
        if expires_at_epoch_seconds <= now_epoch_seconds {
            self.release_reservation(shard_id, item.resource_reservation)?;
            self.shards
                .get_mut(&shard_id)
                .ok_or(ShardingError::ShardUnknown)?
                .expired_pairs
                .insert(item.work.pair);
            return Err(ShardingError::AuthorizationExpired);
        }

        let sequence = self.next_lease_sequence;
        self.next_lease_sequence = self.next_lease_sequence.saturating_add(1);
        let lease_digest = shard_hash_serializable(&(
            sequence,
            shard_id,
            &item.origin_sha256,
            &item.work.pair,
            &item.work.authorization_sha256,
            now_epoch_seconds,
            expires_at_epoch_seconds,
        ))?;
        let lease_id = format!("shard-lease-{sequence:020}-{}", &lease_digest[..16]);
        self.shards
            .get_mut(&shard_id)
            .ok_or(ShardingError::ShardUnknown)?
            .in_flight
            .insert(
                lease_id.clone(),
                ShardLeaseState {
                    item: item.clone(),
                    expires_at_epoch_seconds,
                },
            );
        Ok(ShardLease {
            lease_id,
            shard_id,
            origin_sha256: item.origin_sha256,
            pair: item.work.pair,
            plan_sha256: item.work.plan_sha256,
            capability_sha256: item.work.capability_sha256,
            authorization_sha256: item.work.authorization_sha256,
            session_partition_sha256: item.session_partition_sha256,
            credential_partition_sha256: item.credential_partition_sha256,
            reservation: item.resource_reservation,
            issued_at_epoch_seconds: now_epoch_seconds,
            expires_at_epoch_seconds,
        })
    }

    pub fn complete_lease(
        &mut self,
        shard_id: u32,
        lease_id: &str,
        result: ShardExecutionResult,
        now_epoch_seconds: i64,
    ) -> Result<(), ShardingError> {
        self.ensure_running()?;
        result.validate()?;
        let state = self
            .shards
            .get_mut(&shard_id)
            .ok_or(ShardingError::ShardUnknown)?
            .in_flight
            .remove(lease_id)
            .ok_or(ShardingError::LeaseUnknown)?;
        if now_epoch_seconds >= state.expires_at_epoch_seconds {
            self.release_reservation(shard_id, state.item.resource_reservation)?;
            self.shards
                .get_mut(&shard_id)
                .ok_or(ShardingError::ShardUnknown)?
                .expired_pairs
                .insert(state.item.work.pair);
            return Err(ShardingError::LeaseExpired);
        }
        if !resources_within(result.usage, state.item.resource_reservation) {
            self.release_reservation(shard_id, state.item.resource_reservation)?;
            self.shards
                .get_mut(&shard_id)
                .ok_or(ShardingError::ShardUnknown)?
                .failed_pairs
                .insert(state.item.work.pair);
            return Err(ShardingError::UsageExceedsReservation);
        }

        self.release_reservation(shard_id, state.item.resource_reservation)?;
        self.global_used_resources = self.global_used_resources.checked_add(result.usage);
        let mut accepted = 0_u64;
        let mut duplicates = 0_u64;
        for finding_id in result.finding_ids {
            if self.global_finding_ids.insert(finding_id) {
                accepted = accepted.saturating_add(1);
            } else {
                duplicates = duplicates.saturating_add(1);
                self.global_duplicate_findings =
                    self.global_duplicate_findings.saturating_add(1);
            }
        }
        let shard = self
            .shards
            .get_mut(&shard_id)
            .ok_or(ShardingError::ShardUnknown)?;
        shard.used_resources = shard.used_resources.checked_add(result.usage);
        shard.accepted_unique_findings =
            shard.accepted_unique_findings.saturating_add(accepted);
        shard.duplicate_findings = shard.duplicate_findings.saturating_add(duplicates);
        shard.completed_pairs.insert(state.item.work.pair);
        Ok(())
    }

    pub fn fail_lease(
        &mut self,
        shard_id: u32,
        lease_id: &str,
        now_epoch_seconds: i64,
    ) -> Result<(), ShardingError> {
        self.ensure_running()?;
        let state = self
            .shards
            .get_mut(&shard_id)
            .ok_or(ShardingError::ShardUnknown)?
            .in_flight
            .remove(lease_id)
            .ok_or(ShardingError::LeaseUnknown)?;
        self.release_reservation(shard_id, state.item.resource_reservation)?;
        if now_epoch_seconds >= state.expires_at_epoch_seconds {
            self.shards
                .get_mut(&shard_id)
                .ok_or(ShardingError::ShardUnknown)?
                .expired_pairs
                .insert(state.item.work.pair);
            return Err(ShardingError::LeaseExpired);
        }
        self.shards
            .get_mut(&shard_id)
            .ok_or(ShardingError::ShardUnknown)?
            .failed_pairs
            .insert(state.item.work.pair);
        Ok(())
    }

    pub fn expire(&mut self, now_epoch_seconds: i64) -> Result<u64, ShardingError> {
        let mut expired_count = 0_u64;
        for shard_id in 0..self.limits.shard_count {
            let queued_expired = self
                .shards
                .get(&shard_id)
                .ok_or(ShardingError::ShardUnknown)?
                .queued
                .iter()
                .filter(|(_, item)| {
                    item.work.authorization_expires_at_epoch_seconds <= now_epoch_seconds
                })
                .map(|(pair, _)| pair.clone())
                .collect::<Vec<_>>();
            for pair in queued_expired {
                let item = self
                    .shards
                    .get_mut(&shard_id)
                    .ok_or(ShardingError::ShardUnknown)?
                    .queued
                    .remove(&pair)
                    .ok_or(ShardingError::NoWork)?;
                self.release_reservation(shard_id, item.resource_reservation)?;
                self.shards
                    .get_mut(&shard_id)
                    .ok_or(ShardingError::ShardUnknown)?
                    .expired_pairs
                    .insert(pair);
                expired_count = expired_count.saturating_add(1);
            }

            let lease_expired = self
                .shards
                .get(&shard_id)
                .ok_or(ShardingError::ShardUnknown)?
                .in_flight
                .iter()
                .filter(|(_, state)| state.expires_at_epoch_seconds <= now_epoch_seconds)
                .map(|(lease_id, _)| lease_id.clone())
                .collect::<Vec<_>>();
            for lease_id in lease_expired {
                let state = self
                    .shards
                    .get_mut(&shard_id)
                    .ok_or(ShardingError::ShardUnknown)?
                    .in_flight
                    .remove(&lease_id)
                    .ok_or(ShardingError::LeaseUnknown)?;
                self.release_reservation(shard_id, state.item.resource_reservation)?;
                self.shards
                    .get_mut(&shard_id)
                    .ok_or(ShardingError::ShardUnknown)?
                    .expired_pairs
                    .insert(state.item.work.pair);
                expired_count = expired_count.saturating_add(1);
            }
        }
        Ok(expired_count)
    }

    pub fn apply_run_stop(&mut self, reason: RunStopReason) -> Result<(), ShardingError> {
        self.ensure_running()?;
        self.stop_reason = Some(reason);
        Ok(())
    }

    pub fn emergency_stop(&mut self) -> Result<(), ShardingError> {
        self.ensure_running()?;
        for shard_id in 0..self.limits.shard_count {
            let queued = std::mem::take(
                &mut self
                    .shards
                    .get_mut(&shard_id)
                    .ok_or(ShardingError::ShardUnknown)?
                    .queued,
            );
            for (_, item) in queued {
                self.release_reservation(shard_id, item.resource_reservation)?;
                self.shards
                    .get_mut(&shard_id)
                    .ok_or(ShardingError::ShardUnknown)?
                    .failed_pairs
                    .insert(item.work.pair);
            }
            let in_flight = std::mem::take(
                &mut self
                    .shards
                    .get_mut(&shard_id)
                    .ok_or(ShardingError::ShardUnknown)?
                    .in_flight,
            );
            for (_, state) in in_flight {
                self.release_reservation(shard_id, state.item.resource_reservation)?;
                self.shards
                    .get_mut(&shard_id)
                    .ok_or(ShardingError::ShardUnknown)?
                    .failed_pairs
                    .insert(state.item.work.pair);
            }
        }
        self.stop_reason = Some(RunStopReason::EmergencyStop);
        Ok(())
    }

    pub fn stop_reason(&self) -> Option<RunStopReason> {
        self.stop_reason
    }

    pub fn shard_for_origin(&self, origin_sha256: &str) -> Option<u32> {
        self.origin_bindings
            .get(origin_sha256)
            .map(|binding| binding.shard_id)
    }

    pub fn owner_of(&self, pair: &PairKey) -> Option<u32> {
        self.pair_owners.get(pair).copied()
    }

    pub fn receipt(&self) -> Result<ShardingReceipt, ShardingError> {
        let mut shard_summaries = Vec::with_capacity(self.limits.shard_count as usize);
        for (shard_id, shard) in &self.shards {
            let queue_material = shard.queued.iter().collect::<Vec<_>>();
            let in_flight_material = shard
                .in_flight
                .iter()
                .map(|(lease_id, state)| {
                    (lease_id, &state.item, state.expires_at_epoch_seconds)
                })
                .collect::<Vec<_>>();
            let state_sha256 = shard_hash_serializable(&(
                queue_material,
                in_flight_material,
                &shard.completed_pairs,
                &shard.failed_pairs,
                &shard.expired_pairs,
                shard.reserved_resources,
                shard.used_resources,
                shard.accepted_unique_findings,
                shard.duplicate_findings,
            ))?;
            shard_summaries.push(ShardSummary {
                shard_id: *shard_id,
                queued_pairs: shard.queued.len() as u64,
                in_flight_pairs: shard.in_flight.len() as u64,
                completed_pairs: shard.completed_pairs.len() as u64,
                failed_pairs: shard.failed_pairs.len() as u64,
                expired_pairs: shard.expired_pairs.len() as u64,
                reserved_resources: shard.reserved_resources,
                used_resources: shard.used_resources,
                accepted_unique_findings: shard.accepted_unique_findings,
                duplicate_findings: shard.duplicate_findings,
                state_sha256,
            });
        }
        let queued_pairs = shard_summaries
            .iter()
            .fold(0_u64, |sum, shard| sum.saturating_add(shard.queued_pairs));
        let in_flight_pairs = shard_summaries.iter().fold(0_u64, |sum, shard| {
            sum.saturating_add(shard.in_flight_pairs)
        });
        let completed_pairs = shard_summaries.iter().fold(0_u64, |sum, shard| {
            sum.saturating_add(shard.completed_pairs)
        });
        let failed_pairs = shard_summaries.iter().fold(0_u64, |sum, shard| {
            sum.saturating_add(shard.failed_pairs)
        });
        let expired_pairs = shard_summaries.iter().fold(0_u64, |sum, shard| {
            sum.saturating_add(shard.expired_pairs)
        });
        let ownership_material = self.pair_owners.iter().collect::<Vec<_>>();
        let origin_material = self
            .origin_bindings
            .iter()
            .map(|(origin, binding)| {
                (
                    origin,
                    binding.shard_id,
                    &binding.session_partition_sha256,
                    &binding.credential_partition_sha256,
                )
            })
            .collect::<Vec<_>>();
        let mut receipt = ShardingReceipt {
            shard_count: self.limits.shard_count,
            origin_bindings: self.origin_bindings.len() as u64,
            owned_pairs: self.pair_owners.len() as u64,
            queued_pairs,
            in_flight_pairs,
            completed_pairs,
            failed_pairs,
            expired_pairs,
            global_reserved_resources: self.global_reserved_resources,
            global_used_resources: self.global_used_resources,
            global_unique_findings: self.global_finding_ids.len() as u64,
            global_duplicate_findings: self.global_duplicate_findings,
            stop_reason: self.stop_reason,
            shard_summaries,
            ownership_sha256: shard_hash_serializable(&ownership_material)?,
            origin_bindings_sha256: shard_hash_serializable(&origin_material)?,
            global_findings_sha256: shard_hash_serializable(&self.global_finding_ids)?,
            receipt_sha256: String::new(),
        };
        receipt.receipt_sha256 = shard_hash_serializable(&receipt)?;
        Ok(receipt)
    }

    fn ensure_running(&self) -> Result<(), ShardingError> {
        match self.stop_reason {
            Some(reason) => Err(ShardingError::RunStopped(reason)),
            None => Ok(()),
        }
    }

    fn release_reservation(
        &mut self,
        shard_id: u32,
        reservation: ShardResources,
    ) -> Result<(), ShardingError> {
        self.global_reserved_resources =
            self.global_reserved_resources.checked_sub(reservation);
        let shard = self
            .shards
            .get_mut(&shard_id)
            .ok_or(ShardingError::ShardUnknown)?;
        shard.reserved_resources = shard.reserved_resources.checked_sub(reservation);
        Ok(())
    }
}

fn resources_within(usage: ShardResources, reservation: ShardResources) -> bool {
    usage.requests <= reservation.requests
        && usage.mutations <= reservation.mutations
        && usage.accounted_memory_bytes <= reservation.accounted_memory_bytes
        && usage.evidence_bytes <= reservation.evidence_bytes
        && usage.disk_bytes <= reservation.disk_bytes
        && usage.elapsed_milliseconds <= reservation.elapsed_milliseconds
}
