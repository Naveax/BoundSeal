impl AdaptiveRuleScheduler {
    pub fn new(limits: SchedulerLimits) -> Result<Self, SchedulerError> {
        Ok(Self {
            limits: limits.validate()?,
            profiles: BTreeMap::new(),
            metrics: BTreeMap::new(),
            queued: BTreeMap::new(),
            in_flight: BTreeMap::new(),
            known_pairs: BTreeSet::new(),
            completed_pairs: BTreeSet::new(),
            failed_pairs: BTreeMap::new(),
            expired_pairs: BTreeSet::new(),
            outstanding_request_reservations: 0,
            outstanding_mutation_reservations: 0,
            next_lease_sequence: 1,
            stop_reason: None,
        })
    }

    pub fn register_rule(&mut self, profile: RuleProfile) -> Result<bool, SchedulerError> {
        self.ensure_running()?;
        profile.validate()?;
        if let Some(existing) = self.profiles.get(&profile.rule_id) {
            if existing == &profile {
                return Ok(false);
            }
            return Err(SchedulerError::InvalidInput(
                "rule profile cannot change after registration".into(),
            ));
        }
        if self.profiles.len() >= self.limits.maximum_rules {
            return Err(SchedulerError::QueueBudget);
        }
        self.metrics
            .insert(profile.rule_id.clone(), RuleMetrics::default());
        self.profiles.insert(profile.rule_id.clone(), profile);
        Ok(true)
    }

    pub fn enqueue(
        &mut self,
        item: AuthorizedWorkItem,
        now_epoch_seconds: i64,
    ) -> Result<(), SchedulerError> {
        self.ensure_running()?;
        item.validate()?;
        if !self.profiles.contains_key(&item.pair.rule_id) {
            return Err(SchedulerError::RuleUnknown);
        }
        if item.authorization_expires_at_epoch_seconds <= now_epoch_seconds {
            return Err(SchedulerError::AuthorizationExpired);
        }
        if self.known_pairs.contains(&item.pair) {
            return Err(SchedulerError::PairDuplicate);
        }
        if self.known_pairs.len() >= self.limits.maximum_known_pairs
            || self.queued.len() >= self.limits.maximum_queued_pairs
        {
            return Err(SchedulerError::QueueBudget);
        }

        let next_requests = self
            .outstanding_request_reservations
            .saturating_add(item.estimated_requests);
        if next_requests > self.limits.maximum_outstanding_request_reservations {
            return Err(SchedulerError::RequestReservationBudget);
        }
        let next_mutations = self
            .outstanding_mutation_reservations
            .saturating_add(item.estimated_mutations);
        if next_mutations > self.limits.maximum_outstanding_mutation_reservations {
            return Err(SchedulerError::MutationReservationBudget);
        }

        self.outstanding_request_reservations = next_requests;
        self.outstanding_mutation_reservations = next_mutations;
        self.known_pairs.insert(item.pair.clone());
        self.queued.insert(item.pair.clone(), item);
        Ok(())
    }

    pub fn ranking_snapshot(
        &self,
        now_epoch_seconds: i64,
    ) -> Result<Vec<RankedWorkItem>, SchedulerError> {
        self.ensure_running()?;
        let mut ranked = self
            .queued
            .values()
            .filter(|item| item.authorization_expires_at_epoch_seconds > now_epoch_seconds)
            .map(|item| {
                Ok(RankedWorkItem {
                    pair: item.pair.clone(),
                    score: self.score_item(item)?,
                    authorization_sha256: item.authorization_sha256.clone(),
                })
            })
            .collect::<Result<Vec<_>, SchedulerError>>()?;
        ranked.sort_by(|left, right| {
            right
                .score
                .fixed_point_score
                .cmp(&left.score.fixed_point_score)
                .then_with(|| left.pair.cmp(&right.pair))
                .then_with(|| left.authorization_sha256.cmp(&right.authorization_sha256))
        });
        Ok(ranked)
    }

    pub fn lease_next(
        &mut self,
        now_epoch_seconds: i64,
    ) -> Result<ScheduleLease, SchedulerError> {
        self.ensure_running()?;
        self.expire_authorizations(now_epoch_seconds);
        self.expire_leases(now_epoch_seconds);
        if self.in_flight.len() >= self.limits.maximum_in_flight {
            return Err(SchedulerError::InFlightBudget);
        }
        let ranked = self.ranking_snapshot(now_epoch_seconds)?;
        let selected = ranked.first().ok_or(SchedulerError::NoWork)?;
        let item = self
            .queued
            .remove(&selected.pair)
            .ok_or(SchedulerError::NoWork)?;
        let expires_at_epoch_seconds = item
            .authorization_expires_at_epoch_seconds
            .min(now_epoch_seconds.saturating_add(self.limits.lease_seconds));
        if expires_at_epoch_seconds <= now_epoch_seconds {
            self.release_reservations(&item);
            self.expired_pairs.insert(item.pair);
            return Err(SchedulerError::AuthorizationExpired);
        }
        let sequence = self.next_lease_sequence;
        self.next_lease_sequence = self.next_lease_sequence.saturating_add(1);
        let lease_hash = scheduler_hash_serializable(&(
            sequence,
            &item.pair,
            &item.authorization_sha256,
            now_epoch_seconds,
            expires_at_epoch_seconds,
        ))?;
        let lease_id = format!("lease-{sequence:020}-{}", &lease_hash[..16]);
        let score = selected.score;
        self.in_flight.insert(
            lease_id.clone(),
            LeaseState {
                item: item.clone(),
                score,
                expires_at_epoch_seconds,
            },
        );
        Ok(ScheduleLease {
            lease_id,
            pair: item.pair,
            plan_sha256: item.plan_sha256,
            capability_sha256: item.capability_sha256,
            authorization_sha256: item.authorization_sha256,
            score,
            issued_at_epoch_seconds: now_epoch_seconds,
            expires_at_epoch_seconds,
        })
    }

    pub fn complete_lease(
        &mut self,
        lease_id: &str,
        observation: RuleObservation,
        now_epoch_seconds: i64,
    ) -> Result<(), SchedulerError> {
        self.ensure_running()?;
        let observation = observation.validate()?;
        let state = self
            .in_flight
            .remove(lease_id)
            .ok_or(SchedulerError::LeaseUnknown)?;
        if now_epoch_seconds >= state.expires_at_epoch_seconds {
            self.release_reservations(&state.item);
            self.expired_pairs.insert(state.item.pair);
            return Err(SchedulerError::LeaseExpired);
        }
        self.release_reservations(&state.item);
        self.metrics
            .get_mut(&state.item.pair.rule_id)
            .ok_or(SchedulerError::RuleUnknown)?
            .apply(observation);
        self.completed_pairs.insert(state.item.pair);
        Ok(())
    }

    pub fn fail_lease(
        &mut self,
        lease_id: &str,
        reason: WorkFailureReason,
        now_epoch_seconds: i64,
    ) -> Result<(), SchedulerError> {
        self.ensure_running()?;
        let state = self
            .in_flight
            .remove(lease_id)
            .ok_or(SchedulerError::LeaseUnknown)?;
        self.release_reservations(&state.item);
        if now_epoch_seconds >= state.expires_at_epoch_seconds {
            self.expired_pairs.insert(state.item.pair);
            return Err(SchedulerError::LeaseExpired);
        }
        self.failed_pairs.insert(state.item.pair, reason);
        Ok(())
    }

    pub fn expire_authorizations(&mut self, now_epoch_seconds: i64) -> Vec<PairKey> {
        let expired = self
            .queued
            .iter()
            .filter(|(_, item)| item.authorization_expires_at_epoch_seconds <= now_epoch_seconds)
            .map(|(pair, _)| pair.clone())
            .collect::<Vec<_>>();
        for pair in &expired {
            if let Some(item) = self.queued.remove(pair) {
                self.release_reservations(&item);
                self.expired_pairs.insert(pair.clone());
            }
        }
        expired
    }

    pub fn expire_leases(&mut self, now_epoch_seconds: i64) -> Vec<String> {
        let expired = self
            .in_flight
            .iter()
            .filter(|(_, state)| state.expires_at_epoch_seconds <= now_epoch_seconds)
            .map(|(lease_id, _)| lease_id.clone())
            .collect::<Vec<_>>();
        for lease_id in &expired {
            if let Some(state) = self.in_flight.remove(lease_id) {
                self.release_reservations(&state.item);
                self.expired_pairs.insert(state.item.pair);
            }
        }
        expired
    }

    pub fn apply_run_stop(&mut self, reason: RunStopReason) -> Result<(), SchedulerError> {
        self.ensure_running()?;
        self.stop_reason = Some(reason);
        Ok(())
    }

    pub fn metrics(&self, rule_id: &str) -> Option<RuleMetrics> {
        self.metrics.get(rule_id).copied()
    }

    pub fn receipt(&self) -> Result<SchedulerReceipt, SchedulerError> {
        let queue_material = self.queued.iter().collect::<Vec<_>>();
        let in_flight_material = self
            .in_flight
            .iter()
            .map(|(lease_id, state)| {
                (
                    lease_id,
                    &state.item,
                    state.score,
                    state.expires_at_epoch_seconds,
                )
            })
            .collect::<Vec<_>>();
        let failed_material = self.failed_pairs.iter().collect::<Vec<_>>();
        let terminal_material = (
            &self.completed_pairs,
            failed_material,
            &self.expired_pairs,
        );
        let mut receipt = SchedulerReceipt {
            registered_rules: self.profiles.len() as u64,
            known_pairs: self.known_pairs.len() as u64,
            queued_pairs: self.queued.len() as u64,
            in_flight_pairs: self.in_flight.len() as u64,
            completed_pairs: self.completed_pairs.len() as u64,
            failed_pairs: self.failed_pairs.len() as u64,
            expired_authorizations: self.expired_pairs.len() as u64,
            outstanding_request_reservations: self.outstanding_request_reservations,
            outstanding_mutation_reservations: self.outstanding_mutation_reservations,
            stop_reason: self.stop_reason,
            profiles_sha256: scheduler_hash_serializable(&self.profiles)?,
            metrics_sha256: scheduler_hash_serializable(&self.metrics)?,
            queue_sha256: scheduler_hash_serializable(&queue_material)?,
            in_flight_sha256: scheduler_hash_serializable(&in_flight_material)?,
            terminal_pairs_sha256: scheduler_hash_serializable(&terminal_material)?,
            receipt_sha256: String::new(),
        };
        receipt.receipt_sha256 = scheduler_hash_serializable(&receipt)?;
        Ok(receipt)
    }

    fn ensure_running(&self) -> Result<(), SchedulerError> {
        match self.stop_reason {
            Some(reason) => Err(SchedulerError::RunStopped(reason)),
            None => Ok(()),
        }
    }

    fn score_item(&self, item: &AuthorizedWorkItem) -> Result<RuleScore, SchedulerError> {
        let profile = self
            .profiles
            .get(&item.pair.rule_id)
            .ok_or(SchedulerError::RuleUnknown)?;
        let metrics = self
            .metrics
            .get(&item.pair.rule_id)
            .copied()
            .unwrap_or_default();
        let classified = metrics
            .validated_findings
            .saturating_add(metrics.rejected_findings)
            .saturating_add(metrics.inconclusive_findings);
        let unclassified = metrics.unique_findings.saturating_sub(classified);
        let useful_reward_units = 1_u64
            .saturating_add(metrics.validated_findings.saturating_mul(4))
            .saturating_add(unclassified.saturating_mul(2))
            .saturating_add(metrics.inconclusive_findings);
        let penalty_units = 1_u64
            .saturating_add(metrics.rejected_findings.saturating_mul(4))
            .saturating_add(metrics.duplicate_findings);
        let accounted_cost_units = profile
            .minimum_cost_units
            .saturating_add(metrics.cost_units)
            .saturating_add(item.estimated_cost_units);
        let exploration_numerator = metrics.completed_checks.saturating_add(4);
        let exploration_denominator = metrics.completed_checks.saturating_add(1);

        let numerator = u128::from(useful_reward_units)
            .saturating_mul(u128::from(profile.severity_weight))
            .saturating_mul(u128::from(profile.confidence_weight))
            .saturating_mul(u128::from(profile.base_priority_weight))
            .saturating_mul(u128::from(item.item_priority_weight))
            .saturating_mul(u128::from(exploration_numerator))
            .saturating_mul(SCHEDULER_SCORE_SCALE);
        let denominator = u128::from(penalty_units)
            .saturating_mul(u128::from(accounted_cost_units.max(1)))
            .saturating_mul(u128::from(exploration_denominator));
        let fixed = numerator / denominator.max(1);
        Ok(RuleScore {
            fixed_point_score: u64::try_from(fixed).unwrap_or(u64::MAX),
            useful_reward_units,
            penalty_units,
            accounted_cost_units,
            exploration_numerator,
            exploration_denominator,
        })
    }

    fn release_reservations(&mut self, item: &AuthorizedWorkItem) {
        self.outstanding_request_reservations = self
            .outstanding_request_reservations
            .saturating_sub(item.estimated_requests);
        self.outstanding_mutation_reservations = self
            .outstanding_mutation_reservations
            .saturating_sub(item.estimated_mutations);
    }
}
