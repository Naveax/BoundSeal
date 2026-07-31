impl CoverageTracker {
    pub fn new(
        limits: CoverageLimits,
        budget: CoverageResourceBudget,
        saturation_policy: SaturationPolicy,
    ) -> Result<Self, CoverageError> {
        let limits = limits.validate()?;
        let budget = budget.validate()?;
        let saturation_policy = saturation_policy.validate(limits.maximum_windows)?;
        Ok(Self {
            limits,
            budget,
            saturation_policy,
            admitted_endpoints: BTreeSet::new(),
            considered_endpoints: BTreeSet::new(),
            analyzed_endpoints: BTreeSet::new(),
            enabled_rules: BTreeSet::new(),
            pair_outcomes: BTreeMap::new(),
            skipped_by_reason: BTreeMap::new(),
            unique_findings: 0,
            duplicate_findings: 0,
            validated_findings: 0,
            rejected_findings: 0,
            inconclusive_findings: 0,
            resource_use: ResourceUse::default(),
            queue_telemetry: QueueTelemetry::default(),
            saturation_windows: Vec::new(),
            current_window_checks: 0,
            current_window_unique_findings: 0,
            stop_reason: None,
        })
    }

    pub fn admit_endpoint(&mut self, endpoint_sha256: &str) -> Result<bool, CoverageError> {
        self.ensure_running()?;
        validate_coverage_sha256(endpoint_sha256, "endpoint_sha256")?;
        if self.admitted_endpoints.contains(endpoint_sha256) {
            return Ok(false);
        }
        if self.admitted_endpoints.len() >= self.limits.maximum_endpoints {
            return Err(CoverageError::EndpointBudget);
        }
        let next_endpoints = self.admitted_endpoints.len().saturating_add(1);
        self.preflight_theoretical_pairs(next_endpoints, self.enabled_rules.len())?;
        self.admitted_endpoints.insert(endpoint_sha256.into());
        Ok(true)
    }

    pub fn enable_rule(&mut self, rule_id: &str) -> Result<bool, CoverageError> {
        self.ensure_running()?;
        validate_coverage_rule_id(rule_id)?;
        if self.enabled_rules.contains(rule_id) {
            return Ok(false);
        }
        if self.enabled_rules.len() >= self.limits.maximum_rules {
            return Err(CoverageError::RuleBudget);
        }
        let next_rules = self.enabled_rules.len().saturating_add(1);
        self.preflight_theoretical_pairs(self.admitted_endpoints.len(), next_rules)?;
        self.enabled_rules.insert(rule_id.into());
        Ok(true)
    }

    pub fn set_queue_telemetry(&mut self, telemetry: QueueTelemetry) -> Result<(), CoverageError> {
        self.ensure_running()?;
        self.queue_telemetry = telemetry;
        self.evaluate_saturation();
        Ok(())
    }

    pub fn record_execution(
        &mut self,
        endpoint_sha256: &str,
        rule_id: &str,
        metrics: ExecutionMetrics,
    ) -> Result<(), CoverageError> {
        self.ensure_running()?;
        let metrics = metrics.validate()?;
        let key = self.validate_pair(endpoint_sha256, rule_id)?;
        self.preflight_new_pair(&key)?;

        let next_resources = self.resource_use.checked_add(metrics.resource_delta);
        if let Some(reason) = self.budget.first_exceeded(next_resources) {
            self.stop_reason = Some(reason);
            return Err(CoverageError::ResourceBoundary(reason));
        }

        self.pair_outcomes
            .insert(key, PairOutcome::Executed { metrics });
        self.considered_endpoints.insert(endpoint_sha256.into());
        self.analyzed_endpoints.insert(endpoint_sha256.into());
        self.resource_use = next_resources;
        self.unique_findings = self.unique_findings.saturating_add(metrics.unique_findings);
        self.duplicate_findings = self
            .duplicate_findings
            .saturating_add(metrics.duplicate_findings);
        self.validated_findings = self
            .validated_findings
            .saturating_add(metrics.validated_findings);
        self.rejected_findings = self
            .rejected_findings
            .saturating_add(metrics.rejected_findings);
        self.inconclusive_findings = self
            .inconclusive_findings
            .saturating_add(metrics.inconclusive_findings);

        self.current_window_checks = self.current_window_checks.saturating_add(1);
        self.current_window_unique_findings = self
            .current_window_unique_findings
            .saturating_add(metrics.unique_findings);
        if self.current_window_checks == self.saturation_policy.checks_per_window {
            self.close_saturation_window()?;
        }
        self.evaluate_saturation();
        Ok(())
    }

    pub fn record_skip(
        &mut self,
        endpoint_sha256: &str,
        rule_id: &str,
        reason: PairSkipReason,
    ) -> Result<(), CoverageError> {
        self.ensure_running()?;
        let key = self.validate_pair(endpoint_sha256, rule_id)?;
        self.preflight_new_pair(&key)?;
        self.pair_outcomes.insert(key, PairOutcome::Skipped { reason });
        self.considered_endpoints.insert(endpoint_sha256.into());
        *self.skipped_by_reason.entry(reason).or_insert(0) = self
            .skipped_by_reason
            .get(&reason)
            .copied()
            .unwrap_or(0)
            .saturating_add(1);
        Ok(())
    }

    pub fn mark_completed(&mut self) -> Result<(), CoverageError> {
        self.ensure_running()?;
        let theoretical = self.theoretical_pairs();
        if theoretical == 0
            || self.pair_outcomes.len() as u64 != theoretical
            || self.queue_telemetry.validation_queue != 0
            || self.queue_telemetry.cleanup_queue != 0
        {
            return Err(CoverageError::IncompleteCoverage);
        }
        self.stop_reason = Some(RunStopReason::Completed);
        Ok(())
    }

    pub fn cancel(&mut self) -> Result<(), CoverageError> {
        self.ensure_running()?;
        self.stop_reason = Some(RunStopReason::Cancelled);
        Ok(())
    }

    pub fn emergency_stop(&mut self) -> Result<(), CoverageError> {
        self.ensure_running()?;
        self.stop_reason = Some(RunStopReason::EmergencyStop);
        Ok(())
    }

    pub fn stop_reason(&self) -> Option<RunStopReason> {
        self.stop_reason
    }

    pub fn theoretical_pairs(&self) -> u64 {
        (self.admitted_endpoints.len() as u64)
            .saturating_mul(self.enabled_rules.len() as u64)
    }

    pub fn receipt(&self) -> Result<CoverageReceipt, CoverageError> {
        let theoretical_pairs = self.theoretical_pairs();
        let recorded_pairs = self.pair_outcomes.len() as u64;
        let executed_pairs = self
            .pair_outcomes
            .values()
            .filter(|outcome| matches!(outcome, PairOutcome::Executed { .. }))
            .count() as u64;
        let skipped_pairs = recorded_pairs.saturating_sub(executed_pairs);
        let untested_endpoints = (self.admitted_endpoints.len() as u64)
            .saturating_sub(self.considered_endpoints.len() as u64);
        let mut receipt = CoverageReceipt {
            admitted_endpoints: self.admitted_endpoints.len() as u64,
            considered_endpoints: self.considered_endpoints.len() as u64,
            analyzed_endpoints: self.analyzed_endpoints.len() as u64,
            untested_endpoints,
            enabled_rules: self.enabled_rules.len() as u64,
            theoretical_pairs,
            recorded_pairs,
            untested_pairs: theoretical_pairs.saturating_sub(recorded_pairs),
            executed_pairs,
            skipped_pairs,
            skipped_by_reason: self.skipped_by_reason.clone(),
            unique_findings: self.unique_findings,
            duplicate_findings: self.duplicate_findings,
            validated_findings: self.validated_findings,
            rejected_findings: self.rejected_findings,
            inconclusive_findings: self.inconclusive_findings,
            resource_use: self.resource_use,
            queue_telemetry: self.queue_telemetry,
            saturation_windows: self.saturation_windows.clone(),
            stop_reason: self.stop_reason,
            endpoint_set_sha256: coverage_hash_serializable(&self.admitted_endpoints)?,
            rule_set_sha256: coverage_hash_serializable(&self.enabled_rules)?,
            pair_outcomes_sha256: coverage_hash_serializable(&self.pair_outcomes)?,
            receipt_sha256: String::new(),
        };
        receipt.receipt_sha256 = coverage_hash_serializable(&receipt)?;
        Ok(receipt)
    }

    fn ensure_running(&self) -> Result<(), CoverageError> {
        if self.stop_reason.is_some() {
            Err(CoverageError::RunStopped)
        } else {
            Ok(())
        }
    }

    fn validate_pair(
        &self,
        endpoint_sha256: &str,
        rule_id: &str,
    ) -> Result<PairKey, CoverageError> {
        let key = PairKey::new(endpoint_sha256, rule_id)?;
        if !self.admitted_endpoints.contains(endpoint_sha256) {
            return Err(CoverageError::EndpointNotAdmitted);
        }
        if !self.enabled_rules.contains(rule_id) {
            return Err(CoverageError::RuleNotEnabled);
        }
        Ok(key)
    }

    fn preflight_new_pair(&self, key: &PairKey) -> Result<(), CoverageError> {
        if self.pair_outcomes.contains_key(key) {
            return Err(CoverageError::PairAlreadyRecorded);
        }
        if self.pair_outcomes.len() >= self.limits.maximum_recorded_pairs {
            return Err(CoverageError::PairBudget);
        }
        Ok(())
    }

    fn preflight_theoretical_pairs(
        &self,
        endpoints: usize,
        rules: usize,
    ) -> Result<(), CoverageError> {
        let pairs = endpoints.saturating_mul(rules);
        if pairs > self.limits.maximum_recorded_pairs {
            return Err(CoverageError::PairBudget);
        }
        Ok(())
    }

    fn close_saturation_window(&mut self) -> Result<(), CoverageError> {
        if self.saturation_windows.len() >= self.limits.maximum_windows {
            return Err(CoverageError::InvalidConfig(
                "saturation window budget was exhausted".into(),
            ));
        }
        let left = u128::from(self.current_window_unique_findings)
            .saturating_mul(u128::from(
                self.saturation_policy.yield_threshold_denominator,
            ));
        let right = u128::from(self.current_window_checks).saturating_mul(u128::from(
            self.saturation_policy.yield_threshold_numerator,
        ));
        self.saturation_windows.push(SaturationWindow {
            completed_checks: self.current_window_checks,
            new_unique_findings: self.current_window_unique_findings,
            below_yield_threshold: left < right,
        });
        self.current_window_checks = 0;
        self.current_window_unique_findings = 0;
        Ok(())
    }

    fn evaluate_saturation(&mut self) {
        if self.stop_reason.is_some()
            || self.queue_telemetry.high_priority_unexplored_pairs != 0
            || self.queue_telemetry.validation_queue != 0
            || self.queue_telemetry.cleanup_queue != 0
        {
            return;
        }
        let completed_checks = self
            .saturation_windows
            .iter()
            .fold(0_u64, |sum, window| sum.saturating_add(window.completed_checks));
        let required = self
            .saturation_policy
            .required_consecutive_low_yield_windows;
        if completed_checks < self.saturation_policy.minimum_completed_checks
            || self.saturation_windows.len() < required
        {
            return;
        }
        if self
            .saturation_windows
            .iter()
            .rev()
            .take(required)
            .all(|window| window.below_yield_threshold)
        {
            self.stop_reason = Some(RunStopReason::Saturated);
        }
    }
}
