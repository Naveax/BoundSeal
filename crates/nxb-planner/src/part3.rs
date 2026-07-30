impl WorkQueue {
    pub fn new(limits: SchedulerLimits) -> Result<Self, PlannerError> {
        Ok(Self {
            limits: limits.validate()?,
            items: BTreeMap::new(),
            order: VecDeque::new(),
            dedup: BTreeSet::new(),
            host_in_flight: BTreeMap::new(),
            last_host_start: BTreeMap::new(),
            global_in_flight: 0,
            next_lease_id: 1,
            cancelled: false,
            emergency_stopped: false,
        })
    }

    pub fn enqueue(&mut self, item: WorkItem) -> Result<(), PlannerError> {
        if self.items.len() >= self.limits.maximum_queue_items {
            return Err(PlannerError::QueueFull);
        }
        item.validate()?;
        if self.items.contains_key(&item.work_id) || !self.dedup.insert(item.dedup_key()) {
            return Err(PlannerError::DuplicateWorkItem);
        }
        let work_id = item.work_id.clone();
        self.items.insert(
            work_id.clone(),
            StoredWork {
                item,
                state: WorkState::Queued,
                lease_id: None,
            },
        );
        self.order.push_back(work_id);
        self.reorder();
        Ok(())
    }

    pub fn claim(
        &mut self,
        worker_id: &str,
        now_milliseconds: u64,
    ) -> Result<Option<WorkLease>, PlannerError> {
        validate_identifier(worker_id, "worker_id")?;
        if self.cancelled || self.emergency_stopped {
            return Ok(None);
        }
        if self.global_in_flight >= self.limits.maximum_global_concurrency {
            return Ok(None);
        }
        let mut selected = None;
        for work_id in &self.order {
            let Some(stored) = self.items.get(work_id) else {
                continue;
            };
            if stored.state != WorkState::Queued {
                continue;
            }
            if now_milliseconds >= stored.item.deadline_milliseconds {
                continue;
            }
            let origin = &stored.item.plan.origin;
            if self.host_in_flight.get(origin).copied().unwrap_or(0)
                >= self.limits.maximum_host_concurrency
            {
                continue;
            }
            if self
                .last_host_start
                .get(origin)
                .is_some_and(|last| {
                    now_milliseconds.saturating_sub(*last)
                        < self.limits.minimum_host_interval_milliseconds
                })
            {
                continue;
            }
            selected = Some(work_id.clone());
            break;
        }
        self.expire_queued(now_milliseconds);
        let Some(work_id) = selected else {
            return Ok(None);
        };
        let stored = self
            .items
            .get_mut(&work_id)
            .ok_or(PlannerError::UnknownWorkItem)?;
        let lease_id = format!("work-lease-{:020}", self.next_lease_id);
        self.next_lease_id = self.next_lease_id.saturating_add(1);
        stored.state = WorkState::Running;
        stored.lease_id = Some(lease_id.clone());
        self.global_in_flight = self.global_in_flight.saturating_add(1);
        *self
            .host_in_flight
            .entry(stored.item.plan.origin.clone())
            .or_default() += 1;
        self.last_host_start
            .insert(stored.item.plan.origin.clone(), now_milliseconds);
        Ok(Some(WorkLease {
            lease_id,
            work_id,
            worker_id: worker_id.into(),
            origin: stored.item.plan.origin.clone(),
            claimed_at_milliseconds: now_milliseconds,
            deadline_milliseconds: stored.item.deadline_milliseconds,
            plan_fingerprint: stored.item.plan.fingerprint(),
        }))
    }

    pub fn complete(
        &mut self,
        lease: &WorkLease,
        terminal_state: WorkState,
    ) -> Result<(), PlannerError> {
        if !matches!(terminal_state, WorkState::Completed | WorkState::Failed | WorkState::Cancelled)
        {
            return Err(PlannerError::InvalidWorkState);
        }
        let stored = self
            .items
            .get_mut(&lease.work_id)
            .ok_or(PlannerError::UnknownWorkItem)?;
        if stored.state != WorkState::Running || stored.lease_id.as_deref() != Some(&lease.lease_id) {
            return Err(PlannerError::InvalidWorkState);
        }
        stored.state = terminal_state;
        stored.lease_id = None;
        self.global_in_flight = self.global_in_flight.saturating_sub(1);
        if let Some(value) = self.host_in_flight.get_mut(&stored.item.plan.origin) {
            *value = value.saturating_sub(1);
        }
        Ok(())
    }

    pub fn cancel(&mut self) {
        self.cancelled = true;
        for stored in self.items.values_mut() {
            if stored.state == WorkState::Queued {
                stored.state = WorkState::Cancelled;
            }
        }
    }

    pub fn emergency_stop(&mut self) {
        self.emergency_stopped = true;
        for stored in self.items.values_mut() {
            if matches!(stored.state, WorkState::Queued | WorkState::Running) {
                stored.state = WorkState::Cancelled;
                stored.lease_id = None;
            }
        }
        self.global_in_flight = 0;
        self.host_in_flight.clear();
    }

    pub fn state(&self, work_id: &str) -> Option<WorkState> {
        self.items.get(work_id).map(|stored| stored.state)
    }

    pub fn queued_count(&self) -> usize {
        self.items
            .values()
            .filter(|stored| stored.state == WorkState::Queued)
            .count()
    }

    pub fn in_flight(&self) -> u16 {
        self.global_in_flight
    }

    fn reorder(&mut self) {
        let mut ids = self.order.drain(..).collect::<Vec<_>>();
        ids.sort_by_key(|id| {
            let stored = &self.items[id];
            (
                stored.item.priority.rank(),
                stored.item.enqueued_at_milliseconds,
                stored.item.work_id.clone(),
            )
        });
        self.order = ids.into();
    }

    fn expire_queued(&mut self, now_milliseconds: u64) {
        for stored in self.items.values_mut() {
            if stored.state == WorkState::Queued && now_milliseconds >= stored.item.deadline_milliseconds
            {
                stored.state = WorkState::Expired;
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RunState {
    Created,
    Validated,
    Running,
    Paused,
    Cancelling,
    Completed,
    Failed,
    EmergencyStopped,
}

impl RunState {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Failed | Self::EmergencyStopped
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunSnapshot {
    pub run_id: String,
    pub policy_snapshot_sha256: String,
    pub state: RunState,
    pub generation: u64,
    pub owner_worker_id: Option<String>,
    pub resume_token_sha256: Option<String>,
    pub audit_tail: String,
}

#[derive(Debug)]
pub struct RunMachine {
    snapshot: RunSnapshot,
    audit: PlannerAuditChain,
}

