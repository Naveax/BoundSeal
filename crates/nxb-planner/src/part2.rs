impl WorkItem {
    pub fn validate(&self) -> Result<(), PlannerError> {
        validate_identifier(&self.work_id, "work_id")?;
        if self.deadline_milliseconds <= self.enqueued_at_milliseconds {
            return Err(PlannerError::InvalidPlan(
                "work deadline must follow enqueue time".into(),
            ));
        }
        if self.attempt > self.plan.retry_budget {
            return Err(PlannerError::InvalidPlan(
                "work attempt exceeds plan retry budget".into(),
            ));
        }
        if self.plan.session_required
            && (self.session_id.is_none()
                || self.account_id.is_none()
                || self.tenant_id.is_none())
        {
            return Err(PlannerError::InvalidPlan(
                "session-bound work requires session, account and tenant identity".into(),
            ));
        }
        Ok(())
    }

    pub fn dedup_key(&self) -> String {
        hash_serializable(&(
            self.plan.fingerprint(),
            &self.session_id,
            &self.account_id,
            &self.tenant_id,
        ))
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct SchedulerLimits {
    pub maximum_queue_items: usize,
    pub maximum_global_concurrency: u16,
    pub maximum_host_concurrency: u16,
    pub minimum_host_interval_milliseconds: u64,
}

impl Default for SchedulerLimits {
    fn default() -> Self {
        Self {
            maximum_queue_items: 10_000,
            maximum_global_concurrency: 8,
            maximum_host_concurrency: 2,
            minimum_host_interval_milliseconds: 200,
        }
    }
}

impl SchedulerLimits {
    fn validate(self) -> Result<Self, PlannerError> {
        if self.maximum_queue_items == 0 || self.maximum_queue_items > MAX_QUEUE_ITEMS {
            return Err(PlannerError::InvalidSchedulerLimits(
                "queue item limit".into(),
            ));
        }
        if self.maximum_global_concurrency == 0
            || self.maximum_global_concurrency > MAX_GLOBAL_CONCURRENCY
            || self.maximum_host_concurrency == 0
            || self.maximum_host_concurrency > MAX_HOST_CONCURRENCY
            || self.maximum_host_concurrency > self.maximum_global_concurrency
        {
            return Err(PlannerError::InvalidSchedulerLimits(
                "concurrency limits".into(),
            ));
        }
        if self.minimum_host_interval_milliseconds > 60_000 {
            return Err(PlannerError::InvalidSchedulerLimits(
                "host interval".into(),
            ));
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkState {
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkLease {
    pub lease_id: String,
    pub work_id: String,
    pub worker_id: String,
    pub origin: String,
    pub claimed_at_milliseconds: u64,
    pub deadline_milliseconds: u64,
    pub plan_fingerprint: String,
}

#[derive(Debug, Clone)]
struct StoredWork {
    item: WorkItem,
    state: WorkState,
    lease_id: Option<String>,
}

#[derive(Debug)]
pub struct WorkQueue {
    limits: SchedulerLimits,
    items: BTreeMap<String, StoredWork>,
    order: VecDeque<String>,
    dedup: BTreeSet<String>,
    host_in_flight: BTreeMap<String, u16>,
    last_host_start: BTreeMap<String, u64>,
    global_in_flight: u16,
    next_lease_id: u64,
    cancelled: bool,
    emergency_stopped: bool,
}

