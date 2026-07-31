#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkflowStep {
    pub step_id: String,
    pub action: WorkflowAction,
    pub dependencies: BTreeSet<String>,
    pub capability_id: Option<String>,
    pub request_cost: u64,
    pub mutation_cost: u64,
    pub creates_owned_object: bool,
    pub compensation_step_id: Option<String>,
}

impl WorkflowStep {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        step_id: impl Into<String>,
        action: WorkflowAction,
        dependencies: BTreeSet<String>,
        capability_id: Option<String>,
        request_cost: u64,
        mutation_cost: u64,
        creates_owned_object: bool,
        compensation_step_id: Option<String>,
    ) -> Result<Self, WorkflowError> {
        let step_id = step_id.into();
        validate_identifier(&step_id, "step_id")?;
        if dependencies.len() > MAX_STEP_DEPENDENCIES
            || dependencies.contains(&step_id)
            || dependencies
                .iter()
                .any(|dependency| validate_identifier(dependency, "dependency").is_err())
            || capability_id
                .as_deref()
                .is_some_and(|value| validate_identifier(value, "capability_id").is_err())
            || compensation_step_id
                .as_deref()
                .is_some_and(|value| validate_identifier(value, "compensation_step_id").is_err())
            || request_cost > 100_000
            || mutation_cost > 10_000
        {
            return Err(WorkflowError::InvalidWorkflow("step bounds".into()));
        }
        if matches!(
            action,
            WorkflowAction::GenerateInertMutation
                | WorkflowAction::RegisterOwnedObject
                | WorkflowAction::CleanupOwnedObject
        ) && capability_id.is_none()
        {
            return Err(WorkflowError::InvalidWorkflow(
                "active or cleanup steps require a capability".into(),
            ));
        }
        if mutation_cost > 0 && action != WorkflowAction::GenerateInertMutation {
            return Err(WorkflowError::InvalidWorkflow(
                "only inert-mutation steps may consume mutation budget".into(),
            ));
        }
        if creates_owned_object && action != WorkflowAction::RegisterOwnedObject {
            return Err(WorkflowError::InvalidWorkflow(
                "owned objects must be registered by a dedicated step".into(),
            ));
        }
        Ok(Self {
            step_id,
            action,
            dependencies,
            capability_id,
            request_cost,
            mutation_cost,
            creates_owned_object,
            compensation_step_id,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkflowDefinition {
    pub workflow_id: String,
    pub run_id: String,
    pub policy_snapshot_sha256: String,
    pub steps: BTreeMap<String, WorkflowStep>,
    pub topological_order: Vec<String>,
    pub total_request_budget: u64,
    pub total_mutation_budget: u64,
    pub definition_sha256: String,
}

impl WorkflowDefinition {
    pub fn new(
        workflow_id: impl Into<String>,
        run_id: impl Into<String>,
        policy_snapshot_sha256: impl Into<String>,
        steps: Vec<WorkflowStep>,
    ) -> Result<Self, WorkflowError> {
        let workflow_id = workflow_id.into();
        let run_id = run_id.into();
        validate_identifier(&workflow_id, "workflow_id")?;
        validate_identifier(&run_id, "run_id")?;
        let policy_snapshot_sha256 = policy_snapshot_sha256.into();
        validate_sha256(&policy_snapshot_sha256, "workflow policy snapshot")?;
        if steps.is_empty() || steps.len() > MAX_WORKFLOW_STEPS {
            return Err(WorkflowError::InvalidWorkflow("step count".into()));
        }
        let mut step_map = BTreeMap::new();
        for step in steps {
            if step_map.insert(step.step_id.clone(), step).is_some() {
                return Err(WorkflowError::InvalidWorkflow(
                    "duplicate step identifier".into(),
                ));
            }
        }
        for step in step_map.values() {
            if step
                .dependencies
                .iter()
                .any(|dependency| !step_map.contains_key(dependency))
            {
                return Err(WorkflowError::InvalidWorkflow(
                    "unknown dependency".into(),
                ));
            }
            if let Some(compensation_step_id) = &step.compensation_step_id {
                let compensation = step_map.get(compensation_step_id).ok_or_else(|| {
                    WorkflowError::InvalidWorkflow("unknown compensation step".into())
                })?;
                if compensation.action != WorkflowAction::CleanupOwnedObject
                    || compensation_step_id == &step.step_id
                {
                    return Err(WorkflowError::InvalidWorkflow(
                        "compensation must reference a cleanup step".into(),
                    ));
                }
            }
        }
        let topological_order = topological_sort(&step_map)?;
        let total_request_budget = step_map.values().try_fold(0u64, |total, step| {
            total
                .checked_add(step.request_cost)
                .ok_or_else(|| WorkflowError::InvalidWorkflow("request budget overflow".into()))
        })?;
        let total_mutation_budget = step_map.values().try_fold(0u64, |total, step| {
            total
                .checked_add(step.mutation_cost)
                .ok_or_else(|| WorkflowError::InvalidWorkflow("mutation budget overflow".into()))
        })?;
        if total_request_budget > 1_000_000 || total_mutation_budget > 100_000 {
            return Err(WorkflowError::InvalidWorkflow(
                "workflow aggregate budget".into(),
            ));
        }
        let definition_sha256 = hash_serializable(&(
            &workflow_id,
            &run_id,
            &policy_snapshot_sha256,
            &step_map,
            &topological_order,
            total_request_budget,
            total_mutation_budget,
        ))?;
        Ok(Self {
            workflow_id,
            run_id,
            policy_snapshot_sha256,
            steps: step_map,
            topological_order,
            total_request_budget,
            total_mutation_budget,
            definition_sha256,
        })
    }
}

fn topological_sort(
    steps: &BTreeMap<String, WorkflowStep>,
) -> Result<Vec<String>, WorkflowError> {
    let mut indegree = steps
        .iter()
        .map(|(step_id, step)| (step_id.clone(), step.dependencies.len()))
        .collect::<BTreeMap<_, _>>();
    let mut dependents = BTreeMap::<String, BTreeSet<String>>::new();
    for (step_id, step) in steps {
        for dependency in &step.dependencies {
            dependents
                .entry(dependency.clone())
                .or_default()
                .insert(step_id.clone());
        }
    }
    let mut ready = indegree
        .iter()
        .filter_map(|(step_id, count)| (*count == 0).then_some(step_id.clone()))
        .collect::<BTreeSet<_>>();
    let mut order = Vec::with_capacity(steps.len());
    while let Some(step_id) = ready.pop_first() {
        order.push(step_id.clone());
        for dependent in dependents.get(&step_id).into_iter().flatten() {
            let count = indegree.get_mut(dependent).expect("workflow indegree");
            *count = count.saturating_sub(1);
            if *count == 0 {
                ready.insert(dependent.clone());
            }
        }
    }
    if order.len() != steps.len() {
        return Err(WorkflowError::InvalidWorkflow(
            "workflow dependency cycle".into(),
        ));
    }
    Ok(order)
}
