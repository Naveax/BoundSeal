fn validate_sha256(value: &str, name: &str) -> Result<(), PlannerError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(PlannerError::InvalidPlan(format!(
            "{name} must be lowercase SHA-256"
        )));
    }
    Ok(())
}

fn hash_serializable<T: Serialize>(value: &T) -> String {
    match serde_json::to_vec(value) {
        Ok(bytes) => hash_bytes(&bytes),
        Err(error) => hash_bytes(error.to_string().as_bytes()),
    }
}

fn hash_bytes(bytes: &[u8]) -> String {
    lower_hex(&Sha256::digest(bytes))
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(path: &str, risk: RiskClass) -> RequestIntentPlan {
        RequestIntentPlan::new(
            format!("endpoint-{}", path.trim_matches('/').replace('/', "-")),
            Url::parse(&format!("https://app.example.com{path}")).unwrap(),
            "GET",
            BTreeSet::new(),
            "empty",
            false,
            risk,
            "a".repeat(64),
            "b".repeat(64),
            128,
            1024,
            4,
            1,
            risk != RiskClass::Forbidden,
        )
        .unwrap()
    }

    #[test]
    fn scheduler_is_bounded_fair_and_exact_once() {
        let mut queue = WorkQueue::new(SchedulerLimits {
            minimum_host_interval_milliseconds: 0,
            ..SchedulerLimits::default()
        })
        .unwrap();
        queue
            .enqueue(WorkItem {
                work_id: "work-low".into(),
                plan: plan("/low", RiskClass::Passive),
                priority: WorkPriority::Low,
                enqueued_at_milliseconds: 0,
                deadline_milliseconds: 1000,
                attempt: 0,
                session_id: None,
                account_id: None,
                tenant_id: None,
            })
            .unwrap();
        queue
            .enqueue(WorkItem {
                work_id: "work-high".into(),
                plan: plan("/high", RiskClass::SafeActive),
                priority: WorkPriority::High,
                enqueued_at_milliseconds: 1,
                deadline_milliseconds: 1000,
                attempt: 0,
                session_id: None,
                account_id: None,
                tenant_id: None,
            })
            .unwrap();
        let lease = queue.claim("worker-1", 10).unwrap().unwrap();
        assert_eq!(lease.work_id, "work-high");
        queue.complete(&lease, WorkState::Completed).unwrap();
        assert_eq!(queue.state("work-high"), Some(WorkState::Completed));
        assert_eq!(queue.complete(&lease, WorkState::Completed), Err(PlannerError::InvalidWorkState));
    }

    #[test]
    fn run_state_requires_resume_token_and_terminal_states_do_not_reopen() {
        let mut run = RunMachine::new("run-1", "a".repeat(64)).unwrap();
        run.transition(RunState::Validated, None, None).unwrap();
        run.transition(RunState::Running, Some("worker-1"), None)
            .unwrap();
        run.transition(RunState::Paused, None, Some(b"resume-secret"))
            .unwrap();
        assert!(run
            .transition(RunState::Running, Some("worker-1"), Some(b"wrong"))
            .is_err());
        run.transition(
            RunState::Running,
            Some("worker-1"),
            Some(b"resume-secret"),
        )
        .unwrap();
        run.transition(RunState::Completed, None, None).unwrap();
        assert!(run
            .transition(RunState::Running, Some("worker-1"), None)
            .is_err());
        run.audit().verify().unwrap();
    }

    #[test]
    fn capability_enforces_endpoint_secret_and_mutation_budgets() {
        let endpoint = "c".repeat(64);
        let mut capability = ProbeCapability::new(
            "cap-1",
            "module-1",
            "run-1",
            "worker-1",
            BTreeSet::from(["GET".into()]),
            BTreeSet::from([endpoint.clone()]),
            2,
            1,
            SecretAccessLevel::CookiesOnly,
            false,
            true,
            1000,
        )
        .unwrap();
        capability
            .authorize(CapabilityUseRequest {
                run_id: "run-1".into(),
                worker_id: "worker-1".into(),
                method: "GET".into(),
                endpoint_sha256: endpoint.clone(),
                mutations: 1,
                requires_secret_access: SecretAccessLevel::CookiesOnly,
                replays_body: false,
                follows_redirect: true,
                now_milliseconds: 10,
            })
            .unwrap();
        assert!(capability
            .authorize(CapabilityUseRequest {
                run_id: "run-1".into(),
                worker_id: "worker-1".into(),
                method: "GET".into(),
                endpoint_sha256: endpoint,
                mutations: 1,
                requires_secret_access: SecretAccessLevel::CookiesOnly,
                replays_body: false,
                follows_redirect: false,
                now_milliseconds: 11,
            })
            .is_err());
    }
}
