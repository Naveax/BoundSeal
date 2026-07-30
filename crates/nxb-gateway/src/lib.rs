use std::{net::IpAddr, time::Duration};

use nxb_budget::{BudgetError, RequestBudget};
use nxb_policy::{is_public_destination, CompiledPolicy};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

#[derive(Debug, Clone)]
pub struct RequestIntent {
    pub url: Url,
    pub method: String,
    pub resolved_ips: Vec<IpAddr>,
    pub redirect_depth: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DecisionOutcome {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum DecisionReason {
    Authorized,
    UrlOrMethodOutOfScope,
    MissingDnsResolution,
    NonPublicDestination { ip: IpAddr },
    RedirectLimitExceeded { maximum: u8, observed: u8 },
    TotalBudgetExhausted,
    ConcurrencyExceeded,
    RateLimited { retry_after_milliseconds: u64 },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GatewayDecision {
    pub decision_id: String,
    pub outcome: DecisionOutcome,
    pub reason: DecisionReason,
}

#[derive(Debug)]
pub struct ScopeGateway {
    policy: CompiledPolicy,
    budget: RequestBudget,
    maximum_redirects: u8,
    next_decision_id: u64,
}

#[derive(Debug, Error)]
pub enum GatewayError {
    #[error("gateway budget could not be created: {0}")]
    Budget(#[from] BudgetError),
    #[error("maximum_redirects must be greater than zero")]
    InvalidRedirectLimit,
}

impl ScopeGateway {
    pub fn new(policy: CompiledPolicy, maximum_redirects: u8) -> Result<Self, GatewayError> {
        if maximum_redirects == 0 {
            return Err(GatewayError::InvalidRedirectLimit);
        }

        // NXB-1 intentionally starts narrower than the policy maximums. Later milestones
        // will expose compiled rate/concurrency getters while retaining the no-broadening rule.
        let budget = RequestBudget::new(policy.maximum_total_requests(), 1, 1.0)?;

        Ok(Self {
            policy,
            budget,
            maximum_redirects,
            next_decision_id: 1,
        })
    }

    pub fn authorize(&mut self, intent: &RequestIntent, elapsed: Duration) -> GatewayDecision {
        let decision_id = self.allocate_decision_id();

        if intent.redirect_depth > self.maximum_redirects {
            return deny(
                decision_id,
                DecisionReason::RedirectLimitExceeded {
                    maximum: self.maximum_redirects,
                    observed: intent.redirect_depth,
                },
            );
        }

        if !self.policy.allows_request(&intent.url, &intent.method) {
            return deny(decision_id, DecisionReason::UrlOrMethodOutOfScope);
        }

        if intent.resolved_ips.is_empty() {
            return deny(decision_id, DecisionReason::MissingDnsResolution);
        }

        if let Some(ip) = intent
            .resolved_ips
            .iter()
            .copied()
            .find(|ip| !is_public_destination(*ip))
        {
            return deny(decision_id, DecisionReason::NonPublicDestination { ip });
        }

        match self.budget.try_start(elapsed) {
            Ok(()) => GatewayDecision {
                decision_id,
                outcome: DecisionOutcome::Allow,
                reason: DecisionReason::Authorized,
            },
            Err(BudgetError::Exhausted) => {
                deny(decision_id, DecisionReason::TotalBudgetExhausted)
            }
            Err(BudgetError::ConcurrencyExceeded) => {
                deny(decision_id, DecisionReason::ConcurrencyExceeded)
            }
            Err(BudgetError::RateLimited { retry_after }) => deny(
                decision_id,
                DecisionReason::RateLimited {
                    retry_after_milliseconds: duration_milliseconds_saturated(retry_after),
                },
            ),
            Err(BudgetError::InvalidConfiguration(_)) => {
                unreachable!("gateway validates its budget during construction")
            }
        }
    }

    pub fn complete_request(&mut self) {
        self.budget.finish();
    }

    pub fn remaining_requests(&self) -> u64 {
        self.budget.remaining()
    }

    fn allocate_decision_id(&mut self) -> String {
        let value = self.next_decision_id;
        self.next_decision_id = self.next_decision_id.saturating_add(1);
        format!("decision-{value:020}")
    }
}

fn deny(decision_id: String, reason: DecisionReason) -> GatewayDecision {
    GatewayDecision {
        decision_id,
        outcome: DecisionOutcome::Deny,
        reason,
    }
}

fn duration_milliseconds_saturated(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use chrono::{Duration as ChronoDuration, Utc};
    use nxb_policy::{
        AuthorizationPolicy, AutomationPolicy, ProgramPolicy, ScopePolicy, TargetPolicy,
    };

    use super::*;

    fn gateway() -> ScopeGateway {
        let policy = TargetPolicy {
            schema_version: 1,
            program: ProgramPolicy {
                name: "Example".into(),
                platform: "hackerone".into(),
                policy_url: None,
            },
            scope: ScopePolicy {
                include_hosts: BTreeSet::from(["app.example.com".into()]),
                exclude_hosts: BTreeSet::new(),
                allowed_schemes: BTreeSet::from(["https".into()]),
                allowed_methods: BTreeSet::from(["GET".into()]),
                allow_subdomains: false,
            },
            automation: AutomationPolicy {
                active_testing: false,
                credential_bruteforce: false,
                destructive_testing: false,
                oob_callbacks: false,
                max_requests_per_second: 2.0,
                max_concurrency: 2,
                max_total_requests: 3,
            },
            authorization: AuthorizationPolicy {
                confirmed: true,
                researcher: "naveax".into(),
                policy_snapshot_sha256: "a".repeat(64),
                expires_at: Utc::now() + ChronoDuration::days(1),
            },
        }
        .compile(Utc::now())
        .unwrap();

        ScopeGateway::new(policy, 5).unwrap()
    }

    fn intent(ip: &str) -> RequestIntent {
        RequestIntent {
            url: Url::parse("https://app.example.com/api/me").unwrap(),
            method: "GET".into(),
            resolved_ips: vec![ip.parse().unwrap()],
            redirect_depth: 0,
        }
    }

    #[test]
    fn allows_in_scope_public_request() {
        let mut gateway = gateway();
        let decision = gateway.authorize(&intent("8.8.8.8"), Duration::ZERO);
        assert_eq!(decision.outcome, DecisionOutcome::Allow);
        gateway.complete_request();
    }

    #[test]
    fn denies_private_destination_without_spending_budget() {
        let mut gateway = gateway();
        let decision = gateway.authorize(&intent("127.0.0.1"), Duration::ZERO);
        assert_eq!(
            decision.reason,
            DecisionReason::NonPublicDestination {
                ip: "127.0.0.1".parse().unwrap()
            }
        );
        assert_eq!(gateway.remaining_requests(), 3);
    }

    #[test]
    fn denies_scope_escape() {
        let mut gateway = gateway();
        let mut request = intent("8.8.8.8");
        request.url = Url::parse("https://outside.example.net/").unwrap();
        let decision = gateway.authorize(&request, Duration::ZERO);
        assert_eq!(decision.reason, DecisionReason::UrlOrMethodOutOfScope);
    }

    #[test]
    fn enforces_redirect_limit() {
        let mut gateway = gateway();
        let mut request = intent("8.8.8.8");
        request.redirect_depth = 6;
        let decision = gateway.authorize(&request, Duration::ZERO);
        assert!(matches!(
            decision.reason,
            DecisionReason::RedirectLimitExceeded { .. }
        ));
    }

    #[test]
    fn enforces_concurrency_before_rate() {
        let mut gateway = gateway();
        assert_eq!(
            gateway.authorize(&intent("8.8.8.8"), Duration::ZERO).outcome,
            DecisionOutcome::Allow
        );
        let second = gateway.authorize(&intent("1.1.1.1"), Duration::from_millis(10));
        assert_eq!(second.reason, DecisionReason::ConcurrencyExceeded);
    }
}
