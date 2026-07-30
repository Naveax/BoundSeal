use std::{collections::BTreeMap, net::IpAddr, time::Duration};

use nxb_audit::{AuditChain, AuditDestination, AuditError, AuditEvent};
use nxb_budget::{BudgetError, RequestBudget};
use nxb_destination::{assess_destination, DestinationAssessment, DestinationClass};
use nxb_policy::CompiledPolicy;
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

impl DecisionOutcome {
    fn code(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum DecisionReason {
    Authorized,
    UrlOrMethodOutOfScope,
    MissingDnsResolution,
    NonPublicDestination { ip: IpAddr, class: DestinationClass },
    RedirectLimitExceeded { maximum: u8, observed: u8 },
    TotalBudgetExhausted,
    ConcurrencyExceeded,
    RateLimited { retry_after_milliseconds: u64 },
}

impl DecisionReason {
    fn code(&self) -> &'static str {
        match self {
            Self::Authorized => "authorized",
            Self::UrlOrMethodOutOfScope => "url_or_method_out_of_scope",
            Self::MissingDnsResolution => "missing_dns_resolution",
            Self::NonPublicDestination { .. } => "non_public_destination",
            Self::RedirectLimitExceeded { .. } => "redirect_limit_exceeded",
            Self::TotalBudgetExhausted => "total_budget_exhausted",
            Self::ConcurrencyExceeded => "concurrency_exceeded",
            Self::RateLimited { .. } => "rate_limited",
        }
    }

    fn details(&self) -> BTreeMap<String, String> {
        let mut details = BTreeMap::new();
        match self {
            Self::NonPublicDestination { ip, class } => {
                details.insert("ip".into(), ip.to_string());
                details.insert("class".into(), class.code().into());
            }
            Self::RedirectLimitExceeded { maximum, observed } => {
                details.insert("maximum".into(), maximum.to_string());
                details.insert("observed".into(), observed.to_string());
            }
            Self::RateLimited {
                retry_after_milliseconds,
            } => {
                details.insert(
                    "retry_after_milliseconds".into(),
                    retry_after_milliseconds.to_string(),
                );
            }
            Self::Authorized
            | Self::UrlOrMethodOutOfScope
            | Self::MissingDnsResolution
            | Self::TotalBudgetExhausted
            | Self::ConcurrencyExceeded => {}
        }
        details
    }
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
    audit: AuditChain,
    maximum_redirects: u8,
    next_decision_id: u64,
}

#[derive(Debug, Error)]
pub enum GatewayError {
    #[error("gateway budget could not be created: {0}")]
    Budget(#[from] BudgetError),
    #[error("gateway audit record could not be committed: {0}")]
    Audit(#[from] AuditError),
    #[error("maximum_redirects must be greater than zero")]
    InvalidRedirectLimit,
}

impl ScopeGateway {
    pub fn new(policy: CompiledPolicy, maximum_redirects: u8) -> Result<Self, GatewayError> {
        if maximum_redirects == 0 {
            return Err(GatewayError::InvalidRedirectLimit);
        }

        // The gateway remains intentionally narrower than the policy's global maximums.
        // A later policy API will expose rate/concurrency getters without allowing broadening.
        let budget = RequestBudget::new(policy.maximum_total_requests(), 1, 1.0)?;

        Ok(Self {
            policy,
            budget,
            audit: AuditChain::new(),
            maximum_redirects,
            next_decision_id: 1,
        })
    }

    pub fn authorize(
        &mut self,
        intent: &RequestIntent,
        elapsed: Duration,
    ) -> Result<GatewayDecision, GatewayError> {
        let assessments: Vec<_> = intent
            .resolved_ips
            .iter()
            .copied()
            .map(assess_destination)
            .collect();
        let decision = self.evaluate(intent, elapsed, &assessments);
        let event = audit_event(intent, elapsed, &assessments, &decision);

        // A decision is not returned to a caller unless its audit record was committed.
        self.audit.append(event)?;
        Ok(decision)
    }

    pub fn complete_request(&mut self) {
        self.budget.finish();
    }

    pub fn remaining_requests(&self) -> u64 {
        self.budget.remaining()
    }

    pub fn audit_chain(&self) -> &AuditChain {
        &self.audit
    }

    pub fn verify_audit_chain(&self) -> Result<(), AuditError> {
        self.audit.verify()
    }

    fn evaluate(
        &mut self,
        intent: &RequestIntent,
        elapsed: Duration,
        assessments: &[DestinationAssessment],
    ) -> GatewayDecision {
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

        if assessments.is_empty() {
            return deny(decision_id, DecisionReason::MissingDnsResolution);
        }

        if let Some(assessment) = assessments.iter().find(|value| !value.is_allowed()) {
            return deny(
                decision_id,
                DecisionReason::NonPublicDestination {
                    ip: assessment.ip,
                    class: assessment.class,
                },
            );
        }

        match self.budget.try_start(elapsed) {
            Ok(()) => GatewayDecision {
                decision_id,
                outcome: DecisionOutcome::Allow,
                reason: DecisionReason::Authorized,
            },
            Err(BudgetError::Exhausted) => deny(decision_id, DecisionReason::TotalBudgetExhausted),
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

fn audit_event(
    intent: &RequestIntent,
    elapsed: Duration,
    assessments: &[DestinationAssessment],
    decision: &GatewayDecision,
) -> AuditEvent {
    AuditEvent {
        decision_id: decision.decision_id.clone(),
        outcome: decision.outcome.code().into(),
        reason_code: decision.reason.code().into(),
        reason_details: decision.reason.details(),
        method: intent.method.trim().to_ascii_uppercase(),
        url: sanitized_audit_url(&intent.url),
        resolved_destinations: assessments
            .iter()
            .map(|assessment| AuditDestination {
                ip: assessment.ip.to_string(),
                class: assessment.class.code().into(),
                allowed: assessment.is_allowed(),
            })
            .collect(),
        redirect_depth: intent.redirect_depth,
        elapsed_milliseconds: duration_milliseconds_saturated(elapsed),
    }
}

fn sanitized_audit_url(url: &Url) -> String {
    let mut sanitized = url.clone();
    sanitized.set_query(None);
    sanitized.set_fragment(None);
    sanitized.to_string()
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
        let decision = gateway
            .authorize(&intent("8.8.8.8"), Duration::ZERO)
            .unwrap();
        assert_eq!(decision.outcome, DecisionOutcome::Allow);
        gateway.complete_request();
        gateway.verify_audit_chain().unwrap();
    }

    #[test]
    fn denies_private_destination_without_spending_budget() {
        let mut gateway = gateway();
        let decision = gateway
            .authorize(&intent("127.0.0.1"), Duration::ZERO)
            .unwrap();
        assert_eq!(
            decision.reason,
            DecisionReason::NonPublicDestination {
                ip: "127.0.0.1".parse().unwrap(),
                class: DestinationClass::Loopback,
            }
        );
        assert_eq!(gateway.remaining_requests(), 3);
    }

    #[test]
    fn denies_cgnat_destination_with_specific_classification() {
        let mut gateway = gateway();
        let decision = gateway
            .authorize(&intent("100.64.12.3"), Duration::ZERO)
            .unwrap();
        assert!(matches!(
            decision.reason,
            DecisionReason::NonPublicDestination {
                class: DestinationClass::SharedAddressSpace,
                ..
            }
        ));
    }

    #[test]
    fn denies_scope_escape() {
        let mut gateway = gateway();
        let mut request = intent("8.8.8.8");
        request.url = Url::parse("https://outside.example.net/").unwrap();
        let decision = gateway.authorize(&request, Duration::ZERO).unwrap();
        assert_eq!(decision.reason, DecisionReason::UrlOrMethodOutOfScope);
    }

    #[test]
    fn revalidates_redirect_hops() {
        let mut gateway = gateway();
        let first = gateway
            .authorize(&intent("8.8.8.8"), Duration::ZERO)
            .unwrap();
        assert_eq!(first.outcome, DecisionOutcome::Allow);
        gateway.complete_request();

        let mut redirected = intent("1.1.1.1");
        redirected.redirect_depth = 1;
        redirected.url = Url::parse("https://outside.example.net/landing").unwrap();
        let second = gateway
            .authorize(&redirected, Duration::from_secs(1))
            .unwrap();
        assert_eq!(second.reason, DecisionReason::UrlOrMethodOutOfScope);
        assert_eq!(gateway.audit_chain().len(), 2);
        gateway.verify_audit_chain().unwrap();
    }

    #[test]
    fn enforces_redirect_limit() {
        let mut gateway = gateway();
        let mut request = intent("8.8.8.8");
        request.redirect_depth = 6;
        let decision = gateway.authorize(&request, Duration::ZERO).unwrap();
        assert!(matches!(
            decision.reason,
            DecisionReason::RedirectLimitExceeded { .. }
        ));
    }

    #[test]
    fn enforces_concurrency_before_rate() {
        let mut gateway = gateway();
        assert_eq!(
            gateway
                .authorize(&intent("8.8.8.8"), Duration::ZERO)
                .unwrap()
                .outcome,
            DecisionOutcome::Allow
        );
        let second = gateway
            .authorize(&intent("1.1.1.1"), Duration::from_millis(10))
            .unwrap();
        assert_eq!(second.reason, DecisionReason::ConcurrencyExceeded);
    }

    #[test]
    fn audits_denials_and_redacts_url_secrets() {
        let mut gateway = gateway();
        let mut request = intent("127.0.0.1");
        request.url =
            Url::parse("https://app.example.com/api/me?access_token=secret#private-fragment")
                .unwrap();

        gateway.authorize(&request, Duration::ZERO).unwrap();
        let record = &gateway.audit_chain().records()[0];
        assert_eq!(record.event.url, "https://app.example.com/api/me");
        assert!(!record.event.url.contains("secret"));
        assert_eq!(record.event.reason_code, "non_public_destination");
        gateway.verify_audit_chain().unwrap();
    }
}
