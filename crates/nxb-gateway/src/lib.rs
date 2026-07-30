use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    time::Duration,
};

use nxb_audit::{AuditChain, AuditDestination, AuditDns, AuditError, AuditEvent};
use nxb_budget::{BudgetError, RequestBudget};
use nxb_destination::{assess_destination, DestinationAssessment, DestinationClass};
use nxb_dns::{DnsObservation, DnsPinError, DnsPinSet, DnsPinStatus};
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
    pub dns_context_id: String,
    pub dns_resolver_id: String,
    pub dns_ttl_seconds: u32,
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
#[serde(rename_all = "snake_case")]
pub enum DnsObservationErrorKind {
    InvalidContextId,
    InvalidResolverId,
    InvalidHost,
    EmptyAddressSet,
    ClockRegression,
}

impl DnsObservationErrorKind {
    fn code(&self) -> &'static str {
        match self {
            Self::InvalidContextId => "invalid_context_id",
            Self::InvalidResolverId => "invalid_resolver_id",
            Self::InvalidHost => "invalid_host",
            Self::EmptyAddressSet => "empty_address_set",
            Self::ClockRegression => "clock_regression",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum DecisionReason {
    Authorized,
    UrlOrMethodOutOfScope,
    MissingDnsResolution,
    NonPublicDestination {
        ip: IpAddr,
        class: DestinationClass,
    },
    RedirectLimitExceeded {
        maximum: u8,
        observed: u8,
    },
    InvalidDnsObservation {
        kind: DnsObservationErrorKind,
    },
    DnsResolverChanged {
        expected: String,
        observed: String,
    },
    DnsRebindingDetected {
        host: String,
        pinned: BTreeSet<IpAddr>,
        observed: BTreeSet<IpAddr>,
    },
    TotalBudgetExhausted,
    ConcurrencyExceeded,
    RateLimited {
        retry_after_milliseconds: u64,
    },
}

impl DecisionReason {
    fn code(&self) -> &'static str {
        match self {
            Self::Authorized => "authorized",
            Self::UrlOrMethodOutOfScope => "url_or_method_out_of_scope",
            Self::MissingDnsResolution => "missing_dns_resolution",
            Self::NonPublicDestination { .. } => "non_public_destination",
            Self::RedirectLimitExceeded { .. } => "redirect_limit_exceeded",
            Self::InvalidDnsObservation { .. } => "invalid_dns_observation",
            Self::DnsResolverChanged { .. } => "dns_resolver_changed",
            Self::DnsRebindingDetected { .. } => "dns_rebinding_detected",
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
            Self::InvalidDnsObservation { kind } => {
                details.insert("kind".into(), kind.code().into());
            }
            Self::DnsResolverChanged { expected, observed } => {
                details.insert("expected".into(), expected.clone());
                details.insert("observed".into(), observed.clone());
            }
            Self::DnsRebindingDetected {
                host,
                pinned,
                observed,
            } => {
                details.insert("host".into(), host.clone());
                details.insert("pinned".into(), join_ips(pinned));
                details.insert("observed".into(), join_ips(observed));
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
    dns_pins: DnsPinSet,
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

#[derive(Debug, Clone, Copy)]
enum AuditPinStatus {
    NotEvaluated,
    Pinned,
    Matched,
    Rejected,
}

impl AuditPinStatus {
    fn code(self) -> &'static str {
        match self {
            Self::NotEvaluated => "not_evaluated",
            Self::Pinned => "pinned",
            Self::Matched => "matched",
            Self::Rejected => "rejected",
        }
    }
}

impl ScopeGateway {
    pub fn new(policy: CompiledPolicy, maximum_redirects: u8) -> Result<Self, GatewayError> {
        if maximum_redirects == 0 {
            return Err(GatewayError::InvalidRedirectLimit);
        }

        let budget = RequestBudget::new(
            policy.maximum_total_requests(),
            policy.maximum_concurrency(),
            policy.maximum_requests_per_second(),
        )?;

        Ok(Self {
            policy,
            budget,
            dns_pins: DnsPinSet::new(),
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
        let (decision, pin_status) = self.evaluate(intent, elapsed, &assessments);
        let event = audit_event(intent, elapsed, &assessments, &decision, pin_status);

        // A decision is not returned to a caller unless its audit record was committed.
        self.audit.append(event)?;
        Ok(decision)
    }

    pub fn complete_request(&mut self) {
        self.budget.finish();
    }

    pub fn release_dns_context(&mut self, context_id: &str) -> usize {
        self.dns_pins.release_context(context_id)
    }

    pub fn remaining_requests(&self) -> u64 {
        self.budget.remaining()
    }

    pub fn in_flight_requests(&self) -> u16 {
        self.budget.in_flight()
    }

    pub fn dns_pin_count(&self) -> usize {
        self.dns_pins.len()
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
    ) -> (GatewayDecision, AuditPinStatus) {
        let decision_id = self.allocate_decision_id();

        if intent.redirect_depth > self.maximum_redirects {
            return (
                deny(
                    decision_id,
                    DecisionReason::RedirectLimitExceeded {
                        maximum: self.maximum_redirects,
                        observed: intent.redirect_depth,
                    },
                ),
                AuditPinStatus::NotEvaluated,
            );
        }

        if !self.policy.allows_request(&intent.url, &intent.method) {
            return (
                deny(decision_id, DecisionReason::UrlOrMethodOutOfScope),
                AuditPinStatus::NotEvaluated,
            );
        }

        if assessments.is_empty() {
            return (
                deny(decision_id, DecisionReason::MissingDnsResolution),
                AuditPinStatus::NotEvaluated,
            );
        }

        if let Some(assessment) = assessments.iter().find(|value| !value.is_allowed()) {
            return (
                deny(
                    decision_id,
                    DecisionReason::NonPublicDestination {
                        ip: assessment.ip,
                        class: assessment.class,
                    },
                ),
                AuditPinStatus::NotEvaluated,
            );
        }

        let host = intent
            .url
            .host_str()
            .expect("an allowed request always has a host")
            .to_string();
        let observation = DnsObservation {
            context_id: intent.dns_context_id.clone(),
            host,
            addresses: intent.resolved_ips.iter().copied().collect(),
            resolver_id: intent.dns_resolver_id.clone(),
            ttl_seconds: intent.dns_ttl_seconds,
            observed_at_milliseconds: duration_milliseconds_saturated(elapsed),
        };

        let pin_status = match self.dns_pins.pin_or_validate(observation) {
            Ok(DnsPinStatus::Pinned) => AuditPinStatus::Pinned,
            Ok(DnsPinStatus::Matched) => AuditPinStatus::Matched,
            Err(error) => {
                return (
                    deny(decision_id, map_dns_error(error)),
                    AuditPinStatus::Rejected,
                )
            }
        };

        let decision = match self.budget.try_start(elapsed) {
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
        };

        (decision, pin_status)
    }

    fn allocate_decision_id(&mut self) -> String {
        let value = self.next_decision_id;
        self.next_decision_id = self.next_decision_id.saturating_add(1);
        format!("decision-{value:020}")
    }
}

fn map_dns_error(error: DnsPinError) -> DecisionReason {
    match error {
        DnsPinError::InvalidContextId => DecisionReason::InvalidDnsObservation {
            kind: DnsObservationErrorKind::InvalidContextId,
        },
        DnsPinError::InvalidResolverId => DecisionReason::InvalidDnsObservation {
            kind: DnsObservationErrorKind::InvalidResolverId,
        },
        DnsPinError::InvalidHost => DecisionReason::InvalidDnsObservation {
            kind: DnsObservationErrorKind::InvalidHost,
        },
        DnsPinError::EmptyAddressSet => DecisionReason::InvalidDnsObservation {
            kind: DnsObservationErrorKind::EmptyAddressSet,
        },
        DnsPinError::ClockRegression => DecisionReason::InvalidDnsObservation {
            kind: DnsObservationErrorKind::ClockRegression,
        },
        DnsPinError::ResolverChanged { expected, observed } => {
            DecisionReason::DnsResolverChanged { expected, observed }
        }
        DnsPinError::RebindingDetected {
            host,
            pinned,
            observed,
        } => DecisionReason::DnsRebindingDetected {
            host,
            pinned,
            observed,
        },
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
    pin_status: AuditPinStatus,
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
        dns: AuditDns {
            context_id: sanitized_dns_identifier(&intent.dns_context_id),
            resolver_id: sanitized_dns_identifier(&intent.dns_resolver_id),
            ttl_seconds: intent.dns_ttl_seconds,
            pin_status: pin_status.code().into(),
        },
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

fn sanitized_dns_identifier(value: &str) -> String {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return "[invalid]".into();
    }
    value.to_ascii_lowercase()
}

fn join_ips(values: &BTreeSet<IpAddr>) -> String {
    values
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn duration_milliseconds_saturated(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use chrono::{Duration as ChronoDuration, Utc};
    use nxb_policy::{
        AuthorizationPolicy, AutomationPolicy, ChildPolicy, ProgramPolicy, ScopePolicy,
        TargetPolicy,
    };

    use super::*;

    fn target_policy() -> TargetPolicy {
        TargetPolicy {
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
    }

    fn gateway() -> ScopeGateway {
        let policy = target_policy().compile(Utc::now()).unwrap();
        ScopeGateway::new(policy, 5).unwrap()
    }

    fn intent(ip: &str) -> RequestIntent {
        RequestIntent {
            url: Url::parse("https://app.example.com/api/me").unwrap(),
            method: "GET".into(),
            resolved_ips: vec![ip.parse().unwrap()],
            redirect_depth: 0,
            dns_context_id: "navigation-1".into(),
            dns_resolver_id: "system-resolver".into(),
            dns_ttl_seconds: 60,
        }
    }

    #[test]
    fn allows_in_scope_public_request() {
        let mut gateway = gateway();
        let decision = gateway
            .authorize(&intent("8.8.8.8"), Duration::ZERO)
            .unwrap();
        assert_eq!(decision.outcome, DecisionOutcome::Allow);
        assert_eq!(
            gateway.audit_chain().records()[0].event.dns.pin_status,
            "pinned"
        );
        gateway.complete_request();
        gateway.verify_audit_chain().unwrap();
    }

    #[test]
    fn matching_dns_set_is_reused_inside_context() {
        let mut gateway = gateway();
        gateway
            .authorize(&intent("8.8.8.8"), Duration::ZERO)
            .unwrap();
        gateway.complete_request();
        gateway
            .authorize(&intent("8.8.8.8"), Duration::from_millis(10))
            .unwrap();

        assert_eq!(
            gateway.audit_chain().records()[1].event.dns.pin_status,
            "matched"
        );
        assert_eq!(gateway.dns_pin_count(), 1);
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
        assert_eq!(gateway.dns_pin_count(), 0);
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
    fn denies_public_to_public_dns_rebinding_without_spending_budget() {
        let mut gateway = gateway();
        gateway
            .authorize(&intent("8.8.8.8"), Duration::ZERO)
            .unwrap();
        gateway.complete_request();
        assert_eq!(gateway.remaining_requests(), 2);

        let decision = gateway
            .authorize(&intent("1.1.1.1"), Duration::from_millis(10))
            .unwrap();
        assert!(matches!(
            decision.reason,
            DecisionReason::DnsRebindingDetected { .. }
        ));
        assert_eq!(gateway.remaining_requests(), 2);
        assert_eq!(
            gateway.audit_chain().records()[1].event.dns.pin_status,
            "rejected"
        );
    }

    #[test]
    fn separate_dns_context_can_pin_a_different_public_set() {
        let mut gateway = gateway();
        gateway
            .authorize(&intent("8.8.8.8"), Duration::ZERO)
            .unwrap();
        gateway.complete_request();

        let mut second = intent("1.1.1.1");
        second.dns_context_id = "navigation-2".into();
        let decision = gateway
            .authorize(&second, Duration::from_millis(10))
            .unwrap();
        assert_eq!(decision.outcome, DecisionOutcome::Allow);
        assert_eq!(gateway.dns_pin_count(), 2);
    }

    #[test]
    fn rejects_resolver_change_inside_context() {
        let mut gateway = gateway();
        gateway
            .authorize(&intent("8.8.8.8"), Duration::ZERO)
            .unwrap();
        gateway.complete_request();

        let mut changed = intent("8.8.8.8");
        changed.dns_resolver_id = "alternate-resolver".into();
        let decision = gateway
            .authorize(&changed, Duration::from_millis(10))
            .unwrap();
        assert!(matches!(
            decision.reason,
            DecisionReason::DnsResolverChanged { .. }
        ));
    }

    #[test]
    fn releasing_context_allows_a_fresh_pin() {
        let mut gateway = gateway();
        gateway
            .authorize(&intent("8.8.8.8"), Duration::ZERO)
            .unwrap();
        gateway.complete_request();
        assert_eq!(gateway.release_dns_context("navigation-1"), 1);

        let decision = gateway
            .authorize(&intent("1.1.1.1"), Duration::from_secs(1))
            .unwrap();
        assert_eq!(decision.outcome, DecisionOutcome::Allow);
        assert_eq!(
            gateway.audit_chain().records()[1].event.dns.pin_status,
            "pinned"
        );
    }

    #[test]
    fn denies_scope_escape_before_dns_pinning() {
        let mut gateway = gateway();
        let mut request = intent("8.8.8.8");
        request.url = Url::parse("https://outside.example.net/").unwrap();
        let decision = gateway.authorize(&request, Duration::ZERO).unwrap();
        assert_eq!(decision.reason, DecisionReason::UrlOrMethodOutOfScope);
        assert_eq!(gateway.dns_pin_count(), 0);
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
    fn uses_policy_concurrency_limit() {
        let mut gateway = gateway();
        assert_eq!(
            gateway
                .authorize(&intent("8.8.8.8"), Duration::ZERO)
                .unwrap()
                .outcome,
            DecisionOutcome::Allow
        );

        let mut second = intent("8.8.8.8");
        second.dns_context_id = "navigation-2".into();
        assert_eq!(
            gateway.authorize(&second, Duration::ZERO).unwrap().outcome,
            DecisionOutcome::Allow
        );

        let mut third = intent("8.8.8.8");
        third.dns_context_id = "navigation-3".into();
        let decision = gateway.authorize(&third, Duration::ZERO).unwrap();
        assert_eq!(decision.reason, DecisionReason::ConcurrencyExceeded);
    }

    #[test]
    fn uses_policy_rate_limit() {
        let mut gateway = gateway();
        gateway
            .authorize(&intent("8.8.8.8"), Duration::ZERO)
            .unwrap();
        gateway.complete_request();

        let mut second = intent("8.8.8.8");
        second.dns_context_id = "navigation-2".into();
        gateway.authorize(&second, Duration::ZERO).unwrap();
        gateway.complete_request();

        let mut third = intent("8.8.8.8");
        third.dns_context_id = "navigation-3".into();
        let decision = gateway.authorize(&third, Duration::ZERO).unwrap();
        assert!(matches!(
            decision.reason,
            DecisionReason::RateLimited { .. }
        ));
    }

    #[test]
    fn narrowed_child_budget_is_enforced_by_gateway() {
        let now = Utc::now();
        let parent = target_policy().compile(now).unwrap();
        let narrowed = parent
            .narrow(
                ChildPolicy {
                    max_requests_per_second: Some(0.5),
                    max_concurrency: Some(1),
                    max_total_requests: Some(2),
                    ..ChildPolicy::default()
                },
                now,
            )
            .unwrap();
        let mut gateway = ScopeGateway::new(narrowed, 5).unwrap();

        gateway
            .authorize(&intent("8.8.8.8"), Duration::ZERO)
            .unwrap();
        let concurrent = gateway
            .authorize(&intent("8.8.8.8"), Duration::from_millis(10))
            .unwrap();
        assert_eq!(concurrent.reason, DecisionReason::ConcurrencyExceeded);
        gateway.complete_request();

        let rate_limited = gateway
            .authorize(&intent("8.8.8.8"), Duration::from_secs(1))
            .unwrap();
        assert!(matches!(
            rate_limited.reason,
            DecisionReason::RateLimited { .. }
        ));
        let allowed = gateway
            .authorize(&intent("8.8.8.8"), Duration::from_secs(2))
            .unwrap();
        assert_eq!(allowed.outcome, DecisionOutcome::Allow);
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
        assert_eq!(record.event.dns.context_id, "navigation-1");
        assert_eq!(record.event.dns.resolver_id, "system-resolver");
        gateway.verify_audit_chain().unwrap();
    }
}
