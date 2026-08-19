use std::{collections::BTreeSet, time::Duration};

use bsl_gateway::ScopeGateway;
use bsl_http1::{Http1Framing, Http1Header, Http1Response, Http1Version};
use bsl_pinned_transport::PinnedTransportCoordinator;
use bsl_policy::{AuthorizationPolicy, AutomationPolicy, ProgramPolicy, ScopePolicy, TargetPolicy};
use bsl_redirect::*;
use chrono::{TimeZone, Utc};
use sha2::{Digest, Sha256};
use url::Url;

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn session(generation: u64) -> RedirectSessionSnapshot {
    RedirectSessionSnapshot {
        session_id: "session-1".into(),
        run_id: "run-1".into(),
        worker_id: "worker-1".into(),
        account_id: "account-a".into(),
        tenant_id: "tenant-a".into(),
        role_id: "admin".into(),
        generation,
    }
}

fn policy(hosts: &[&str]) -> bsl_policy::CompiledPolicy {
    TargetPolicy {
        schema_version: 1,
        program: ProgramPolicy {
            name: "redirect-fixture".into(),
            platform: "fixture".into(),
            policy_url: None,
        },
        scope: ScopePolicy {
            include_hosts: hosts.iter().map(|host| (*host).to_string()).collect(),
            exclude_hosts: BTreeSet::new(),
            allowed_schemes: BTreeSet::from(["http".into(), "https".into()]),
            allowed_methods: BTreeSet::from([
                "GET".into(),
                "HEAD".into(),
                "POST".into(),
                "PUT".into(),
            ]),
            allow_subdomains: false,
        },
        automation: AutomationPolicy {
            active_testing: false,
            credential_bruteforce: false,
            destructive_testing: false,
            oob_callbacks: false,
            max_requests_per_second: 5.0,
            max_concurrency: 8,
            max_total_requests: 100,
        },
        authorization: AuthorizationPolicy {
            confirmed: true,
            researcher: "fixture".into(),
            policy_snapshot_sha256: "a".repeat(64),
            expires_at: Utc.with_ymd_and_hms(2030, 1, 1, 0, 0, 0).unwrap(),
        },
    }
    .compile(Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap())
    .unwrap()
}

fn coordinator(hosts: &[&str], start: &str, method: &str, body: &[u8]) -> RedirectCoordinator {
    let gateway = ScopeGateway::new(policy(hosts), 8).unwrap();
    let transport = PinnedTransportCoordinator::new(gateway);
    let current = RedirectRequestState::new(
        Url::parse(start).unwrap(),
        method,
        digest(body),
        body.len() as u64,
        session(1),
    )
    .unwrap();
    RedirectCoordinator::new("chain-1", transport, current, RedirectLimits::default()).unwrap()
}

fn redirect_response(status: u16, locations: &[&str]) -> Http1Response {
    Http1Response {
        version: Http1Version::Http11,
        status_code: status,
        reason: Vec::new(),
        headers: locations
            .iter()
            .map(|location| Http1Header::new("Location", location.as_bytes().to_vec()))
            .collect(),
        trailers: Vec::new(),
        body: Vec::new(),
        framing: Http1Framing::NoBody,
        interim_responses: 0,
    }
}

fn dns(context: &str) -> RedirectDnsInput {
    RedirectDnsInput {
        resolved_ips: vec!["1.1.1.1".parse().unwrap()],
        selected_ip: "1.1.1.1".parse().unwrap(),
        context_id: context.into(),
        resolver_id: "resolver-1".into(),
        ttl_seconds: 60,
    }
}

fn unchanged() -> RedirectSessionUpdate {
    RedirectSessionUpdate {
        snapshot: session(1),
        response_state_changed: false,
    }
}

#[test]
fn post_302_becomes_get_and_receives_new_ticket() {
    let mut coordinator = coordinator(
        &["app.example.com"],
        "https://app.example.com/login",
        "POST",
        b"credentials",
    );
    let step = coordinator
        .authorize_next(
            &redirect_response(302, &["/home"]),
            dns("redirect-context-1"),
            unchanged(),
            Duration::from_millis(10),
        )
        .unwrap();
    assert!(step.is_authorized());
    assert_eq!(step.redirect_depth, 1);
    assert_eq!(step.next_request.method, "GET");
    assert_eq!(step.next_request.body_bytes, 0);
    assert_eq!(
        step.secret_disposition,
        RedirectSecretDisposition::ReissueBoundSecrets
    );
    let ticket = step.authorization.ticket.unwrap();
    assert_eq!(ticket.redirect_depth, 1);
    assert_eq!(ticket.dns_context_id, "redirect-context-1");
}

#[test]
fn cross_origin_get_strips_header_secrets_and_rematerializes_cookies() {
    let mut coordinator = coordinator(
        &["app.example.com", "api.example.com"],
        "https://app.example.com/start",
        "GET",
        b"",
    );
    let step = coordinator
        .authorize_next(
            &redirect_response(301, &["https://api.example.com/next"]),
            dns("redirect-context-1"),
            unchanged(),
            Duration::from_millis(10),
        )
        .unwrap();
    assert!(step.is_authorized());
    assert_eq!(step.origin_transition, OriginTransition::CrossOrigin);
    assert_eq!(
        step.secret_disposition,
        RedirectSecretDisposition::RematerializeCookiesOnly
    );
}

#[test]
fn https_downgrade_is_rejected_before_gateway_authorization() {
    let mut coordinator = coordinator(
        &["app.example.com"],
        "https://app.example.com/start",
        "GET",
        b"",
    );
    let error = coordinator
        .authorize_next(
            &redirect_response(302, &["http://app.example.com/next"]),
            dns("redirect-context-1"),
            unchanged(),
            Duration::from_millis(10),
        )
        .unwrap_err();
    assert!(matches!(error, RedirectError::HttpsDowngrade));
    assert_eq!(
        coordinator
            .transport()
            .gateway()
            .audit_chain()
            .records()
            .len(),
        0
    );
}

#[test]
fn redirect_loop_is_rejected() {
    let mut coordinator = coordinator(
        &["app.example.com"],
        "https://app.example.com/start",
        "GET",
        b"",
    );
    let error = coordinator
        .authorize_next(
            &redirect_response(302, &["/start"]),
            dns("redirect-context-1"),
            unchanged(),
            Duration::from_millis(10),
        )
        .unwrap_err();
    assert!(matches!(error, RedirectError::RedirectLoop));
}

#[test]
fn redirect_dns_context_cannot_be_reused() {
    let mut coordinator = coordinator(
        &["app.example.com"],
        "https://app.example.com/start",
        "GET",
        b"",
    );
    coordinator
        .authorize_next(
            &redirect_response(302, &["/one"]),
            dns("redirect-context-1"),
            unchanged(),
            Duration::from_millis(10),
        )
        .unwrap();
    let error = coordinator
        .authorize_next(
            &redirect_response(302, &["/two"]),
            dns("redirect-context-1"),
            unchanged(),
            Duration::from_millis(20),
        )
        .unwrap_err();
    assert!(matches!(error, RedirectError::DnsContextReused));
}

#[test]
fn cross_origin_307_does_not_replay_body() {
    let mut coordinator = coordinator(
        &["app.example.com", "api.example.com"],
        "https://app.example.com/start",
        "POST",
        b"secret-body",
    );
    let error = coordinator
        .authorize_next(
            &redirect_response(307, &["https://api.example.com/next"]),
            dns("redirect-context-1"),
            unchanged(),
            Duration::from_millis(10),
        )
        .unwrap_err();
    assert!(matches!(error, RedirectError::CrossOriginBodyReplayDenied));
}

#[test]
fn declared_session_rotation_requires_exact_next_generation() {
    let mut coordinator = coordinator(
        &["app.example.com"],
        "https://app.example.com/start",
        "GET",
        b"",
    );
    let error = coordinator
        .authorize_next(
            &redirect_response(302, &["/next"]),
            dns("redirect-context-1"),
            RedirectSessionUpdate {
                snapshot: session(1),
                response_state_changed: true,
            },
            Duration::from_millis(10),
        )
        .unwrap_err();
    assert!(matches!(error, RedirectError::SessionGenerationMismatch));
}

#[test]
fn account_or_tenant_change_is_rejected() {
    let mut coordinator = coordinator(
        &["app.example.com"],
        "https://app.example.com/start",
        "GET",
        b"",
    );
    let mut changed = session(1);
    changed.tenant_id = "tenant-b".into();
    let error = coordinator
        .authorize_next(
            &redirect_response(302, &["/next"]),
            dns("redirect-context-1"),
            RedirectSessionUpdate {
                snapshot: changed,
                response_state_changed: false,
            },
            Duration::from_millis(10),
        )
        .unwrap_err();
    assert!(matches!(error, RedirectError::SessionIdentityMismatch));
}

#[test]
fn multiple_location_fields_are_rejected() {
    let mut coordinator = coordinator(
        &["app.example.com"],
        "https://app.example.com/start",
        "GET",
        b"",
    );
    let error = coordinator
        .authorize_next(
            &redirect_response(302, &["/one", "/two"]),
            dns("redirect-context-1"),
            unchanged(),
            Duration::from_millis(10),
        )
        .unwrap_err();
    assert!(matches!(error, RedirectError::MultipleLocations));
}

#[test]
fn out_of_scope_redirect_is_audited_without_ticket() {
    let mut coordinator = coordinator(
        &["app.example.com"],
        "https://app.example.com/start",
        "GET",
        b"",
    );
    let step = coordinator
        .authorize_next(
            &redirect_response(302, &["https://outside.example/next"]),
            dns("redirect-context-1"),
            unchanged(),
            Duration::from_millis(10),
        )
        .unwrap();
    assert!(!step.is_authorized());
    assert!(step.authorization.ticket.is_none());
    assert!(coordinator.is_terminal());
    coordinator.audit().verify().unwrap();
}

#[test]
fn audit_does_not_store_location_or_query_secret() {
    let secret = "redirect-secret-value";
    let mut coordinator = coordinator(
        &["app.example.com"],
        "https://app.example.com/start",
        "GET",
        b"",
    );
    coordinator
        .authorize_next(
            &redirect_response(302, &[&format!("/next?token={secret}")]),
            dns("redirect-context-1"),
            unchanged(),
            Duration::from_millis(10),
        )
        .unwrap();
    let serialized = serde_json::to_string(coordinator.audit().records()).unwrap();
    assert!(!serialized.contains(secret));
    assert!(!serialized.contains("token="));
    coordinator.audit().verify().unwrap();
}
