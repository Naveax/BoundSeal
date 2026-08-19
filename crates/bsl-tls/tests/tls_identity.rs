use std::{collections::BTreeSet, time::Duration};

use chrono::{Duration as ChronoDuration, Utc};
use nxb_executor::{
    ExecutionControl, ExecutionLimits, ExecutorConfig, PermitExecutor, SyntheticBackend,
    SyntheticScenario,
};
use nxb_gateway::{RequestIntent, ScopeGateway};
use nxb_local_executor::LocalExecutionPipeline;
use nxb_pinned_transport::PinnedTransportCoordinator;
use nxb_policy::{AuthorizationPolicy, AutomationPolicy, ProgramPolicy, ScopePolicy, TargetPolicy};
use nxb_stream::{BoundedByteStream, StreamLimits};
use nxb_stream_fixture::InMemoryDuplex;
use nxb_tls::*;
use nxb_transport::{ConnectionAttempt, ConnectionTicket};

const NOW: i64 = 1_800_000_000;

fn hex(character: char) -> String {
    std::iter::repeat_n(character, 64).collect()
}

fn stream_for(scheme: &str) -> BoundedByteStream<InMemoryDuplex> {
    let host = "app.example.com";
    let url = format!("{scheme}://{host}/api");
    let policy = TargetPolicy {
        schema_version: 1,
        program: ProgramPolicy {
            name: "tls-fixture".into(),
            platform: "fixture".into(),
            policy_url: None,
        },
        scope: ScopePolicy {
            include_hosts: BTreeSet::from([host.into()]),
            exclude_hosts: BTreeSet::new(),
            allowed_schemes: BTreeSet::from([scheme.into()]),
            allowed_methods: BTreeSet::from(["GET".into()]),
            allow_subdomains: false,
        },
        automation: AutomationPolicy {
            active_testing: false,
            credential_bruteforce: false,
            destructive_testing: false,
            oob_callbacks: false,
            max_requests_per_second: 5.0,
            max_concurrency: 4,
            max_total_requests: 10,
        },
        authorization: AuthorizationPolicy {
            confirmed: true,
            researcher: "fixture".into(),
            policy_snapshot_sha256: "a".repeat(64),
            expires_at: Utc::now() + ChronoDuration::days(1),
        },
    }
    .compile(Utc::now())
    .unwrap();
    let gateway = ScopeGateway::new(policy, 4).unwrap();
    let transport = PinnedTransportCoordinator::new(gateway);
    let executor = PermitExecutor::new(
        ExecutorConfig {
            executor_id: "tls-fixture-executor".into(),
        },
        SyntheticBackend::new([SyntheticScenario::success(1, 2, 32, 8)]),
    )
    .unwrap();
    let mut pipeline = LocalExecutionPipeline::new(transport, executor);
    let intent = RequestIntent {
        url: url::Url::parse(&url).unwrap(),
        method: "GET".into(),
        resolved_ips: vec!["1.1.1.1".parse().unwrap()],
        redirect_depth: 0,
        dns_context_id: "tls-navigation-1".into(),
        dns_resolver_id: "fixture-resolver".into(),
        dns_ttl_seconds: 60,
    };
    let ticket = pipeline
        .transport_mut()
        .authorize_connection(&intent, "1.1.1.1".parse().unwrap(), Duration::ZERO)
        .unwrap()
        .ticket
        .unwrap();
    let result = pipeline
        .consume_and_execute(
            attempt(&ticket),
            Duration::from_millis(1),
            ExecutionLimits::default(),
            ExecutionControl::default(),
        )
        .unwrap();
    let permit = result.ticket_use.permit.unwrap();
    let receipt = result.execution_receipt.unwrap();
    BoundedByteStream::open(
        &permit,
        &receipt,
        pipeline.executor().audit(),
        StreamLimits::default(),
        InMemoryDuplex::default(),
    )
    .unwrap()
}

fn attempt(ticket: &ConnectionTicket) -> ConnectionAttempt {
    ConnectionAttempt {
        ticket_id: ticket.ticket_id.clone(),
        dns_context_id: ticket.dns_context_id.clone(),
        scheme: ticket.scheme,
        remote_ip: ticket.selected_ip,
        port: ticket.port,
        sni: ticket.sni.clone(),
        http_host: ticket.http_host.clone(),
        redirect_depth: ticket.redirect_depth,
    }
}

fn certificate_chain() -> Vec<SyntheticCertificate> {
    vec![
        SyntheticCertificate {
            fingerprint_sha256: hex('1'),
            subject_spki_sha256: hex('a'),
            issuer_spki_sha256: hex('b'),
            encoded_bytes: 1_200,
            dns_sans: vec!["app.example.com".into()],
            common_name: Some("ignored.example.com".into()),
            not_before_epoch_seconds: NOW - 10_000,
            not_after_epoch_seconds: NOW + 10_000,
            is_ca: false,
            path_len_constraint: None,
            key_usage_digital_signature: true,
            key_usage_cert_sign: false,
            eku_server_auth: true,
            signature_valid: true,
            unsupported_critical_extension: false,
        },
        SyntheticCertificate {
            fingerprint_sha256: hex('2'),
            subject_spki_sha256: hex('b'),
            issuer_spki_sha256: hex('c'),
            encoded_bytes: 1_000,
            dns_sans: Vec::new(),
            common_name: None,
            not_before_epoch_seconds: NOW - 20_000,
            not_after_epoch_seconds: NOW + 20_000,
            is_ca: true,
            path_len_constraint: Some(0),
            key_usage_digital_signature: true,
            key_usage_cert_sign: true,
            eku_server_auth: false,
            signature_valid: true,
            unsupported_critical_extension: false,
        },
        SyntheticCertificate {
            fingerprint_sha256: hex('3'),
            subject_spki_sha256: hex('c'),
            issuer_spki_sha256: hex('c'),
            encoded_bytes: 900,
            dns_sans: Vec::new(),
            common_name: None,
            not_before_epoch_seconds: NOW - 30_000,
            not_after_epoch_seconds: NOW + 30_000,
            is_ca: true,
            path_len_constraint: Some(1),
            key_usage_digital_signature: true,
            key_usage_cert_sign: true,
            eku_server_auth: false,
            signature_valid: true,
            unsupported_critical_extension: false,
        },
    ]
}

fn observation() -> TlsHandshakeObservation {
    TlsHandshakeObservation {
        server_name: "app.example.com".into(),
        protocol_version: TlsProtocolVersion::Tls13,
        alpn: Some("http/1.1".into()),
        chain: certificate_chain(),
        handshake_read_bytes: 12_000,
        handshake_write_bytes: 4_000,
        elapsed_milliseconds: 80,
        early_data_accepted: false,
        renegotiation_observed: false,
        session_resumed: false,
    }
}

fn new_verifier() -> TlsPeerVerifier {
    TlsPeerVerifier::new(
        TlsPeerVerifierConfig {
            verifier_id: "tls-fixture-verifier".into(),
            limits: TlsLimits::default(),
        },
        TlsTrustStore::new([hex('3')]).unwrap(),
    )
    .unwrap()
}

fn rejected_reason(decision: TlsVerificationDecision) -> TlsRejectionReason {
    match decision.outcome {
        TlsVerificationOutcome::Rejected { reason } => reason,
        TlsVerificationOutcome::Verified => panic!("fixture unexpectedly verified"),
    }
}

#[test]
fn valid_chain_produces_audit_bound_tls_grant() {
    let stream = stream_for("https");
    let mut verifier = new_verifier();
    let decision = verifier.verify(&stream, &observation(), NOW).unwrap();
    assert!(decision.is_verified());
    let grant = decision.grant.unwrap();
    assert_eq!(grant.sni(), "app.example.com");
    assert_eq!(grant.alpn(), "http/1.1");
    assert_eq!(grant.protocol_version(), TlsProtocolVersion::Tls13);
    assert_eq!(grant.tls_audit_anchor(), verifier.audit().tail_hash());
    verifier.audit().verify().unwrap();
}

#[test]
fn wrong_host_is_rejected_even_when_common_name_matches() {
    let stream = stream_for("https");
    let mut verifier = new_verifier();
    let mut observed = observation();
    observed.chain[0].dns_sans = vec!["other.example.com".into()];
    observed.chain[0].common_name = Some("app.example.com".into());
    let decision = verifier.verify(&stream, &observed, NOW).unwrap();
    assert_eq!(
        rejected_reason(decision),
        TlsRejectionReason::HostnameMismatch
    );
}

#[test]
fn common_name_is_never_a_san_fallback() {
    let stream = stream_for("https");
    let mut verifier = new_verifier();
    let mut observed = observation();
    observed.chain[0].dns_sans.clear();
    observed.chain[0].common_name = Some("app.example.com".into());
    let decision = verifier.verify(&stream, &observed, NOW).unwrap();
    assert_eq!(
        rejected_reason(decision),
        TlsRejectionReason::MissingDnsSubjectAlternativeName
    );
}

#[test]
fn conservative_wildcard_matches_one_label_only() {
    let stream = stream_for("https");
    let mut verifier = new_verifier();
    let mut observed = observation();
    observed.chain[0].dns_sans = vec!["*.example.com".into()];
    assert!(verifier
        .verify(&stream, &observed, NOW)
        .unwrap()
        .is_verified());

    let stream = stream_for("https");
    let mut verifier = new_verifier();
    let mut observed = observation();
    observed.chain[0].dns_sans = vec!["*.app.example.com".into()];
    assert_eq!(
        rejected_reason(verifier.verify(&stream, &observed, NOW).unwrap()),
        TlsRejectionReason::HostnameMismatch
    );
}

#[test]
fn expired_leaf_is_rejected() {
    let stream = stream_for("https");
    let mut verifier = new_verifier();
    let mut observed = observation();
    observed.chain[0].not_after_epoch_seconds = NOW - 1;
    assert_eq!(
        rejected_reason(verifier.verify(&stream, &observed, NOW).unwrap()),
        TlsRejectionReason::CertificateExpired {
            certificate_index: 0
        }
    );
}

#[test]
fn untrusted_root_and_broken_issuer_link_are_rejected() {
    let stream = stream_for("https");
    let mut untrusted = TlsPeerVerifier::new(
        TlsPeerVerifierConfig {
            verifier_id: "untrusted-fixture".into(),
            limits: TlsLimits::default(),
        },
        TlsTrustStore::new([hex('4')]).unwrap(),
    )
    .unwrap();
    assert_eq!(
        rejected_reason(untrusted.verify(&stream, &observation(), NOW).unwrap()),
        TlsRejectionReason::UntrustedRoot
    );

    let stream = stream_for("https");
    let mut verifier = new_verifier();
    let mut observed = observation();
    observed.chain[0].issuer_spki_sha256 = hex('d');
    assert_eq!(
        rejected_reason(verifier.verify(&stream, &observed, NOW).unwrap()),
        TlsRejectionReason::IssuerLinkMismatch {
            certificate_index: 0
        }
    );
}

#[test]
fn unsupported_protocol_alpn_and_replay_features_are_rejected() {
    let stream = stream_for("https");
    let mut verifier = new_verifier();
    let mut observed = observation();
    observed.protocol_version = TlsProtocolVersion::Tls11;
    assert_eq!(
        rejected_reason(verifier.verify(&stream, &observed, NOW).unwrap()),
        TlsRejectionReason::UnsupportedProtocolVersion
    );

    let stream = stream_for("https");
    let mut verifier = new_verifier();
    let mut observed = observation();
    observed.alpn = Some("h2".into());
    assert_eq!(
        rejected_reason(verifier.verify(&stream, &observed, NOW).unwrap()),
        TlsRejectionReason::UnsupportedAlpn
    );

    let stream = stream_for("https");
    let mut verifier = new_verifier();
    let mut observed = observation();
    observed.early_data_accepted = true;
    assert_eq!(
        rejected_reason(verifier.verify(&stream, &observed, NOW).unwrap()),
        TlsRejectionReason::EarlyDataRejected
    );

    let stream = stream_for("https");
    let mut verifier = new_verifier();
    let mut observed = observation();
    observed.session_resumed = true;
    assert_eq!(
        rejected_reason(verifier.verify(&stream, &observed, NOW).unwrap()),
        TlsRejectionReason::SessionResumptionRejected
    );
}

#[test]
fn handshake_budgets_and_http_streams_are_rejected() {
    let stream = stream_for("https");
    let mut verifier = new_verifier();
    let mut observed = observation();
    observed.elapsed_milliseconds = TlsLimits::default().handshake_timeout_milliseconds + 1;
    assert_eq!(
        rejected_reason(verifier.verify(&stream, &observed, NOW).unwrap()),
        TlsRejectionReason::HandshakeTimeout
    );

    let stream = stream_for("http");
    let mut verifier = new_verifier();
    assert_eq!(
        rejected_reason(verifier.verify(&stream, &observation(), NOW).unwrap()),
        TlsRejectionReason::HttpTransport
    );
}

#[test]
fn audit_excludes_certificate_names_and_common_name_content() {
    let stream = stream_for("https");
    let mut verifier = new_verifier();
    let mut observed = observation();
    observed.chain[0]
        .dns_sans
        .push("certificate-secret.example".into());
    observed.chain[0].common_name = Some("common-name-secret-value".into());
    verifier.verify(&stream, &observed, NOW).unwrap();
    let serialized = serde_json::to_string(verifier.audit().records()).unwrap();
    assert!(!serialized.contains("certificate-secret"));
    assert!(!serialized.contains("common-name-secret"));
    verifier.audit().verify().unwrap();
}
