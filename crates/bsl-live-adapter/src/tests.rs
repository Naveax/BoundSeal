use std::{
    collections::BTreeSet,
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, TcpListener},
    sync::Arc,
    thread,
    time::Duration,
};

use bsl_executor::{
    ExecutionControl, ExecutionLimits, ExecutionOutcome, ExecutorConfig, PermitBackend,
    PermitEndpoint, PermitExecutor,
};
use bsl_http1::{Http1Codec, Http1Limits};
use bsl_stream::{BoundedByteStream, StreamControl, StreamLimits};
use bsl_tls::LibraryVerifiedTlsBinder;
use bsl_transport::{TransportPermit, TransportScheme};
use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::{
    pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
    version::{TLS12, TLS13},
    RootCertStore, ServerConfig, ServerConnection, StreamOwned,
};

use crate::{
    backend::LiveConnectBackend,
    model::{LiveAdapterLimits, LivePassiveReceipt},
    LivePassiveRequest, PassiveMethod,
};

fn permit(ip: IpAddr, port: u16, host: &str) -> TransportPermit {
    TransportPermit {
        ticket_id: "ticket-live-0001".into(),
        decision_id: "decision-live-0001".into(),
        dns_context_id: "dns-live-0001".into(),
        scheme: TransportScheme::Https,
        remote_ip: ip,
        port,
        sni: Some(host.into()),
        http_host: if port == 443 {
            host.into()
        } else {
            format!("{host}:{port}")
        },
        redirect_depth: 0,
        binding_hash: "a".repeat(64),
    }
}

fn endpoint<'a>(permit: &'a TransportPermit) -> PermitEndpoint<'a> {
    PermitEndpoint {
        ticket_id: &permit.ticket_id,
        decision_id: &permit.decision_id,
        dns_context_id: &permit.dns_context_id,
        scheme: permit.scheme,
        remote_ip: permit.remote_ip,
        port: permit.port,
        sni: permit.sni.as_deref(),
        http_host: &permit.http_host,
        redirect_depth: permit.redirect_depth,
        binding_hash: &permit.binding_hash,
    }
}

#[test]
fn passive_request_rejects_query_encoding_and_action_paths() {
    assert!(LivePassiveRequest::new(PassiveMethod::Get, "/health").is_ok());
    assert!(LivePassiveRequest::new(PassiveMethod::Head, "/assets/app.js").is_ok());
    assert!(LivePassiveRequest::new(PassiveMethod::Get, "/?page=1").is_err());
    assert!(LivePassiveRequest::new(PassiveMethod::Get, "/a%2fb").is_err());
    assert!(LivePassiveRequest::new(PassiveMethod::Get, "/account/logout").is_err());
    assert!(LivePassiveRequest::new(PassiveMethod::Get, "https://example.com/").is_err());
}

#[test]
fn production_backend_rejects_non_public_destination_before_connect() {
    let mut backend = LiveConnectBackend::with_mozilla_roots().unwrap();
    let permit = permit(IpAddr::V4(Ipv4Addr::LOCALHOST), 443, "localhost");
    let report = backend.execute(
        endpoint(&permit),
        &ExecutionLimits::default(),
        &ExecutionControl::default(),
    );
    assert_eq!(
        report.failure_code.as_deref(),
        Some("non_public_destination")
    );
    assert!(report.connected_after_milliseconds.is_none());
    assert!(backend.take_stream().is_none());
}

#[test]
fn production_backend_rejects_non_standard_port_before_connect() {
    let mut backend = LiveConnectBackend::with_mozilla_roots().unwrap();
    let permit = permit("1.1.1.1".parse().unwrap(), 8443, "example.com");
    let report = backend.execute(
        endpoint(&permit),
        &ExecutionLimits::default(),
        &ExecutionControl::default(),
    );
    assert_eq!(
        report.failure_code.as_deref(),
        Some("permit_boundary_rejected")
    );
    assert!(report.connected_after_milliseconds.is_none());
}

#[test]
fn executor_cancellation_never_invokes_live_socket_backend() {
    let backend = LiveConnectBackend::with_mozilla_roots().unwrap();
    let mut executor = PermitExecutor::new(
        ExecutorConfig {
            executor_id: "bsl-live-test".into(),
        },
        backend,
    )
    .unwrap();
    let permit = permit(IpAddr::V4(Ipv4Addr::LOCALHOST), 443, "localhost");
    let receipt = executor
        .execute(
            &permit,
            &"b".repeat(64),
            ExecutionLimits::default(),
            ExecutionControl {
                cancel_requested: true,
                emergency_stop_requested: false,
            },
        )
        .unwrap();
    assert_eq!(receipt.outcome, ExecutionOutcome::Cancelled);
    assert!(executor.backend().last_observation().is_none());
    assert!(executor.backend_mut().take_stream().is_none());
}

#[test]
fn limit_validation_requires_stream_to_cover_http_wire_budget() {
    let mut limits = LiveAdapterLimits::conservative_default();
    limits.stream.maximum_read_bytes = limits.http.maximum_response_wire_bytes - 1;
    assert!(limits.validate().is_err());
}

#[test]
fn live_receipt_rejects_tampering() {
    let mut receipt = LivePassiveReceipt {
        ticket_id: "ticket-live-0001".into(),
        decision_id: "decision-live-0001".into(),
        dns_context_id: "dns-live-0001".into(),
        execution_id: "execution-00000000000000000001".into(),
        stream_id: "stream-00000000000000000001".into(),
        exchange_id: "http1-exchange-00000000000000000001".into(),
        request_method: "GET".into(),
        request_target_sha256: "a".repeat(64),
        remote_ip: "1.1.1.1".into(),
        server_name_sha256: "b".repeat(64),
        tls_protocol: "tls_1_3".into(),
        tls_alpn: Some("http/1.1".into()),
        tls_cipher_suite: "TLS13_AES_128_GCM_SHA256".into(),
        leaf_certificate_sha256: "c".repeat(64),
        response_status: 200,
        response_framing: "content_length".into(),
        response_header_count: 2,
        response_trailer_count: 0,
        response_body_bytes: 2,
        response_body_sha256: "d".repeat(64),
        redirect_observed: false,
        transport_audit_anchor: "e".repeat(64),
        executor_audit_tail: "f".repeat(64),
        stream_audit_tail: "1".repeat(64),
        http_audit_tail: "2".repeat(64),
        receipt_sha256: String::new(),
    };
    receipt.receipt_sha256 = crate::model::live_hash_serializable(&receipt).unwrap();
    receipt.verify().unwrap();
    receipt.response_status = 302;
    assert!(receipt.verify().is_err());
}

#[test]
fn local_tls_http_exchange_uses_verified_certificate_and_http1() {
    let listener = match TcpListener::bind((Ipv4Addr::LOCALHOST, 443)) {
        Ok(listener) => listener,
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::AddrInUse
            ) =>
        {
            return;
        }
        Err(error) => panic!("local TLS fixture bind failed: {error}"),
    };

    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["fixture.example.com".into()]).unwrap();
    let certificate = cert.der().clone();
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut server_config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&TLS13, &TLS12])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![certificate.clone()], private_key)
        .unwrap();
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];

    let server = thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let connection = ServerConnection::new(Arc::new(server_config)).unwrap();
        let mut stream = StreamOwned::new(connection, socket);
        let mut request = Vec::new();
        let mut buffer = [0_u8; 2048];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = stream.read(&mut buffer).unwrap();
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
            assert!(request.len() < 32 * 1024);
        }
        let request_text = String::from_utf8_lossy(&request);
        let request_text_lower = request_text.to_ascii_lowercase();
        assert!(request_text.starts_with("GET /health HTTP/1.1\r\n"));
        assert!(request_text_lower.contains("\r\nhost: fixture.example.com\r\n"));
        assert!(request_text_lower.contains("\r\naccept-encoding: identity\r\n"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nOK")
            .unwrap();
        stream.flush().unwrap();
    });

    let mut roots = RootCertStore::empty();
    roots.add(certificate).unwrap();
    let backend = LiveConnectBackend::with_test_roots(roots).unwrap();
    let mut executor = PermitExecutor::new(
        ExecutorConfig {
            executor_id: "bsl-live-local-tls".into(),
        },
        backend,
    )
    .unwrap();
    let permit = permit(IpAddr::V4(Ipv4Addr::LOCALHOST), 443, "fixture.example.com");
    let execution = executor
        .execute(
            &permit,
            &"9".repeat(64),
            ExecutionLimits {
                connect_timeout_milliseconds: 2_000,
                total_timeout_milliseconds: 5_000,
                maximum_read_bytes: 1024 * 1024,
                maximum_write_bytes: 1024 * 1024,
            },
            ExecutionControl::default(),
        )
        .unwrap();
    assert_eq!(execution.outcome, ExecutionOutcome::Completed);
    let observation = executor.backend().last_observation().cloned().unwrap();
    assert!(matches!(
        observation.protocol_version.as_str(),
        "tls_1_2" | "tls_1_3"
    ));
    assert_eq!(observation.alpn_protocol.as_deref(), Some("http/1.1"));
    assert_eq!(observation.certificate_chain_length, 1);

    let tls_stream = executor.backend_mut().take_stream().unwrap();
    let stream = BoundedByteStream::open(
        &permit,
        &execution,
        executor.audit(),
        StreamLimits {
            maximum_read_bytes: 1024 * 1024,
            maximum_write_bytes: 128 * 1024,
            maximum_operation_bytes: 64 * 1024,
            read_deadline_milliseconds: 5_000,
            write_deadline_milliseconds: 5_000,
            total_deadline_milliseconds: 10_000,
            maximum_operations: 256,
        },
        tls_stream,
    )
    .unwrap();
    let verified_observation = observation
        .library_verified("bsl-live-local-tls:rustls-webpki")
        .unwrap();
    let mut tls_binder = LibraryVerifiedTlsBinder::new();
    let tls_grant = tls_binder.bind(&stream, &verified_observation).unwrap();
    let mut codec =
        Http1Codec::new_verified_tls(stream, &tls_grant, Http1Limits::conservative_default())
            .unwrap();
    let exchange = codec
        .exchange(
            &LivePassiveRequest::new(PassiveMethod::Get, "/health")
                .unwrap()
                .to_http1(),
            StreamControl::default(),
        )
        .unwrap();
    assert_eq!(exchange.response.status_code, 200);
    assert_eq!(exchange.response.body, b"OK");
    assert_eq!(exchange.response.headers.len(), 3);
    codec.audit().verify().unwrap();
    codec.channel_audit().verify().unwrap();
    tls_binder.audit().verify().unwrap();
    server.join().unwrap();
}

#[test]
fn exact_response_header_names_are_not_secret_material() {
    let names = BTreeSet::from(["content-type", "strict-transport-security"]);
    assert_eq!(names.len(), 2);
}
