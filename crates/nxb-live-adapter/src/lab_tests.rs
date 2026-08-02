use std::{
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener},
    path::PathBuf,
    sync::Arc,
    thread,
    time::Duration,
};

use nxb_executor::{
    ExecutionControl, ExecutionLimits, ExecutionOutcome, ExecutorConfig, PermitExecutor,
};
use nxb_http1::{Http1Codec, Http1Error, Http1Limits};
use nxb_stream::{BoundedByteStream, StreamControl, StreamLimits};
use nxb_transport::{TransportPermit, TransportScheme};
use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    version::{TLS12, TLS13},
    RootCertStore, ServerConfig, ServerConnection, StreamOwned,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{backend::LiveConnectBackend, LivePassiveRequest, PassiveMethod};

#[derive(Clone)]
enum LabBehavior {
    Reply(Vec<u8>),
    DelayReply(Duration, Vec<u8>),
}

#[derive(Debug, Clone, Serialize)]
struct LabScenarioReceipt {
    scenario: String,
    expected: String,
    observed: String,
    passed: bool,
    evidence_sha256: String,
}

#[derive(Debug, Clone, Serialize)]
struct LabTranscript {
    version: u32,
    mode: String,
    scenario_count: u64,
    scenarios: Vec<LabScenarioReceipt>,
    transcript_sha256: String,
}

struct LabServer {
    address: SocketAddr,
    certificate: CertificateDer<'static>,
    handle: thread::JoinHandle<()>,
}

fn logical_permit(host: &str) -> TransportPermit {
    TransportPermit {
        ticket_id: "ticket-lab-0001".into(),
        decision_id: "decision-lab-0001".into(),
        dns_context_id: "dns-lab-0001".into(),
        scheme: TransportScheme::Https,
        remote_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        port: 443,
        sni: Some(host.into()),
        http_host: host.into(),
        redirect_depth: 0,
        binding_hash: "a".repeat(64),
    }
}

fn start_server(certificate_name: &str, behavior: LabBehavior) -> LabServer {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec![certificate_name.into()]).unwrap();
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

    let handle = thread::spawn(move || {
        let Ok((socket, _)) = listener.accept() else {
            return;
        };
        let _ = socket.set_read_timeout(Some(Duration::from_secs(3)));
        let _ = socket.set_write_timeout(Some(Duration::from_secs(3)));
        let Ok(connection) = ServerConnection::new(Arc::new(server_config)) else {
            return;
        };
        let mut stream = StreamOwned::new(connection, socket);
        let mut request = Vec::new();
        let mut buffer = [0_u8; 2048];
        loop {
            match stream.read(&mut buffer) {
                Ok(0) | Err(_) => return,
                Ok(read) => {
                    request.extend_from_slice(&buffer[..read]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                    if request.len() > 32 * 1024 {
                        return;
                    }
                }
            }
        }
        match behavior {
            LabBehavior::Reply(bytes) => {
                let _ = stream.write_all(&bytes);
                let _ = stream.flush();
            }
            LabBehavior::DelayReply(delay, bytes) => {
                thread::sleep(delay);
                let _ = stream.write_all(&bytes);
                let _ = stream.flush();
            }
        }
    });

    LabServer {
        address,
        certificate,
        handle,
    }
}

fn roots_with(certificate: CertificateDer<'static>) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.add(certificate).unwrap();
    roots
}

fn stream_limits(read_deadline_milliseconds: u64) -> StreamLimits {
    StreamLimits {
        maximum_read_bytes: 1024 * 1024,
        maximum_write_bytes: 128 * 1024,
        maximum_operation_bytes: 64 * 1024,
        read_deadline_milliseconds,
        write_deadline_milliseconds: 2_000,
        total_deadline_milliseconds: 5_000,
        maximum_operations: 256,
    }
}

fn run_exchange(
    server: &LabServer,
    trust: RootCertStore,
    sni: &str,
    http_limits: Http1Limits,
    read_deadline_milliseconds: u64,
) -> Result<u16, String> {
    let permit = logical_permit(sni);
    let backend = LiveConnectBackend::with_test_roots_on_socket(trust, server.address)
        .map_err(|error| error.to_string())?;
    let mut executor = PermitExecutor::new(
        ExecutorConfig {
            executor_id: "nxb130-lab".into(),
        },
        backend,
    )
    .map_err(|error| error.to_string())?;
    let execution = executor
        .execute(
            &permit,
            &"9".repeat(64),
            ExecutionLimits {
                connect_timeout_milliseconds: 1_000,
                total_timeout_milliseconds: 3_000,
                maximum_read_bytes: 1024 * 1024,
                maximum_write_bytes: 1024 * 1024,
            },
            ExecutionControl::default(),
        )
        .map_err(|error| error.to_string())?;
    if execution.outcome != ExecutionOutcome::Completed {
        return Err(execution
            .failure_code
            .unwrap_or_else(|| "connection_failed".into()));
    }
    let tls_stream = executor
        .backend_mut()
        .take_stream()
        .ok_or_else(|| "missing_tls_stream".to_string())?;
    let stream = BoundedByteStream::open(
        &permit,
        &execution,
        executor.audit(),
        stream_limits(read_deadline_milliseconds),
        tls_stream,
    )
    .map_err(|error| error.to_string())?;
    let mut codec = Http1Codec::new(stream, http_limits).map_err(|error| error.to_string())?;
    codec
        .exchange(
            &LivePassiveRequest::new(PassiveMethod::Get, "/health")
                .unwrap()
                .to_http1(),
            StreamControl::default(),
        )
        .map(|exchange| exchange.response.status_code)
        .map_err(|error| classify_http_error(&error))
}

fn classify_http_error(error: &Http1Error) -> String {
    match error {
        Http1Error::InvalidResponse(_) => "invalid_response".into(),
        Http1Error::TruncatedResponse(_) => "truncated_response".into(),
        Http1Error::Stream(_) | Http1Error::StreamState { .. } | Http1Error::StreamOutcome { .. } => {
            "stream_failure".into()
        }
        other => format!("{other:?}").to_ascii_lowercase(),
    }
}

fn record(scenario: &str, expected: &str, observed: String) -> LabScenarioReceipt {
    let passed = observed == expected;
    LabScenarioReceipt {
        scenario: scenario.into(),
        expected: expected.into(),
        evidence_sha256: hash_bytes(format!("{scenario}\0{expected}\0{observed}").as_bytes()),
        observed,
        passed,
    }
}

fn finish_server(server: LabServer) {
    server.handle.join().unwrap();
}

fn hash_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").unwrap();
    }
    output
}

fn write_transcript(scenarios: Vec<LabScenarioReceipt>) {
    assert!(scenarios.iter().all(|scenario| scenario.passed));
    let mut transcript = LabTranscript {
        version: 1,
        mode: "local-test-only-no-public-network".into(),
        scenario_count: scenarios.len() as u64,
        scenarios,
        transcript_sha256: String::new(),
    };
    transcript.transcript_sha256 = hash_bytes(&serde_json::to_vec(&transcript).unwrap());
    if let Ok(path) = std::env::var("NXB130_TRANSCRIPT_PATH") {
        let path = PathBuf::from(path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, serde_json::to_vec_pretty(&transcript).unwrap()).unwrap();
    }
}

#[test]
fn adversarial_local_lab_produces_sanitized_transcript() {
    let mut scenarios = Vec::new();

    let server = start_server(
        "localhost",
        LabBehavior::Reply(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nOK".to_vec(),
        ),
    );
    let observed = run_exchange(
        &server,
        roots_with(server.certificate.clone()),
        "localhost",
        Http1Limits::conservative_default(),
        2_000,
    )
    .map(|status| format!("status_{status}"))
    .unwrap_or_else(|error| error);
    scenarios.push(record("valid_tls_http1", "status_200", observed));
    finish_server(server);

    let server = start_server(
        "wrong.example",
        LabBehavior::Reply(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec()),
    );
    let observed = run_exchange(
        &server,
        roots_with(server.certificate.clone()),
        "localhost",
        Http1Limits::conservative_default(),
        2_000,
    )
    .err()
    .unwrap_or_else(|| "unexpected_success".into());
    scenarios.push(record("wrong_hostname", "tls_io_invalid_data", observed));
    finish_server(server);

    let trusted = generate_simple_self_signed(vec!["localhost".into()])
        .unwrap()
        .cert
        .der()
        .clone();
    let server = start_server(
        "localhost",
        LabBehavior::Reply(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec()),
    );
    let observed = run_exchange(
        &server,
        roots_with(trusted),
        "localhost",
        Http1Limits::conservative_default(),
        2_000,
    )
    .err()
    .unwrap_or_else(|| "unexpected_success".into());
    scenarios.push(record("untrusted_certificate", "tls_io_invalid_data", observed));
    finish_server(server);

    let server = start_server(
        "localhost",
        LabBehavior::Reply(
            b"HTTP/1.1 302 Found\r\nLocation: https://other.example/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
        ),
    );
    let observed = run_exchange(
        &server,
        roots_with(server.certificate.clone()),
        "localhost",
        Http1Limits::conservative_default(),
        2_000,
    )
    .map(|status| format!("status_{status}_not_followed"))
    .unwrap_or_else(|error| error);
    scenarios.push(record(
        "redirect_not_followed",
        "status_302_not_followed",
        observed,
    ));
    finish_server(server);

    let mut header_limits = Http1Limits::conservative_default();
    header_limits.maximum_response_header_bytes = 1024;
    header_limits.maximum_header_value_bytes = 1024;
    let oversized = format!(
        "HTTP/1.1 200 OK\r\nX-Oversized: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        "a".repeat(2048)
    )
    .into_bytes();
    let server = start_server("localhost", LabBehavior::Reply(oversized));
    let observed = run_exchange(
        &server,
        roots_with(server.certificate.clone()),
        "localhost",
        header_limits,
        2_000,
    )
    .err()
    .unwrap_or_else(|| "unexpected_success".into());
    scenarios.push(record("oversized_header", "invalid_response", observed));
    finish_server(server);

    let server = start_server(
        "localhost",
        LabBehavior::Reply(
            b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nOK".to_vec(),
        ),
    );
    let observed = run_exchange(
        &server,
        roots_with(server.certificate.clone()),
        "localhost",
        Http1Limits::conservative_default(),
        2_000,
    )
    .err()
    .unwrap_or_else(|| "unexpected_success".into());
    scenarios.push(record(
        "truncated_content_length",
        "truncated_response",
        observed,
    ));
    finish_server(server);

    let server = start_server(
        "localhost",
        LabBehavior::Reply(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\nZZ\r\nBAD\r\n0\r\n\r\n".to_vec(),
        ),
    );
    let observed = run_exchange(
        &server,
        roots_with(server.certificate.clone()),
        "localhost",
        Http1Limits::conservative_default(),
        2_000,
    )
    .err()
    .unwrap_or_else(|| "unexpected_success".into());
    scenarios.push(record("malformed_chunk", "invalid_response", observed));
    finish_server(server);

    let server = start_server(
        "localhost",
        LabBehavior::DelayReply(
            Duration::from_millis(300),
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
        ),
    );
    let observed = run_exchange(
        &server,
        roots_with(server.certificate.clone()),
        "localhost",
        Http1Limits::conservative_default(),
        50,
    )
    .err()
    .unwrap_or_else(|| "unexpected_success".into());
    scenarios.push(record("read_timeout", "stream_failure", observed));
    finish_server(server);

    write_transcript(scenarios);
}

#[test]
fn production_constructor_still_rejects_loopback() {
    let mut backend = LiveConnectBackend::with_mozilla_roots().unwrap();
    let permit = logical_permit("localhost");
    let report = nxb_executor::PermitBackend::execute(
        &mut backend,
        nxb_executor::PermitEndpoint {
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
        },
        &ExecutionLimits::default(),
        &ExecutionControl::default(),
    );
    assert_eq!(report.failure_code.as_deref(), Some("non_public_destination"));
}
