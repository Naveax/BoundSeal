use std::collections::VecDeque;

use nxb_executor::{
    ExecutionControl, ExecutionLimits, ExecutorConfig, PermitExecutor, SyntheticBackend,
    SyntheticScenario,
};
use nxb_http1::{
    Http1Codec, Http1Error, Http1Framing, Http1Header, Http1Limits, Http1Request,
};
use nxb_stream::{BoundedByteStream, StreamLimits};
use nxb_stream_fixture::{FixtureReadEvent, FixtureWriteEvent, InMemoryDuplex};
use nxb_transport::{TransportPermit, TransportScheme};

use crate::{conversation_fixture, scripted_fixture, Http1FixtureConfig};

fn permit() -> TransportPermit {
    TransportPermit {
        ticket_id: "ticket-http1-0001".into(),
        decision_id: "decision-http1-0001".into(),
        dns_context_id: "navigation-http1-1".into(),
        scheme: TransportScheme::Https,
        remote_ip: "1.1.1.1".parse().unwrap(),
        port: 443,
        sni: Some("app.example.com".into()),
        http_host: "app.example.com".into(),
        redirect_depth: 0,
        binding_hash: "a".repeat(64),
    }
}

fn codec_with_backend(backend: InMemoryDuplex) -> Http1Codec<InMemoryDuplex> {
    let permit = permit();
    let mut executor = PermitExecutor::new(
        ExecutorConfig {
            executor_id: "http1-fixture-executor".into(),
        },
        SyntheticBackend::new([SyntheticScenario::success(1, 2, 0, 0)]),
    )
    .unwrap();
    let execution = executor
        .execute(
            &permit,
            &"b".repeat(64),
            ExecutionLimits::default(),
            ExecutionControl::default(),
        )
        .unwrap();
    let stream = BoundedByteStream::open(
        &permit,
        &execution,
        executor.audit(),
        StreamLimits::default(),
        backend,
    )
    .unwrap();
    Http1Codec::new(stream, Http1Limits::default()).unwrap()
}

fn codec(response: impl Into<Vec<u8>>) -> Http1Codec<InMemoryDuplex> {
    codec_with_backend(conversation_fixture(
        response,
        Http1FixtureConfig::default(),
    ))
}

fn get_request() -> Http1Request {
    Http1Request::new("GET", "/api/me?fixture=1")
}

#[test]
fn parses_fragmented_content_length_response() {
    let mut codec = codec(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-Test: yes\r\n\r\nhello".to_vec());
    let exchange = codec
        .exchange(&get_request(), Default::default())
        .unwrap();

    assert_eq!(exchange.response.status_code, 200);
    assert_eq!(exchange.response.body, b"hello");
    assert_eq!(exchange.response.framing, Http1Framing::ContentLength(5));
    assert_eq!(exchange.response.headers.len(), 2);
    assert_eq!(exchange.receipt.response_body_bytes, 5);
    codec.audit().verify().unwrap();

    let captured = codec
        .stream()
        .backend()
        .captured_writes()
        .iter()
        .flatten()
        .copied()
        .collect::<Vec<_>>();
    let request_wire = String::from_utf8(captured).unwrap();
    assert!(request_wire.contains("Host: app.example.com\r\n"));
    assert!(request_wire.contains("Content-Length: 0\r\n"));
    assert!(request_wire.ends_with("Connection: close\r\n\r\n"));
}

#[test]
fn parses_chunked_response_and_bounded_trailer() {
    let mut codec = codec(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\nX-Trace: complete\r\n\r\n"
            .to_vec(),
    );
    let exchange = codec
        .exchange(&get_request(), Default::default())
        .unwrap();

    assert_eq!(exchange.response.body, b"Wikipedia");
    assert_eq!(exchange.response.framing, Http1Framing::Chunked);
    assert_eq!(exchange.response.trailers.len(), 1);
    assert_eq!(exchange.response.trailers[0].name, "x-trace");
}

#[test]
fn accepts_bounded_interim_response_before_final_response() {
    let mut codec = codec(
        b"HTTP/1.1 103 Early Hints\r\nLink: </a.css>; rel=preload\r\n\r\nHTTP/1.1 204 No Content\r\nDate: now\r\n\r\n"
            .to_vec(),
    );
    let exchange = codec
        .exchange(&get_request(), Default::default())
        .unwrap();

    assert_eq!(exchange.response.status_code, 204);
    assert_eq!(exchange.response.interim_responses, 1);
    assert_eq!(exchange.response.framing, Http1Framing::NoBody);
}

#[test]
fn rejects_conflicting_content_length_values() {
    let mut codec = codec(
        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nContent-Length: 5\r\n\r\nhello"
            .to_vec(),
    );
    let error = codec
        .exchange(&get_request(), Default::default())
        .unwrap_err();
    assert!(matches!(error, Http1Error::InvalidResponse(_)));
}

#[test]
fn rejects_transfer_encoding_and_content_length_ambiguity() {
    let mut codec = codec(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n0\r\n\r\n"
            .to_vec(),
    );
    let error = codec
        .exchange(&get_request(), Default::default())
        .unwrap_err();
    assert!(matches!(error, Http1Error::InvalidResponse(_)));
}

#[test]
fn rejects_obsolete_folded_header_lines() {
    let mut codec = codec(
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n X-Smuggled: yes\r\n\r\n".to_vec(),
    );
    let error = codec
        .exchange(&get_request(), Default::default())
        .unwrap_err();
    assert!(matches!(error, Http1Error::InvalidResponse(_)));
}

#[test]
fn detects_truncated_content_length_body() {
    let backend = scripted_fixture(
        [
            FixtureReadEvent::Bytes {
                bytes: b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nshort".to_vec(),
                elapsed_milliseconds: 1,
            },
            FixtureReadEvent::Eof {
                elapsed_milliseconds: 0,
            },
        ],
        [FixtureWriteEvent::Accept {
            maximum_bytes: u64::MAX,
            elapsed_milliseconds: 1,
        }],
    );
    let mut codec = codec_with_backend(backend);
    let error = codec
        .exchange(&get_request(), Default::default())
        .unwrap_err();
    assert!(matches!(error, Http1Error::TruncatedResponse(_)));
}

#[test]
fn caller_cannot_override_stream_authority_or_framing_headers() {
    let backend = conversation_fixture(
        b"HTTP/1.1 204 No Content\r\n\r\n".to_vec(),
        Http1FixtureConfig::default(),
    );
    let mut codec = codec_with_backend(backend);
    let mut request = get_request();
    request
        .headers
        .push(Http1Header::new("Host", b"attacker.invalid".to_vec()));

    let error = codec.exchange(&request, Default::default()).unwrap_err();
    assert!(matches!(error, Http1Error::InvalidRequest(_)));
    assert!(codec.stream().backend().captured_writes().is_empty());
}

#[test]
fn serialized_http_audit_does_not_contain_request_or_response_body() {
    let secret_request = b"request-secret-7c8d".to_vec();
    let secret_response = b"response-secret-9f0a";
    let response = [
        b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\n".as_slice(),
        secret_response.as_slice(),
    ]
    .concat();
    let mut codec = codec(response);
    let mut request = Http1Request::new("POST", "/submit");
    request.body = secret_request.clone();
    request
        .headers
        .push(Http1Header::new("Content-Type", b"application/octet-stream".to_vec()));

    let exchange = codec.exchange(&request, Default::default()).unwrap();
    assert_eq!(exchange.response.body, secret_response);

    let serialized = serde_json::to_string(codec.audit().records()).unwrap();
    assert!(!serialized.contains(std::str::from_utf8(&secret_request).unwrap()));
    assert!(!serialized.contains(std::str::from_utf8(secret_response).unwrap()));
    assert_eq!(codec.audit().records().len(), 1);
}

#[test]
fn backpressure_retry_budget_is_enforced() {
    let mut reads = VecDeque::new();
    for _ in 0..33 {
        reads.push_back(FixtureReadEvent::Backpressure {
            elapsed_milliseconds: 0,
        });
    }
    let backend = scripted_fixture(
        reads,
        [FixtureWriteEvent::Accept {
            maximum_bytes: u64::MAX,
            elapsed_milliseconds: 0,
        }],
    );
    let mut codec = codec_with_backend(backend);
    let error = codec
        .exchange(&get_request(), Default::default())
        .unwrap_err();
    assert_eq!(error, Http1Error::BackpressureBudgetExceeded);
}
