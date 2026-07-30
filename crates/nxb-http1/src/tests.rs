use std::collections::BTreeMap;

use crate::{
    parser::{parse_response, ParseProgress},
    Http1AuditChain, Http1AuditError, Http1AuditEvent, Http1Error, Http1Framing,
    Http1Limits,
};

fn parse_complete(bytes: &[u8]) -> crate::Http1Response {
    match parse_response(bytes, true, "GET", &Http1Limits::default()).unwrap() {
        ParseProgress::Complete(value) => value.response,
        ParseProgress::Incomplete => panic!("fixture should be complete"),
    }
}

#[test]
fn accepts_identical_duplicate_content_length_values() {
    let response = parse_complete(
        b"HTTP/1.1 200 OK\r\nContent-Length: 4, 4\r\nContent-Length: 4\r\n\r\ntest",
    );
    assert_eq!(response.body, b"test");
    assert_eq!(response.framing, Http1Framing::ContentLength(4));
}

#[test]
fn rejects_bare_lf_response_framing() {
    let error = parse_response(
        b"HTTP/1.1 200 OK\nContent-Length: 0\n\n",
        true,
        "GET",
        &Http1Limits::default(),
    )
    .unwrap_err();
    assert!(matches!(
        error,
        Http1Error::TruncatedResponse(_) | Http1Error::InvalidResponse(_)
    ));
}

#[test]
fn rejects_chunk_extensions_to_keep_framing_deterministic() {
    let error = parse_response(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4;foo=bar\r\ntest\r\n0\r\n\r\n",
        true,
        "GET",
        &Http1Limits::default(),
    )
    .unwrap_err();
    assert!(matches!(error, Http1Error::InvalidResponse(_)));
}

#[test]
fn head_response_ignores_declared_body_framing() {
    let result = parse_response(
        b"HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\n",
        false,
        "HEAD",
        &Http1Limits::default(),
    )
    .unwrap();
    let ParseProgress::Complete(parsed) = result else {
        panic!("HEAD response should complete after headers");
    };
    assert_eq!(parsed.response.framing, Http1Framing::NoBody);
    assert!(parsed.response.body.is_empty());
}

#[test]
fn audit_detects_modified_exchange_metadata() {
    let mut chain = Http1AuditChain::new("a".repeat(64)).unwrap();
    chain.append(audit_event()).unwrap();
    chain.records_mut()[0].event.response_status = 500;
    assert_eq!(
        chain.verify(),
        Err(Http1AuditError::RecordHashMismatch { record_index: 0 })
    );
}

fn audit_event() -> Http1AuditEvent {
    Http1AuditEvent {
        exchange_id: "http1-exchange-0001".into(),
        stream_id: "stream-0001".into(),
        execution_id: "execution-0001".into(),
        request_method: "GET".into(),
        request_target_sha256: "b".repeat(64),
        request_wire_sha256: "c".repeat(64),
        request_body_sha256: "d".repeat(64),
        request_header_count: 3,
        request_body_bytes: 0,
        response_wire_sha256: "e".repeat(64),
        response_body_sha256: "f".repeat(64),
        response_status: 200,
        response_version: "http_1_1".into(),
        response_framing: "content_length".into(),
        response_header_count: 1,
        response_trailer_count: 0,
        response_body_bytes: 4,
        interim_responses: 0,
        stream_audit_before: "1".repeat(64),
        stream_audit_after: "2".repeat(64),
        metadata: BTreeMap::new(),
    }
}
