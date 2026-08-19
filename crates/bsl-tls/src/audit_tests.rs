use std::collections::BTreeMap;

use crate::{TlsAuditChain, TlsAuditError, TlsAuditEvent};

fn event() -> TlsAuditEvent {
    TlsAuditEvent {
        verification_id: "tls-verification-1".into(),
        tls_session_id: Some("tls-session-1".into()),
        verifier_id: "verifier-1".into(),
        status: "verified".into(),
        reason: "verified".into(),
        stream_id: "stream-1".into(),
        execution_id: "execution-1".into(),
        ticket_id: "ticket-1".into(),
        binding_hash: "a".repeat(64),
        stream_audit_anchor: "b".repeat(64),
        sni: "app.example.com".into(),
        http_host: "app.example.com".into(),
        port: 443,
        redirect_depth: 0,
        protocol_version: "tls_1_3".into(),
        alpn: "http/1.1".into(),
        handshake_read_bytes: 100,
        handshake_write_bytes: 50,
        elapsed_milliseconds: 10,
        chain_depth: 3,
        chain_fingerprint_sha256: "c".repeat(64),
        leaf_fingerprint_sha256: Some("d".repeat(64)),
        root_fingerprint_sha256: Some("e".repeat(64)),
        matched_san_sha256: Some("f".repeat(64)),
        early_data_accepted: false,
        renegotiation_observed: false,
        session_resumed: false,
        details: BTreeMap::new(),
    }
}

#[test]
fn modified_tls_audit_event_is_detected() {
    let mut chain = TlsAuditChain::new();
    chain.append(event()).unwrap();
    chain.records_mut()[0].event.alpn = "h2".into();
    assert_eq!(
        chain.verify(),
        Err(TlsAuditError::RecordHashMismatch { record_index: 0 })
    );
}
