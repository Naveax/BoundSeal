#[cfg(test)]
mod tests {
    use super::*;

    fn stream(scheme: &str) -> StreamBindingSnapshot {
        StreamBindingSnapshot {
            stream_id: "stream-1".into(),
            execution_id: "execution-1".into(),
            ticket_id: "ticket-1".into(),
            binding_hash: "a".repeat(64),
            stream_audit_anchor: "b".repeat(64),
            scheme: scheme.into(),
            sni: (scheme == "https").then(|| "app.example.com".into()),
            http_host: "app.example.com".into(),
            port: if scheme == "https" { 443 } else { 80 },
            redirect_depth: 0,
        }
    }

    fn tls() -> TlsBindingSnapshot {
        TlsBindingSnapshot {
            tls_session_id: "tls-1".into(),
            stream_id: "stream-1".into(),
            execution_id: "execution-1".into(),
            ticket_id: "ticket-1".into(),
            binding_hash: "a".repeat(64),
            stream_audit_anchor: "b".repeat(64),
            sni: "app.example.com".into(),
            http_host: "app.example.com".into(),
            port: 443,
            redirect_depth: 0,
            alpn: "http/1.1".into(),
            tls_audit_anchor: "c".repeat(64),
            leaf_fingerprint_sha256: "d".repeat(64),
        }
    }

    #[test]
    fn tls_channel_requires_exact_binding_and_is_one_use() {
        let mut grant = HttpChannelGrant::verified_tls("channel-1", stream("https"), tls()).unwrap();
        let lease = grant.consume().unwrap();
        assert_eq!(lease.kind, ChannelKind::VerifiedTls);
        assert_eq!(grant.consume(), Err(ChannelError::ChannelReplay));
    }

    #[test]
    fn plain_channel_rejects_sensitive_headers() {
        let mut grant = HttpChannelGrant::plain("channel-1", stream("http")).unwrap();
        let lease = grant.consume().unwrap();
        let header = RequestHeader::new(
            HeaderName::parse("Authorization").unwrap(),
            b"Bearer secret".to_vec(),
        )
        .unwrap();
        let error = TypedRequestPlan::build(
            &lease,
            HttpMethod::Get,
            RequestTarget::new("/", []).unwrap(),
            vec![header],
            BodySource::Empty,
            None,
        )
        .unwrap_err();
        assert_eq!(error, ChannelError::SensitiveHeadersRequireTls);
    }

    #[test]
    fn request_target_is_canonical_and_body_is_not_debugged() {
        let target = RequestTarget::new(
            "/search",
            [("q".into(), "a b".into()), ("page".into(), "1".into())],
        )
        .unwrap();
        assert_eq!(target.as_str(), "/search?page=1&q=a%20b");
        let body = BodySource::Fixed(b"body-secret".to_vec());
        assert!(!format!("{body:?}").contains("body-secret"));
    }

    #[test]
    fn response_receipt_excludes_raw_preview() {
        let mut grant = HttpChannelGrant::plain("channel-1", stream("http")).unwrap();
        let lease = grant.consume().unwrap();
        let envelope = ResponseEnvelope::capture(
            &lease,
            200,
            [("Content-Type".into(), b"text/plain; charset=utf-8".to_vec())],
            b"response-secret",
            false,
            "e".repeat(64),
            ResponseLimits::default(),
        )
        .unwrap();
        let serialized = serde_json::to_string(&envelope.receipt()).unwrap();
        assert!(!serialized.contains("response-secret"));
        assert_eq!(envelope.preview.bytes(), b"response-secret");
    }

    #[test]
    fn channel_audit_detects_tampering_by_recalculation() {
        let mut chain = ChannelAuditChain::new();
        chain
            .append(ChannelAuditEvent {
                action: "request_planned".into(),
                channel_id: "channel-1".into(),
                channel_kind: "plain_http".into(),
                authority: "app.example.com".into(),
                stream_id: "stream-1".into(),
                ticket_id: "ticket-1".into(),
                request_fingerprint_sha256: Some("a".repeat(64)),
                response_body_sha256: None,
                anchor: "b".repeat(64),
                metadata: BTreeMap::new(),
            })
            .unwrap();
        chain.verify().unwrap();
    }
}
