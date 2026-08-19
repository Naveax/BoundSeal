fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(headers: Vec<ObservedHeader>) -> ResponseObservation {
        ResponseObservation {
            url: Url::parse("https://app.example.com/account").unwrap(),
            status: 200,
            authenticated: true,
            headers,
            body_sha256: "a".repeat(64),
            body_bytes: 100,
            tls: Some(TlsObservation {
                verified: true,
                protocol: "tls_1_3".into(),
                alpn: "http/1.1".into(),
                leaf_not_after_epoch_seconds: 2_000_000,
                observed_at_epoch_seconds: 1_000_000,
                hostname_covered: true,
                wildcard_san: false,
                chain_depth: 3,
                trusted_root_sha256: "b".repeat(64),
                session_resumed: false,
                early_data_accepted: false,
            }),
        }
    }

    #[test]
    fn header_and_cache_analyzers_emit_redacted_findings() {
        let observed = response(vec![
            ObservedHeader::new("Server", b"Example/1.2".to_vec()).unwrap(),
            ObservedHeader::new("Cache-Control", b"public".to_vec()).unwrap(),
        ]);
        let headers = HeaderSecurityAnalyzer.analyze(&observed).unwrap();
        let cache = CachePolicyAnalyzer.analyze(&observed).unwrap();
        assert!(headers.iter().any(|finding| finding.rule_id == "BSL-HDR-001"));
        assert!(cache.iter().any(|finding| finding.rule_id == "BSL-CACHE-001"));
        let serialized = serde_json::to_string(&(headers, cache)).unwrap();
        assert!(!serialized.contains("Example/1.2"));
    }

    #[test]
    fn cookie_analyzer_flags_missing_security_attributes_without_value_disclosure() {
        let secret = "cookie-secret-value";
        let observed = response(vec![ObservedHeader::new(
            "Set-Cookie",
            format!("session={secret}; Path=/").into_bytes(),
        )
        .unwrap()]);
        let findings = CookieSecurityAnalyzer.analyze(&observed).unwrap();
        assert!(findings.iter().any(|finding| finding.rule_id == "BSL-COOKIE-001"));
        assert!(findings.iter().any(|finding| finding.rule_id == "BSL-COOKIE-002"));
        assert!(!serde_json::to_string(&findings).unwrap().contains(secret));
    }

    #[test]
    fn cors_and_redirect_downgrades_are_detected() {
        let observed = response(vec![
            ObservedHeader::new("Access-Control-Allow-Origin", b"*".to_vec()).unwrap(),
            ObservedHeader::new("Access-Control-Allow-Credentials", b"true".to_vec()).unwrap(),
        ]);
        assert!(CorsAnalyzer
            .analyze(&observed)
            .unwrap()
            .iter()
            .any(|finding| finding.rule_id == "BSL-CORS-001"));
        let redirect = RedirectAnalyzer
            .analyze_redirect(&RedirectObservation {
                from_url: "https://app.example.com/start".into(),
                to_url: "http://other.example/next".into(),
                status: 307,
                original_method: "POST".into(),
                next_method: "POST".into(),
                body_preserved: true,
                credential_headers_forwarded: true,
                cookie_rematerialized: false,
                session_generation_before: 1,
                session_generation_after: 1,
                chain_depth: 1,
                loop_detected: false,
            })
            .unwrap();
        assert!(redirect.iter().any(|finding| finding.rule_id == "BSL-REDIRECT-001"));
        assert!(redirect.iter().any(|finding| finding.rule_id == "BSL-REDIRECT-002"));
    }
}
