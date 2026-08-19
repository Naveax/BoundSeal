impl PassiveAnalyzer for TlsMetadataAnalyzer {
    fn analyze(&self, response: &ResponseObservation) -> Result<Vec<Finding>, AnalyzerError> {
        response.validate()?;
        let origin = response.origin()?;
        let endpoint = response.endpoint_sha256();
        let mut findings = Vec::new();
        let Some(tls) = &response.tls else {
            if response.url.scheme() == "https" {
                push_finding(
                    &mut findings,
                    "BSL-TLS-001",
                    "HTTPS response lacks verified TLS metadata",
                    Severity::High,
                    Confidence::High,
                    &origin,
                    &endpoint,
                    b"missing:tls-observation",
                    "No verified TLS identity observation was attached to the HTTPS response.",
                    BTreeMap::new(),
                )?;
            }
            return Ok(findings);
        };
        if !tls.verified || !tls.hostname_covered || !is_sha256(&tls.trusted_root_sha256) {
            push_finding(
                &mut findings,
                "BSL-TLS-002",
                "TLS peer identity was not fully verified",
                Severity::High,
                Confidence::High,
                &origin,
                &endpoint,
                hash_serializable(tls).as_bytes(),
                "The TLS observation did not establish trusted hostname-bound peer identity.",
                BTreeMap::new(),
            )?;
        }
        if !matches!(tls.protocol.as_str(), "tls_1_2" | "tls_1_3") {
            push_finding(
                &mut findings,
                "BSL-TLS-003",
                "Unsupported legacy TLS protocol observed",
                Severity::High,
                Confidence::High,
                &origin,
                &endpoint,
                tls.protocol.as_bytes(),
                "The protocol is outside the accepted TLS 1.2/1.3 policy.",
                BTreeMap::from([("protocol".into(), tls.protocol.clone())]),
            )?;
        }
        if tls.alpn != "http/1.1" {
            push_finding(
                &mut findings,
                "BSL-TLS-004",
                "Unexpected ALPN for the HTTP/1 channel",
                Severity::Medium,
                Confidence::High,
                &origin,
                &endpoint,
                tls.alpn.as_bytes(),
                "The negotiated ALPN does not match the current HTTP/1-only contract.",
                BTreeMap::from([("alpn".into(), tls.alpn.clone())]),
            )?;
        }
        let remaining = tls
            .leaf_not_after_epoch_seconds
            .saturating_sub(tls.observed_at_epoch_seconds);
        if remaining < 30 * 24 * 60 * 60 {
            push_finding(
                &mut findings,
                "BSL-TLS-005",
                "TLS certificate expires soon",
                Severity::Low,
                Confidence::High,
                &origin,
                &endpoint,
                remaining.to_string().as_bytes(),
                "The leaf certificate validity window has less than thirty days remaining.",
                BTreeMap::from([("remaining_seconds".into(), remaining.to_string())]),
            )?;
        }
        if tls.session_resumed || tls.early_data_accepted {
            push_finding(
                &mut findings,
                "BSL-TLS-006",
                "TLS replay-related feature conflicts with the frozen channel policy",
                Severity::Medium,
                Confidence::High,
                &origin,
                &endpoint,
                hash_serializable(&(tls.session_resumed, tls.early_data_accepted)).as_bytes(),
                "Session resumption or early data was observed while the current policy disables both.",
                BTreeMap::from([
                    ("session_resumed".into(), tls.session_resumed.to_string()),
                    ("early_data".into(), tls.early_data_accepted.to_string()),
                ]),
            )?;
        }
        Ok(findings)
    }
}

#[derive(Debug, Default)]
pub struct RedirectAnalyzer;

