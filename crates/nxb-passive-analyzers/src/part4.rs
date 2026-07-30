impl RedirectAnalyzer {
    pub fn analyze_redirect(
        &self,
        observation: &RedirectObservation,
    ) -> Result<Vec<Finding>, AnalyzerError> {
        let from = Url::parse(&observation.from_url)
            .map_err(|_| AnalyzerError::InvalidObservation("redirect from URL".into()))?;
        let to = Url::parse(&observation.to_url)
            .map_err(|_| AnalyzerError::InvalidObservation("redirect to URL".into()))?;
        if !matches!(observation.status, 301 | 302 | 303 | 307 | 308) {
            return Err(AnalyzerError::InvalidObservation(
                "redirect status is unsupported".into(),
            ));
        }
        let origin = normalized_origin(&from)?;
        let endpoint = hash_bytes(from.as_str().as_bytes());
        let mut findings = Vec::new();
        let cross_origin = normalized_origin(&from)? != normalized_origin(&to)?;
        if from.scheme() == "https" && to.scheme() == "http" {
            push_finding(
                &mut findings,
                "NXB-REDIRECT-001",
                "HTTPS redirect downgrades to HTTP",
                Severity::High,
                Confidence::High,
                &origin,
                &endpoint,
                observation.to_url.as_bytes(),
                "The redirect target changes the transport from HTTPS to HTTP.",
                BTreeMap::new(),
            )?;
        }
        if cross_origin && observation.credential_headers_forwarded {
            push_finding(
                &mut findings,
                "NXB-REDIRECT-002",
                "Cross-origin redirect forwards credential headers",
                Severity::High,
                Confidence::High,
                &origin,
                &endpoint,
                hash_serializable(observation).as_bytes(),
                "Authorization-like credentials were reported as forwarded across origins.",
                BTreeMap::new(),
            )?;
        }
        if cross_origin && observation.body_preserved {
            push_finding(
                &mut findings,
                "NXB-REDIRECT-003",
                "Cross-origin redirect preserves request body",
                Severity::High,
                Confidence::High,
                &origin,
                &endpoint,
                hash_serializable(observation).as_bytes(),
                "A non-empty request body may be replayed to a different origin.",
                BTreeMap::new(),
            )?;
        }
        if observation.loop_detected || observation.chain_depth > 8 {
            push_finding(
                &mut findings,
                "NXB-REDIRECT-004",
                "Redirect loop or excessive chain depth",
                Severity::Low,
                Confidence::High,
                &origin,
                &endpoint,
                observation.chain_depth.to_string().as_bytes(),
                "The redirect chain loops or exceeds the conservative depth policy.",
                BTreeMap::from([("chain_depth".into(), observation.chain_depth.to_string())]),
            )?;
        }
        let expected_generation = if observation.cookie_rematerialized {
            observation.session_generation_before.saturating_add(1)
        } else {
            observation.session_generation_before
        };
        if observation.session_generation_after != expected_generation {
            push_finding(
                &mut findings,
                "NXB-REDIRECT-005",
                "Redirect session generation transition is inconsistent",
                Severity::Medium,
                Confidence::High,
                &origin,
                &endpoint,
                hash_serializable(&(
                    observation.session_generation_before,
                    observation.session_generation_after,
                ))
                .as_bytes(),
                "Session state changed without the expected monotonic generation transition.",
                BTreeMap::new(),
            )?;
        }
        Ok(findings)
    }
}

#[derive(Debug, Default)]
pub struct CorsAnalyzer;

impl PassiveAnalyzer for CorsAnalyzer {
    fn analyze(&self, response: &ResponseObservation) -> Result<Vec<Finding>, AnalyzerError> {
        response.validate()?;
        let origin = response.origin()?;
        let endpoint = response.endpoint_sha256();
        let mut findings = Vec::new();
        let allow_origin = response.first_text("access-control-allow-origin");
        let allow_credentials = response
            .first_text("access-control-allow-credentials")
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("true"));
        if allow_origin.as_deref() == Some("*") && allow_credentials {
            push_finding(
                &mut findings,
                "NXB-CORS-001",
                "CORS combines wildcard origin with credentials",
                Severity::High,
                Confidence::High,
                &origin,
                &endpoint,
                b"acao:*;acac:true",
                "Wildcard origin and credential allowance form an invalid or dangerously broad CORS policy.",
                BTreeMap::new(),
            )?;
        }
        if allow_origin.as_deref() == Some("null") {
            push_finding(
                &mut findings,
                "NXB-CORS-002",
                "CORS explicitly allows the null origin",
                Severity::Medium,
                Confidence::High,
                &origin,
                &endpoint,
                b"acao:null",
                "The null origin is explicitly permitted.",
                BTreeMap::new(),
            )?;
        }
        if allow_origin.is_some()
            && response.first_text("vary").is_none_or(|value| {
                !value
                    .to_ascii_lowercase()
                    .split(',')
                    .any(|part| part.trim() == "origin")
            })
            && allow_origin.as_deref() != Some("*")
        {
            push_finding(
                &mut findings,
                "NXB-CORS-003",
                "Dynamic CORS response lacks Vary: Origin",
                Severity::Medium,
                Confidence::Medium,
                &origin,
                &endpoint,
                allow_origin.as_deref().unwrap_or_default().as_bytes(),
                "A non-wildcard Access-Control-Allow-Origin response lacks an Origin cache variance marker.",
                BTreeMap::new(),
            )?;
        }
        if response.values("access-control-allow-origin").len() > 1 {
            push_finding(
                &mut findings,
                "NXB-CORS-004",
                "CORS allow-origin header is duplicated",
                Severity::Medium,
                Confidence::High,
                &origin,
                &endpoint,
                b"duplicate:access-control-allow-origin",
                "Multiple allow-origin values may be interpreted inconsistently.",
                BTreeMap::new(),
            )?;
        }
        Ok(findings)
    }
}

#[derive(Debug, Default)]
pub struct CachePolicyAnalyzer;
