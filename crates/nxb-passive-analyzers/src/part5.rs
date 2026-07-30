impl PassiveAnalyzer for CachePolicyAnalyzer {
    fn analyze(&self, response: &ResponseObservation) -> Result<Vec<Finding>, AnalyzerError> {
        response.validate()?;
        let origin = response.origin()?;
        let endpoint = response.endpoint_sha256();
        let mut findings = Vec::new();
        let cache_control = response
            .first_text("cache-control")
            .unwrap_or_default()
            .to_ascii_lowercase();
        let directives = cache_control
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .collect::<BTreeSet<_>>();
        if response.authenticated
            && !directives.contains("private")
            && !directives.contains("no-store")
        {
            push_finding(
                &mut findings,
                "NXB-CACHE-001",
                "Authenticated response is not explicitly private or no-store",
                Severity::Medium,
                Confidence::High,
                &origin,
                &endpoint,
                cache_control.as_bytes(),
                "The response is authenticated but does not explicitly prohibit shared caching.",
                BTreeMap::new(),
            )?;
        }
        if directives.contains("public") && directives.contains("private") {
            push_finding(
                &mut findings,
                "NXB-CACHE-002",
                "Cache-Control contains public/private conflict",
                Severity::Medium,
                Confidence::High,
                &origin,
                &endpoint,
                cache_control.as_bytes(),
                "The response declares mutually conflicting cache visibility directives.",
                BTreeMap::new(),
            )?;
        }
        if !response.values("set-cookie").is_empty()
            && directives.contains("public")
            && !directives.contains("no-store")
        {
            push_finding(
                &mut findings,
                "NXB-CACHE-003",
                "Cookie-setting response is publicly cacheable",
                Severity::High,
                Confidence::High,
                &origin,
                &endpoint,
                cache_control.as_bytes(),
                "A response that mutates cookies is marked public without no-store.",
                BTreeMap::new(),
            )?;
        }
        if response.first_text("vary").is_none()
            && (response.authenticated || !response.values("set-cookie").is_empty())
        {
            push_finding(
                &mut findings,
                "NXB-CACHE-004",
                "Sensitive response lacks Vary metadata",
                Severity::Low,
                Confidence::Medium,
                &origin,
                &endpoint,
                b"missing:vary",
                "No Vary header was observed on a response with authentication or cookie state.",
                BTreeMap::new(),
            )?;
        }
        Ok(findings)
    }
}

#[derive(Debug)]
struct ParsedCookie {
    name: String,
    domain: Option<String>,
    path: Option<String>,
    secure: bool,
    http_only: bool,
    same_site: Option<String>,
}

fn parse_cookie(value: &[u8]) -> Result<ParsedCookie, AnalyzerError> {
    if value.is_empty() || value.len() > 16 * 1024 || !value.is_ascii() {
        return Err(AnalyzerError::InvalidObservation(
            "Set-Cookie value bounds".into(),
        ));
    }
    let text = std::str::from_utf8(value)
        .map_err(|_| AnalyzerError::InvalidObservation("Set-Cookie UTF-8".into()))?;
    let mut parts = text.split(';');
    let pair = parts
        .next()
        .ok_or_else(|| AnalyzerError::InvalidObservation("cookie pair".into()))?;
    let (name, _) = pair
        .split_once('=')
        .ok_or_else(|| AnalyzerError::InvalidObservation("cookie pair".into()))?;
    if name.is_empty() || !name.bytes().all(valid_token_byte) {
        return Err(AnalyzerError::InvalidObservation("cookie name".into()));
    }
    let mut cookie = ParsedCookie {
        name: name.into(),
        domain: None,
        path: None,
        secure: false,
        http_only: false,
        same_site: None,
    };
    for attribute in parts {
        let attribute = attribute.trim();
        let (name, value) = attribute
            .split_once('=')
            .map(|(name, value)| (name.trim().to_ascii_lowercase(), Some(value.trim())))
            .unwrap_or_else(|| (attribute.to_ascii_lowercase(), None));
        match name.as_str() {
            "secure" => cookie.secure = true,
            "httponly" => cookie.http_only = true,
            "domain" => cookie.domain = value.map(|value| value.trim_start_matches('.').to_ascii_lowercase()),
            "path" => cookie.path = value.map(str::to_string),
            "samesite" => cookie.same_site = value.map(|value| value.to_ascii_lowercase()),
            _ => {}
        }
    }
    Ok(cookie)
}

fn duplicate_header_names(headers: &[ObservedHeader]) -> BTreeSet<String> {
    let mut seen = BTreeSet::new();
    let mut duplicates = BTreeSet::new();
    for header in headers {
        if !seen.insert(header.name.clone()) {
            duplicates.insert(header.name.clone());
        }
    }
    duplicates
}

#[allow(clippy::too_many_arguments)]
fn push_finding(
    findings: &mut Vec<Finding>,
    rule_id: &str,
    title: &str,
    severity: Severity,
    confidence: Confidence,
    origin: &str,
    endpoint_sha256: &str,
    evidence: &[u8],
    summary: &str,
    metadata: BTreeMap<String, String>,
) -> Result<(), AnalyzerError> {
    if findings.len() >= MAX_FINDINGS_PER_ANALYZER {
        return Err(AnalyzerError::FindingLimit);
    }
    let evidence_sha256 = hash_bytes(evidence);
    let finding_id = hash_serializable(&(
        rule_id,
        origin,
        endpoint_sha256,
        &evidence_sha256,
    ));
    findings.push(Finding {
        finding_id,
        rule_id: rule_id.into(),
        title: title.into(),
        severity,
        confidence,
        origin: origin.into(),
        endpoint_sha256: endpoint_sha256.into(),
        evidence_sha256,
        summary: summary.into(),
        metadata,
    });
    Ok(())
}

fn normalized_origin(url: &Url) -> Result<String, AnalyzerError> {
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(AnalyzerError::InvalidObservation(
            "origin URL is invalid".into(),
        ));
    }
    let host = url.host_str().expect("validated host").to_ascii_lowercase();
    let port = url
        .port_or_known_default()
        .ok_or_else(|| AnalyzerError::InvalidObservation("origin port".into()))?;
    Ok(format!("{}://{}:{}", url.scheme(), host, port))
}

fn valid_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn hash_serializable<T: Serialize>(value: &T) -> String {
    match serde_json::to_vec(value) {
        Ok(bytes) => hash_bytes(&bytes),
        Err(error) => hash_bytes(error.to_string().as_bytes()),
    }
}

fn hash_bytes(bytes: &[u8]) -> String {
    lower_hex(&Sha256::digest(bytes))
}

