impl PassiveAnalyzer for HeaderSecurityAnalyzer {
    fn analyze(&self, response: &ResponseObservation) -> Result<Vec<Finding>, AnalyzerError> {
        response.validate()?;
        let origin = response.origin()?;
        let endpoint = response.endpoint_sha256();
        let mut findings = Vec::new();
        let present = response
            .headers
            .iter()
            .map(|header| header.name.as_str())
            .collect::<BTreeSet<_>>();
        if response.url.scheme() == "https" && !present.contains("strict-transport-security") {
            push_finding(
                &mut findings,
                "BSL-HDR-001",
                "HTTPS response lacks HSTS",
                Severity::Medium,
                Confidence::High,
                &origin,
                &endpoint,
                b"missing:strict-transport-security",
                "The HTTPS response did not declare Strict-Transport-Security.",
                BTreeMap::new(),
            )?;
        }
        for (name, rule, title, severity) in [
            (
                "content-security-policy",
                "BSL-HDR-002",
                "Content Security Policy is absent",
                Severity::Low,
            ),
            (
                "x-content-type-options",
                "BSL-HDR-003",
                "MIME sniffing protection is absent",
                Severity::Low,
            ),
            (
                "referrer-policy",
                "BSL-HDR-004",
                "Referrer Policy is absent",
                Severity::Low,
            ),
            (
                "permissions-policy",
                "BSL-HDR-005",
                "Permissions Policy is absent",
                Severity::Info,
            ),
        ] {
            if !present.contains(name) {
                push_finding(
                    &mut findings,
                    rule,
                    title,
                    severity,
                    Confidence::High,
                    &origin,
                    &endpoint,
                    format!("missing:{name}").as_bytes(),
                    title,
                    BTreeMap::new(),
                )?;
            }
        }
        if let Some(server) = response.first_text("server") {
            if server.chars().any(|character| character.is_ascii_digit()) {
                push_finding(
                    &mut findings,
                    "BSL-HDR-006",
                    "Server header discloses version-like metadata",
                    Severity::Info,
                    Confidence::Medium,
                    &origin,
                    &endpoint,
                    server.as_bytes(),
                    "The Server header appears to expose version metadata.",
                    BTreeMap::from([("value_sha256".into(), hash_bytes(server.as_bytes()))]),
                )?;
            }
        }
        for duplicate in duplicate_header_names(&response.headers) {
            if matches!(
                duplicate.as_str(),
                "strict-transport-security"
                    | "content-security-policy"
                    | "x-content-type-options"
                    | "referrer-policy"
            ) {
                push_finding(
                    &mut findings,
                    "BSL-HDR-007",
                    "Security header is duplicated",
                    Severity::Low,
                    Confidence::High,
                    &origin,
                    &endpoint,
                    duplicate.as_bytes(),
                    "A security policy header appears more than once and may be interpreted inconsistently.",
                    BTreeMap::from([("header".into(), duplicate.clone())]),
                )?;
            }
        }
        Ok(findings)
    }
}

#[derive(Debug, Default)]
pub struct CookieSecurityAnalyzer;

impl PassiveAnalyzer for CookieSecurityAnalyzer {
    fn analyze(&self, response: &ResponseObservation) -> Result<Vec<Finding>, AnalyzerError> {
        response.validate()?;
        let origin = response.origin()?;
        let endpoint = response.endpoint_sha256();
        let mut findings = Vec::new();
        for value in response.values("set-cookie") {
            let cookie = parse_cookie(value)?;
            let mut metadata = BTreeMap::from([
                ("cookie_name_sha256".into(), hash_bytes(cookie.name.as_bytes())),
                ("host_only".into(), cookie.domain.is_none().to_string()),
                ("path".into(), cookie.path.clone().unwrap_or_else(|| "[default]".into())),
            ]);
            if response.url.scheme() == "https" && !cookie.secure {
                push_finding(
                    &mut findings,
                    "BSL-COOKIE-001",
                    "Cookie lacks Secure on an HTTPS response",
                    Severity::Medium,
                    Confidence::High,
                    &origin,
                    &endpoint,
                    value,
                    "The cookie can be eligible for cleartext transmission unless another control prevents it.",
                    metadata.clone(),
                )?;
            }
            if !cookie.http_only {
                push_finding(
                    &mut findings,
                    "BSL-COOKIE-002",
                    "Cookie lacks HttpOnly",
                    Severity::Low,
                    Confidence::High,
                    &origin,
                    &endpoint,
                    value,
                    "The cookie is readable by script in a browser context.",
                    metadata.clone(),
                )?;
            }
            match cookie.same_site.as_deref() {
                None => push_finding(
                    &mut findings,
                    "BSL-COOKIE-003",
                    "Cookie lacks SameSite",
                    Severity::Low,
                    Confidence::High,
                    &origin,
                    &endpoint,
                    value,
                    "The cookie does not explicitly state a SameSite policy.",
                    metadata.clone(),
                )?,
                Some("none") if !cookie.secure => push_finding(
                    &mut findings,
                    "BSL-COOKIE-004",
                    "SameSite=None cookie lacks Secure",
                    Severity::Medium,
                    Confidence::High,
                    &origin,
                    &endpoint,
                    value,
                    "SameSite=None should be paired with Secure.",
                    metadata.clone(),
                )?,
                _ => {}
            }
            if cookie.domain.as_deref().is_some_and(|domain| {
                response
                    .url
                    .host_str()
                    .is_some_and(|host| domain.split('.').count() < host.split('.').count())
            }) {
                metadata.insert("domain_scope".into(), "broader_than_origin_host".into());
                push_finding(
                    &mut findings,
                    "BSL-COOKIE-005",
                    "Cookie Domain broadens host scope",
                    Severity::Low,
                    Confidence::Medium,
                    &origin,
                    &endpoint,
                    value,
                    "The cookie Domain attribute appears broader than the response host.",
                    metadata,
                )?;
            }
        }
        Ok(findings)
    }
}

#[derive(Debug, Default)]
pub struct TlsMetadataAnalyzer;
