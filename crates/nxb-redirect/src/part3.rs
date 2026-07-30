impl RedirectCoordinator {
    pub fn new(
        chain_id: impl Into<String>,
        transport: PinnedTransportCoordinator,
        current: RedirectRequestState,
        limits: RedirectLimits,
    ) -> Result<Self, RedirectError> {
        let chain_id = chain_id.into();
        validate_identifier(&chain_id, "chain_id").map_err(|_| RedirectError::InvalidChainId)?;
        let limits = limits.validate()?;
        let first_request_hash = request_identity_hash(&current.url, &current.method);
        let audit = RedirectAuditChain::new(
            &chain_id,
            transport.transport_audit().tail_hash(),
        );
        Ok(Self {
            chain_id,
            limits,
            transport,
            current,
            seen_requests: BTreeSet::from([first_request_hash]),
            used_dns_contexts: BTreeSet::new(),
            redirect_count: 0,
            terminal: false,
            audit,
        })
    }

    pub fn authorize_next(
        &mut self,
        response: &Http1Response,
        dns: RedirectDnsInput,
        session_update: RedirectSessionUpdate,
        elapsed: Duration,
    ) -> Result<RedirectStep, RedirectError> {
        if self.terminal {
            return Err(RedirectError::ChainTerminated);
        }
        if self.redirect_count >= self.limits.maximum_redirects {
            self.terminal = true;
            return Err(RedirectError::RedirectLimitExceeded);
        }
        validate_session_update(&self.current.session, &session_update)?;
        validate_identifier(&dns.context_id, "dns_context_id")?;
        validate_identifier(&dns.resolver_id, "dns_resolver_id")?;
        if self.used_dns_contexts.contains(&dns.context_id) {
            self.terminal = true;
            return Err(RedirectError::DnsContextReused);
        }

        let location_bytes = strict_location(response)?;
        let location_sha256 = hash(location_bytes);
        let mut next_url = resolve_location(&self.current.url, location_bytes)?;
        next_url.set_fragment(None);
        let to_target_sha256 = target_hash(&next_url);
        let from_origin = Origin::from_url(&self.current.url)?;
        let to_origin = Origin::from_url(&next_url)?;
        if from_origin.scheme == "https" && to_origin.scheme == "http" {
            self.terminal = true;
            return Err(RedirectError::HttpsDowngrade);
        }

        let (method, body_disposition) = redirect_method_plan(
            response.status_code,
            &self.current.method,
        )?;
        let origin_transition = if from_origin == to_origin {
            OriginTransition::SameOrigin
        } else {
            OriginTransition::CrossOrigin
        };
        if origin_transition == OriginTransition::CrossOrigin
            && body_disposition == RedirectBodyDisposition::Preserve
            && self.current.body_bytes > 0
        {
            self.terminal = true;
            return Err(RedirectError::CrossOriginBodyReplayDenied);
        }
        let secret_disposition = match origin_transition {
            OriginTransition::SameOrigin => RedirectSecretDisposition::ReissueBoundSecrets,
            OriginTransition::CrossOrigin => RedirectSecretDisposition::RematerializeCookiesOnly,
        };
        let next_body_sha256 = match body_disposition {
            RedirectBodyDisposition::Preserve => self.current.body_sha256.clone(),
            RedirectBodyDisposition::Drop => hash(&[]),
        };
        let next_body_bytes = match body_disposition {
            RedirectBodyDisposition::Preserve => self.current.body_bytes,
            RedirectBodyDisposition::Drop => 0,
        };
        let next_request = RedirectNextRequest {
            url: next_url.clone(),
            method: method.clone(),
            body_disposition,
            body_sha256: next_body_sha256,
            body_bytes: next_body_bytes,
        };
        let next_request_hash = request_identity_hash(&next_url, &method);
        if self.seen_requests.contains(&next_request_hash) {
            self.terminal = true;
            return Err(RedirectError::RedirectLoop);
        }

        let redirect_depth = self.redirect_count.saturating_add(1);
        let intent = RequestIntent {
            url: next_url.clone(),
            method: method.clone(),
            resolved_ips: dns.resolved_ips.clone(),
            redirect_depth,
            dns_context_id: dns.context_id.clone(),
            dns_resolver_id: dns.resolver_id.clone(),
            dns_ttl_seconds: dns.ttl_seconds,
        };
        let authorization = self.transport.authorize_connection(
            &intent,
            dns.selected_ip,
            elapsed,
        )?;
        if authorization.decision.outcome == DecisionOutcome::Allow
            && authorization.ticket.is_none()
        {
            self.terminal = true;
            return Err(RedirectError::MissingTransportTicket);
        }

        self.append_audit_event(RedirectAuditInput {
            response_status: response.status_code,
            from_origin: &from_origin,
            to_origin: &to_origin,
            location_sha256: &location_sha256,
            to_target_sha256: &to_target_sha256,
            method_after: &method,
            body_disposition,
            origin_transition,
            secret_disposition,
            session: &session_update.snapshot,
            dns_context_id: &dns.context_id,
            decision: &authorization.decision,
            ticket_id: authorization
                .ticket
                .as_ref()
                .map(|ticket| ticket.ticket_id.clone()),
            ticket_binding_hash: authorization
                .ticket
                .as_ref()
                .map(|ticket| ticket.binding_hash.clone()),
        })?;

        let step = RedirectStep {
            redirect_depth,
            status_code: response.status_code,
            from_origin,
            to_origin,
            origin_transition,
            secret_disposition,
            session_generation: session_update.snapshot.generation,
            next_request: next_request.clone(),
            authorization,
        };

        self.used_dns_contexts.insert(dns.context_id);
        if step.is_authorized() {
            self.seen_requests.insert(next_request_hash);
            self.redirect_count = redirect_depth;
            self.current = RedirectRequestState {
                url: next_request.url,
                method: next_request.method,
                body_sha256: next_request.body_sha256,
                body_bytes: next_request.body_bytes,
                session: session_update.snapshot,
            };
        } else {
            self.terminal = true;
        }
        Ok(step)
    }

    fn append_audit_event(
        &mut self,
        input: RedirectAuditInput<'_>,
    ) -> Result<(), RedirectError> {
        let gateway_decision_bytes = serde_json::to_vec(input.decision)
            .map_err(|error| RedirectAuditError::Serialization(error.to_string()))?;
        let gateway_outcome = match &input.decision.outcome {
            DecisionOutcome::Allow => "allow",
            DecisionOutcome::Deny => "deny",
        };
        self.audit.append(RedirectAuditEvent {
            chain_id: self.chain_id.clone(),
            step: self.redirect_count.saturating_add(1),
            status: if input.decision.outcome == DecisionOutcome::Allow {
                "authorized".into()
            } else {
                "gateway_denied".into()
            },
            reason: "redirect_reauthorized".into(),
            response_status: input.response_status,
            from_origin: origin_code(input.from_origin),
            to_origin: origin_code(input.to_origin),
            from_target_sha256: target_hash(&self.current.url),
            to_target_sha256: input.to_target_sha256.into(),
            location_sha256: input.location_sha256.into(),
            method_before: self.current.method.clone(),
            method_after: input.method_after.into(),
            body_disposition: input.body_disposition.code().into(),
            origin_transition: input.origin_transition.code().into(),
            secret_disposition: input.secret_disposition.code().into(),
            session_identity_sha256: session_identity_hash(input.session),
            session_generation: input.session.generation,
            dns_context_id: input.dns_context_id.into(),
            gateway_decision_id: input.decision.decision_id.clone(),
            gateway_outcome: gateway_outcome.into(),
            gateway_decision_sha256: hash(&gateway_decision_bytes),
            gateway_audit_anchor: self
                .transport
                .gateway()
                .audit_chain()
                .tail_hash()
                .to_string(),
            ticket_id: input.ticket_id,
            ticket_binding_hash: input.ticket_binding_hash,
            transport_audit_anchor: self.transport.transport_audit().tail_hash().to_string(),
        })?;
        Ok(())
    }

    pub fn current(&self) -> &RedirectRequestState {
        &self.current
    }

    pub fn redirect_count(&self) -> u8 {
        self.redirect_count
    }

    pub fn is_terminal(&self) -> bool {
        self.terminal
    }

    pub fn audit(&self) -> &RedirectAuditChain {
        &self.audit
    }

    pub fn transport(&self) -> &PinnedTransportCoordinator {
        &self.transport
    }

    pub fn into_transport(self) -> PinnedTransportCoordinator {
        self.transport
    }
}

fn strict_location(response: &Http1Response) -> Result<&[u8], RedirectError> {
    if !matches!(response.status_code, 301 | 302 | 303 | 307 | 308) {
        return Err(RedirectError::NotRedirect);
    }
    let locations = response
        .headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("location"))
        .collect::<Vec<_>>();
    match locations.len() {
        0 => Err(RedirectError::MissingLocation),
        1 => {
            let value = locations[0].value.as_slice();
            if value.is_empty() || value.len() > MAX_LOCATION_BYTES {
                return Err(RedirectError::InvalidLocation(
                    "length is outside the supported range".into(),
                ));
            }
            if value.first().is_some_and(u8::is_ascii_whitespace)
                || value.last().is_some_and(u8::is_ascii_whitespace)
                || value
                    .iter()
                    .any(|byte| byte.is_ascii_control() || *byte == b' ')
            {
                return Err(RedirectError::InvalidLocation(
                    "whitespace or control bytes are forbidden".into(),
                ));
            }
            Ok(value)
        }
        _ => Err(RedirectError::MultipleLocations),
    }
}

fn resolve_location(base: &Url, location: &[u8]) -> Result<Url, RedirectError> {
    let location = std::str::from_utf8(location)
        .map_err(|_| RedirectError::InvalidLocation("value is not UTF-8".into()))?;
    let url = base
        .join(location)
        .map_err(|error| RedirectError::InvalidLocation(error.to_string()))?;
    validate_http_url(&url)?;
    Ok(url)
}

fn redirect_method_plan(
    status: u16,
    current_method: &str,
) -> Result<(String, RedirectBodyDisposition), RedirectError> {
    match status {
        301 | 302 if current_method == "POST" => {
            Ok(("GET".into(), RedirectBodyDisposition::Drop))
        }
        301 | 302 => Ok((current_method.into(), RedirectBodyDisposition::Preserve)),
        303 if current_method == "HEAD" => {
            Ok(("HEAD".into(), RedirectBodyDisposition::Drop))
        }
        303 => Ok(("GET".into(), RedirectBodyDisposition::Drop)),
        307 | 308 => Ok((current_method.into(), RedirectBodyDisposition::Preserve)),
        _ => Err(RedirectError::NotRedirect),
    }
}

fn validate_session_update(
    current: &RedirectSessionSnapshot,
    update: &RedirectSessionUpdate,
) -> Result<(), RedirectError> {
    update.snapshot.validate()?;
    if !current.identity_matches(&update.snapshot) {
        return Err(RedirectError::SessionIdentityMismatch);
    }
    let valid_generation = if update.response_state_changed {
        update.snapshot.generation == current.generation.saturating_add(1)
    } else {
        update.snapshot.generation == current.generation
    };
    if !valid_generation {
        return Err(RedirectError::SessionGenerationMismatch);
    }
    Ok(())
}

fn validate_http_url(url: &Url) -> Result<(), RedirectError> {
    if !matches!(url.scheme(), "http" | "https") || !url.has_host() {
        return Err(RedirectError::InvalidUrl);
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(RedirectError::UserInfoForbidden);
    }
    Ok(())
}

fn normalize_method(method: &str) -> Result<String, RedirectError> {
    let normalized = method.to_ascii_uppercase();
    if normalized.is_empty()
        || normalized.len() > 32
        || !normalized.bytes().all(|byte| {
            byte.is_ascii_uppercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
    {
        return Err(RedirectError::InvalidMethod);
    }
    Ok(normalized)
}

fn validate_identifier(value: &str, name: &str) -> Result<(), RedirectError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(RedirectError::InvalidIdentifier(name.into()));
    }
    Ok(())
}

fn validate_sha256(value: &str, name: &str) -> Result<(), RedirectError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(RedirectError::InvalidDigest(name.into()));
    }
    Ok(())
}

fn request_identity_hash(url: &Url, method: &str) -> String {
    hash(format!("{method}\0{}", url.as_str()).as_bytes())
}

fn target_hash(url: &Url) -> String {
    hash(origin_form(url).as_bytes())
}

fn origin_form(url: &Url) -> String {
    let mut value = url.path().to_string();
    if value.is_empty() {
        value.push('/');
    }
    if let Some(query) = url.query() {
        value.push('?');
        value.push_str(query);
    }
    value
}

fn origin_code(origin: &Origin) -> String {
    format!("{}://{}", origin.scheme, origin.authority())
}

fn session_identity_hash(session: &RedirectSessionSnapshot) -> String {
    hash(
        format!(
            "{}\0{}\0{}\0{}\0{}\0{}",
            session.session_id,
            session.run_id,
            session.worker_id,
            session.account_id,
            session.tenant_id,
            session.role_id
        )
        .as_bytes(),
    )
}

fn hash(bytes: &[u8]) -> String {
    lower_hex(&Sha256::digest(bytes))
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

