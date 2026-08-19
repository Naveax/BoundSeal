impl DiscoveryGraph {
    pub fn build(base: &Url, document: &StructuredDocument) -> Result<Self, ContentError> {
        if !matches!(base.scheme(), "http" | "https")
            || base.host_str().is_none()
            || !base.username().is_empty()
            || base.password().is_some()
        {
            return Err(ContentError::InvalidDiscoveredUrl(
                "base URL is not an absolute HTTP(S) URL".into(),
            ));
        }
        let base_origin = origin(base)?;
        let mut nodes = Vec::new();
        let mut seen = BTreeSet::new();
        let mut duplicates = 0usize;
        for link in &document.links {
            if nodes.len() >= MAX_DISCOVERY_ITEMS {
                return Err(ContentError::ResourceLimit("discovery item count".into()));
            }
            let candidate = canonicalize_candidate(base, &link.raw_target);
            let (canonical, disposition, reason) = match candidate {
                Ok(url) => {
                    let same_origin = origin(&url)? == base_origin;
                    (
                        Some(url.to_string()),
                        if same_origin {
                            DiscoveryDisposition::SameOriginCandidate
                        } else {
                            DiscoveryDisposition::CrossOriginPassive
                        },
                        if same_origin {
                            "same_origin".into()
                        } else {
                            "cross_origin_passive_only".into()
                        },
                    )
                }
                Err(error) => (None, DiscoveryDisposition::Rejected, error.to_string()),
            };
            let digest = canonical
                .as_deref()
                .map(|value| hash_bytes(value.as_bytes()))
                .unwrap_or_else(|| link.raw_target_sha256.clone());
            if !seen.insert((digest.clone(), "GET".to_string())) {
                duplicates = duplicates.saturating_add(1);
                continue;
            }
            nodes.push(DiscoveryNode {
                node_id: format!("discovery-node-{:020}", nodes.len() + 1),
                canonical_url: canonical,
                canonical_url_sha256: digest,
                disposition,
                source_kind: format!("{}:{}", link.source_tag, link.source_attribute),
                method: "GET".into(),
                parameter_names: BTreeSet::new(),
                reason,
            });
        }
        for form in &document.forms {
            if nodes.len() >= MAX_DISCOVERY_ITEMS {
                return Err(ContentError::ResourceLimit("discovery item count".into()));
            }
            let target = if form.action.is_empty() {
                Ok(base.clone())
            } else {
                canonicalize_candidate(base, &form.action)
            };
            let (canonical, disposition, reason) = match target {
                Ok(url) => {
                    let same_origin = origin(&url)? == base_origin;
                    (
                        Some(url.to_string()),
                        if same_origin {
                            DiscoveryDisposition::SameOriginCandidate
                        } else {
                            DiscoveryDisposition::CrossOriginPassive
                        },
                        if same_origin {
                            "same_origin_form".into()
                        } else {
                            "cross_origin_form_passive_only".into()
                        },
                    )
                }
                Err(error) => (None, DiscoveryDisposition::Rejected, error.to_string()),
            };
            let digest = canonical
                .as_deref()
                .map(|value| hash_bytes(value.as_bytes()))
                .unwrap_or_else(|| form.action_sha256.clone());
            if !seen.insert((digest.clone(), form.method.clone())) {
                duplicates = duplicates.saturating_add(1);
                continue;
            }
            nodes.push(DiscoveryNode {
                node_id: format!("discovery-node-{:020}", nodes.len() + 1),
                canonical_url: canonical,
                canonical_url_sha256: digest,
                disposition,
                source_kind: "form".into(),
                method: form.method.clone(),
                parameter_names: form.parameter_names.clone(),
                reason,
            });
        }
        Ok(Self {
            base_origin,
            base_url_sha256: hash_bytes(base.as_str().as_bytes()),
            nodes,
            duplicate_count: duplicates,
        })
    }
}

fn parse_parameter_value(value: &str) -> Result<String, ContentError> {
    if value.starts_with('"') {
        if value.len() < 2 || !value.ends_with('"') {
            return Err(ContentError::InvalidMediaType(
                "unterminated quoted parameter".into(),
            ));
        }
        let inner = &value[1..value.len() - 1];
        if inner
            .bytes()
            .any(|byte| matches!(byte, b'\r' | b'\n' | 0 | b'\\'))
        {
            return Err(ContentError::InvalidMediaType(
                "quoted parameter contains unsupported escapes or controls".into(),
            ));
        }
        return Ok(inner.to_string());
    }
    if !valid_token(value) {
        return Err(ContentError::InvalidMediaType(
            "parameter value is invalid".into(),
        ));
    }
    Ok(value.to_string())
}

fn valid_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
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
        })
}

