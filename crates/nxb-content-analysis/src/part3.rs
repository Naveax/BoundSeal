fn extract_html(body: &[u8], limits: ExtractionLimits) -> Result<StructuredDocument, ContentError> {
    let text = std::str::from_utf8(body)
        .map_err(|_| ContentError::InvalidStructuredContent("HTML is not UTF-8".into()))?;
    let lower = text.to_ascii_lowercase();
    let mut node_count = 0usize;
    let mut links = Vec::new();
    let mut forms = Vec::new();
    let mut active_form: Option<ExtractedForm> = None;
    let mut cursor = 0usize;
    while let Some(open_offset) = lower[cursor..].find('<') {
        let start = cursor + open_offset;
        let Some(close_offset) = lower[start..].find('>') else {
            return Err(ContentError::InvalidStructuredContent(
                "unterminated HTML tag".into(),
            ));
        };
        let end = start + close_offset;
        let tag_text = &text[start + 1..end];
        cursor = end + 1;
        if tag_text.starts_with('!') || tag_text.starts_with('?') {
            continue;
        }
        node_count = node_count.saturating_add(1);
        if node_count > limits.maximum_nodes {
            return Err(ContentError::ResourceLimit("HTML node count".into()));
        }
        let closing = tag_text.trim_start().starts_with('/');
        let normalized = tag_text.trim().trim_start_matches('/');
        let tag_name = normalized
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        if closing && tag_name == "form" {
            if let Some(form) = active_form.take() {
                forms.push(form);
            }
            continue;
        }
        let attributes = parse_html_attributes(normalized)?;
        for (attribute, source) in [("href", "link"), ("src", "resource"), ("action", "form")]
        {
            if let Some(value) = attributes.get(attribute) {
                if links.len() >= limits.maximum_links {
                    return Err(ContentError::ResourceLimit("HTML link count".into()));
                }
                links.push(ExtractedLink {
                    raw_target_sha256: hash_bytes(value.as_bytes()),
                    raw_target: value.clone(),
                    source_tag: tag_name.clone(),
                    source_attribute: format!("{source}:{attribute}"),
                });
            }
        }
        if tag_name == "form" {
            if active_form.is_some() {
                return Err(ContentError::InvalidStructuredContent(
                    "nested forms are rejected".into(),
                ));
            }
            let action = attributes.get("action").cloned().unwrap_or_else(|| "".into());
            active_form = Some(ExtractedForm {
                action_sha256: hash_bytes(action.as_bytes()),
                action,
                method: attributes
                    .get("method")
                    .map(|value| value.to_ascii_uppercase())
                    .unwrap_or_else(|| "GET".into()),
                enctype: attributes
                    .get("enctype")
                    .map(|value| value.to_ascii_lowercase())
                    .unwrap_or_else(|| "application/x-www-form-urlencoded".into()),
                parameter_names: BTreeSet::new(),
            });
        } else if matches!(tag_name.as_str(), "input" | "textarea" | "select" | "button") {
            if let (Some(form), Some(name)) = (active_form.as_mut(), attributes.get("name")) {
                if !name.is_empty() && name.len() <= 256 {
                    form.parameter_names.insert(name.clone());
                }
            }
        }
        if forms.len() > limits.maximum_forms {
            return Err(ContentError::ResourceLimit("HTML form count".into()));
        }
    }
    if let Some(form) = active_form.take() {
        forms.push(form);
    }
    Ok(StructuredDocument {
        kind: ContentClassification::Html,
        body_sha256: hash_bytes(body),
        body_bytes: body.len(),
        node_count,
        maximum_depth: 1,
        token_count: text.split_whitespace().count().min(limits.maximum_tokens),
        links,
        forms,
        metadata: BTreeMap::from([
            ("parser".into(), "bounded_html_lexical".into()),
            ("script_execution".into(), "disabled".into()),
        ]),
    })
}

fn extract_json(body: &[u8], limits: ExtractionLimits) -> Result<StructuredDocument, ContentError> {
    let text = std::str::from_utf8(body)
        .map_err(|_| ContentError::InvalidStructuredContent("JSON is not UTF-8".into()))?;
    let mut depth = 0usize;
    let mut maximum_depth = 0usize;
    let mut nodes = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for byte in text.bytes() {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            } else if byte < 0x20 {
                return Err(ContentError::InvalidStructuredContent(
                    "JSON string contains a control byte".into(),
                ));
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth = depth.saturating_add(1);
                maximum_depth = maximum_depth.max(depth);
                nodes = nodes.saturating_add(1);
            }
            b'}' | b']' => {
                if depth == 0 {
                    return Err(ContentError::InvalidStructuredContent(
                        "JSON closing delimiter underflow".into(),
                    ));
                }
                depth -= 1;
            }
            b',' | b':' => nodes = nodes.saturating_add(1),
            _ => {}
        }
        if depth > limits.maximum_depth {
            return Err(ContentError::ResourceLimit("JSON depth".into()));
        }
        if nodes > limits.maximum_nodes {
            return Err(ContentError::ResourceLimit("JSON node count".into()));
        }
    }
    if in_string || depth != 0 {
        return Err(ContentError::InvalidStructuredContent(
            "JSON structure is incomplete".into(),
        ));
    }
    Ok(StructuredDocument {
        kind: ContentClassification::Json,
        body_sha256: hash_bytes(body),
        body_bytes: body.len(),
        node_count: nodes,
        maximum_depth,
        token_count: text.split_whitespace().count().min(limits.maximum_tokens),
        links: Vec::new(),
        forms: Vec::new(),
        metadata: BTreeMap::from([("parser".into(), "bounded_json_structure".into())]),
    })
}

