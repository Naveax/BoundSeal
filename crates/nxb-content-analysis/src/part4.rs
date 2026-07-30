fn extract_xml(body: &[u8], limits: ExtractionLimits) -> Result<StructuredDocument, ContentError> {
    let text = std::str::from_utf8(body)
        .map_err(|_| ContentError::InvalidStructuredContent("XML is not UTF-8".into()))?;
    let upper = text.to_ascii_uppercase();
    if upper.contains("<!DOCTYPE") || upper.contains("<!ENTITY") {
        return Err(ContentError::InvalidStructuredContent(
            "DTD and entity declarations are forbidden".into(),
        ));
    }
    let mut depth = 0usize;
    let mut maximum_depth = 0usize;
    let mut nodes = 0usize;
    let mut cursor = 0usize;
    while let Some(open_offset) = text[cursor..].find('<') {
        let start = cursor + open_offset;
        let Some(close_offset) = text[start..].find('>') else {
            return Err(ContentError::InvalidStructuredContent(
                "unterminated XML tag".into(),
            ));
        };
        let end = start + close_offset;
        let tag = text[start + 1..end].trim();
        cursor = end + 1;
        if tag.starts_with('?') || tag.starts_with('!') {
            continue;
        }
        nodes = nodes.saturating_add(1);
        if tag.starts_with('/') {
            if depth == 0 {
                return Err(ContentError::InvalidStructuredContent(
                    "XML depth underflow".into(),
                ));
            }
            depth -= 1;
        } else if !tag.ends_with('/') {
            depth = depth.saturating_add(1);
            maximum_depth = maximum_depth.max(depth);
        }
        if nodes > limits.maximum_nodes {
            return Err(ContentError::ResourceLimit("XML node count".into()));
        }
        if depth > limits.maximum_depth {
            return Err(ContentError::ResourceLimit("XML depth".into()));
        }
    }
    if depth != 0 {
        return Err(ContentError::InvalidStructuredContent(
            "XML tags are not balanced".into(),
        ));
    }
    Ok(StructuredDocument {
        kind: ContentClassification::Xml,
        body_sha256: hash_bytes(body),
        body_bytes: body.len(),
        node_count: nodes,
        maximum_depth,
        token_count: text.split_whitespace().count().min(limits.maximum_tokens),
        links: Vec::new(),
        forms: Vec::new(),
        metadata: BTreeMap::from([
            ("parser".into(), "bounded_xml_lexical".into()),
            ("external_entities".into(), "disabled".into()),
        ]),
    })
}

fn extract_text(body: &[u8], limits: ExtractionLimits) -> Result<StructuredDocument, ContentError> {
    let text = std::str::from_utf8(body)
        .map_err(|_| ContentError::InvalidStructuredContent("text is not UTF-8".into()))?;
    let token_count = text.split_whitespace().count();
    if token_count > limits.maximum_tokens {
        return Err(ContentError::ResourceLimit("text token count".into()));
    }
    Ok(StructuredDocument {
        kind: ContentClassification::Text,
        body_sha256: hash_bytes(body),
        body_bytes: body.len(),
        node_count: 0,
        maximum_depth: 0,
        token_count,
        links: Vec::new(),
        forms: Vec::new(),
        metadata: BTreeMap::from([("parser".into(), "bounded_text_tokens".into())]),
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryDisposition {
    SameOriginCandidate,
    CrossOriginPassive,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiscoveryNode {
    pub node_id: String,
    pub canonical_url: Option<String>,
    pub canonical_url_sha256: String,
    pub disposition: DiscoveryDisposition,
    pub source_kind: String,
    pub method: String,
    pub parameter_names: BTreeSet<String>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiscoveryGraph {
    pub base_origin: String,
    pub base_url_sha256: String,
    pub nodes: Vec<DiscoveryNode>,
    pub duplicate_count: usize,
}

