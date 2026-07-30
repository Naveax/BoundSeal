pub fn validate_encoding_layers(
    layers: Vec<EncodingLayerObservation>,
) -> Result<EncodingReceipt, ContentError> {
    if layers.is_empty() || layers.len() > MAX_ENCODING_LAYERS {
        return Err(ContentError::InvalidEncoding(
            "encoding layer count is outside the supported range".into(),
        ));
    }
    let mut previous_output = None;
    let mut maximum_ratio = 1u64;
    for (index, layer) in layers.iter().enumerate() {
        validate_sha256(&layer.output_sha256)?;
        if layer.input_bytes == 0 || layer.input_bytes > MAX_COMPRESSED_BYTES {
            return Err(ContentError::InvalidEncoding(format!(
                "layer {index} input byte count"
            )));
        }
        if layer.output_bytes > MAX_DECOMPRESSED_BYTES {
            return Err(ContentError::InvalidEncoding(format!(
                "layer {index} output byte count"
            )));
        }
        if let Some(expected) = previous_output {
            if layer.input_bytes != expected {
                return Err(ContentError::InvalidEncoding(
                    "encoding layers are not byte-accounting contiguous".into(),
                ));
            }
        }
        let ratio = layer.output_bytes.saturating_add(layer.input_bytes - 1) / layer.input_bytes;
        if ratio > MAX_COMPRESSION_RATIO {
            return Err(ContentError::InvalidEncoding(
                "compression ratio exceeds the supported limit".into(),
            ));
        }
        maximum_ratio = maximum_ratio.max(ratio);
        previous_output = Some(layer.output_bytes);
    }
    Ok(EncodingReceipt {
        original_bytes: layers[0].input_bytes,
        final_bytes: layers.last().expect("non-empty encoding layers").output_bytes,
        maximum_observed_ratio: maximum_ratio,
        final_sha256: layers
            .last()
            .expect("non-empty encoding layers")
            .output_sha256
            .clone(),
        layers,
    })
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExtractionLimits {
    pub maximum_bytes: usize,
    pub maximum_nodes: usize,
    pub maximum_depth: usize,
    pub maximum_links: usize,
    pub maximum_forms: usize,
    pub maximum_tokens: usize,
}

impl Default for ExtractionLimits {
    fn default() -> Self {
        Self {
            maximum_bytes: 8 * 1024 * 1024,
            maximum_nodes: 20_000,
            maximum_depth: 128,
            maximum_links: 10_000,
            maximum_forms: 2_000,
            maximum_tokens: 200_000,
        }
    }
}

impl ExtractionLimits {
    fn validate(self) -> Result<Self, ContentError> {
        if self.maximum_bytes == 0
            || self.maximum_bytes > MAX_DOCUMENT_BYTES
            || self.maximum_nodes == 0
            || self.maximum_nodes > MAX_DOCUMENT_NODES
            || self.maximum_depth == 0
            || self.maximum_depth > MAX_DOCUMENT_DEPTH
            || self.maximum_links > MAX_DISCOVERY_ITEMS
            || self.maximum_forms > MAX_DISCOVERY_ITEMS
            || self.maximum_tokens > 1_000_000
        {
            return Err(ContentError::ResourceLimit("extraction limits".into()));
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExtractedLink {
    pub raw_target_sha256: String,
    pub raw_target: String,
    pub source_tag: String,
    pub source_attribute: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExtractedForm {
    pub action_sha256: String,
    pub action: String,
    pub method: String,
    pub enctype: String,
    pub parameter_names: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StructuredDocument {
    pub kind: ContentClassification,
    pub body_sha256: String,
    pub body_bytes: usize,
    pub node_count: usize,
    pub maximum_depth: usize,
    pub token_count: usize,
    pub links: Vec<ExtractedLink>,
    pub forms: Vec<ExtractedForm>,
    pub metadata: BTreeMap<String, String>,
}

pub fn extract_structured(
    classification: ContentClassification,
    body: &[u8],
    limits: ExtractionLimits,
) -> Result<StructuredDocument, ContentError> {
    let limits = limits.validate()?;
    if body.len() > limits.maximum_bytes {
        return Err(ContentError::ResourceLimit("document bytes".into()));
    }
    match classification {
        ContentClassification::Html => extract_html(body, limits),
        ContentClassification::Json => extract_json(body, limits),
        ContentClassification::Xml => extract_xml(body, limits),
        ContentClassification::Text => extract_text(body, limits),
        ContentClassification::Binary => Ok(StructuredDocument {
            kind: ContentClassification::Binary,
            body_sha256: hash_bytes(body),
            body_bytes: body.len(),
            node_count: 0,
            maximum_depth: 0,
            token_count: 0,
            links: Vec::new(),
            forms: Vec::new(),
            metadata: BTreeMap::from([("parser".into(), "binary_metadata_only".into())]),
        }),
    }
}

