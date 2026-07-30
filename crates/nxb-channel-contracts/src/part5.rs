impl ResponseEnvelope {
    pub fn capture(
        channel: &HttpChannelLease,
        status: u16,
        headers: impl IntoIterator<Item = (String, Vec<u8>)>,
        body: &[u8],
        body_truncated: bool,
        http_audit_anchor: impl Into<String>,
        limits: ResponseLimits,
    ) -> Result<Self, ChannelError> {
        if !(100..=599).contains(&status) {
            return Err(ChannelError::InvalidResponse("status code".into()));
        }
        if limits.maximum_header_count == 0
            || limits.maximum_header_count > MAX_RESPONSE_HEADER_COUNT
            || limits.maximum_header_bytes == 0
            || limits.maximum_header_bytes > MAX_RESPONSE_HEADER_BYTES
            || limits.maximum_body_bytes == 0
            || limits.maximum_body_bytes > MAX_RESPONSE_BODY_BYTES
            || limits.maximum_preview_bytes > MAX_RESPONSE_PREVIEW_BYTES
        {
            return Err(ChannelError::InvalidResponse("limits".into()));
        }
        if body.len() > limits.maximum_body_bytes {
            return Err(ChannelError::InvalidResponse("body byte limit".into()));
        }
        let headers = headers.into_iter().collect::<Vec<_>>();
        if headers.len() > limits.maximum_header_count {
            return Err(ChannelError::InvalidResponse("header count".into()));
        }
        let mut header_bytes = 0usize;
        let mut metadata = Vec::with_capacity(headers.len());
        let mut content_type = None;
        let mut charset = None;
        let mut redirect_location_sha256 = None;
        let mut set_cookie_count = 0usize;
        for (name, value) in headers {
            let normalized = name.to_ascii_lowercase();
            if normalized.is_empty() || !normalized.bytes().all(is_token_byte) {
                return Err(ChannelError::InvalidResponse("header name".into()));
            }
            if value
                .iter()
                .any(|byte| matches!(*byte, 0 | b'\r' | b'\n'))
            {
                return Err(ChannelError::InvalidResponse("header value".into()));
            }
            header_bytes = header_bytes
                .checked_add(normalized.len() + value.len() + 4)
                .ok_or_else(|| ChannelError::InvalidResponse("header byte overflow".into()))?;
            if header_bytes > limits.maximum_header_bytes {
                return Err(ChannelError::InvalidResponse("header byte limit".into()));
            }
            if normalized == "content-type" {
                let parsed = String::from_utf8_lossy(&value).trim().to_ascii_lowercase();
                content_type = parsed.split(';').next().map(str::trim).map(str::to_string);
                charset = parsed
                    .split(';')
                    .skip(1)
                    .find_map(|part| part.trim().strip_prefix("charset=").map(str::to_string));
            } else if normalized == "location" {
                redirect_location_sha256 = Some(hash_bytes(&value));
            } else if normalized == "set-cookie" {
                set_cookie_count = set_cookie_count.saturating_add(1);
            }
            metadata.push(ResponseHeaderMetadata {
                name: normalized,
                value_bytes: value.len(),
                value_sha256: hash_bytes(&value),
            });
        }
        let http_audit_anchor = http_audit_anchor.into();
        validate_sha256(&http_audit_anchor, "http_audit_anchor")?;
        Ok(Self {
            status,
            headers: metadata,
            body_bytes: body.len(),
            body_sha256: hash_bytes(body),
            body_truncated,
            content_type,
            charset,
            redirect_location_sha256,
            set_cookie_count,
            preview: ResponseBodyPreview {
                bytes: body[..body.len().min(limits.maximum_preview_bytes)].to_vec(),
            },
            stream_audit_anchor: channel.stream.stream_audit_anchor.clone(),
            tls_audit_anchor: channel.tls_audit_anchor.clone(),
            http_audit_anchor,
        })
    }

    pub fn receipt(&self) -> ResponseReceipt {
        ResponseReceipt {
            status: self.status,
            header_count: self.headers.len(),
            body_bytes: self.body_bytes,
            body_sha256: self.body_sha256.clone(),
            body_truncated: self.body_truncated,
            preview_bytes: self.preview.bytes.len(),
            preview_sha256: hash_bytes(&self.preview.bytes),
            content_type: self.content_type.clone(),
            charset: self.charset.clone(),
            redirect_location_sha256: self.redirect_location_sha256.clone(),
            set_cookie_count: self.set_cookie_count,
            stream_audit_anchor: self.stream_audit_anchor.clone(),
            tls_audit_anchor: self.tls_audit_anchor.clone(),
            http_audit_anchor: self.http_audit_anchor.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResponseReceipt {
    pub status: u16,
    pub header_count: usize,
    pub body_bytes: usize,
    pub body_sha256: String,
    pub body_truncated: bool,
    pub preview_bytes: usize,
    pub preview_sha256: String,
    pub content_type: Option<String>,
    pub charset: Option<String>,
    pub redirect_location_sha256: Option<String>,
    pub set_cookie_count: usize,
    pub stream_audit_anchor: String,
    pub tls_audit_anchor: Option<String>,
    pub http_audit_anchor: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChannelAuditEvent {
    pub action: String,
    pub channel_id: String,
    pub channel_kind: String,
    pub authority: String,
    pub stream_id: String,
    pub ticket_id: String,
    pub request_fingerprint_sha256: Option<String>,
    pub response_body_sha256: Option<String>,
    pub anchor: String,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChannelAuditRecord {
    pub sequence: u64,
    pub previous_hash: String,
    pub event: ChannelAuditEvent,
    pub record_hash: String,
}

#[derive(Debug)]
pub struct ChannelAuditChain {
    records: Vec<ChannelAuditRecord>,
    tail_hash: String,
}

impl Default for ChannelAuditChain {
    fn default() -> Self {
        Self::new()
    }
}

