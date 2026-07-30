impl TypedRequestPlan {
    pub fn build(
        channel: &HttpChannelLease,
        method: HttpMethod,
        target: RequestTarget,
        headers: Vec<RequestHeader>,
        body: BodySource,
        content_type: Option<String>,
    ) -> Result<Self, ChannelError> {
        body.validate()?;
        if headers.len() > MAX_REQUEST_HEADER_COUNT {
            return Err(ChannelError::RequestLimit("header count".into()));
        }
        let header_bytes = headers
            .iter()
            .map(|header| header.name.as_str().len() + header.value_len() + 4)
            .sum::<usize>();
        if header_bytes > MAX_REQUEST_HEADER_BYTES {
            return Err(ChannelError::RequestLimit("header bytes".into()));
        }
        let mut seen = BTreeSet::new();
        for header in &headers {
            if !seen.insert(header.name.as_str().to_string()) {
                return Err(ChannelError::InvalidHeader(
                    "duplicate caller-controlled header".into(),
                ));
            }
            if header.name.is_sensitive() && !channel.permits_sensitive_headers() {
                return Err(ChannelError::SensitiveHeadersRequireTls);
            }
        }
        if body.total_bytes() > 0 && !method.normally_has_body() && method != HttpMethod::Delete {
            return Err(ChannelError::InvalidBody(
                "method does not permit a request body in this contract".into(),
            ));
        }
        if let Some(value) = &content_type {
            if value.is_empty()
                || value.len() > 256
                || !value.is_ascii()
                || value.bytes().any(|byte| matches!(byte, b'\r' | b'\n' | 0))
            {
                return Err(ChannelError::InvalidBody("content type is invalid".into()));
            }
        }
        let header_fingerprints = headers
            .iter()
            .map(|header| {
                (
                    header.name.as_str().to_string(),
                    header.value_len(),
                    header.value_sha256(),
                )
            })
            .collect::<Vec<_>>();
        let fingerprint = hash_serializable(&(
            channel.grant_fingerprint_sha256.as_str(),
            method.as_str(),
            target.sha256(),
            &header_fingerprints,
            body.kind(),
            body.total_bytes(),
            body.sha256(),
            content_type.as_deref(),
        ));
        Ok(Self {
            method,
            target,
            headers,
            body,
            content_type,
            request_fingerprint_sha256: fingerprint,
        })
    }

    pub fn receipt(&self, channel: &HttpChannelLease) -> RequestReceipt {
        RequestReceipt {
            channel_id: channel.channel_id.clone(),
            channel_kind: channel.kind.clone(),
            authority: channel.stream.http_host.clone(),
            method: self.method.as_str().into(),
            target_sha256: self.target.sha256.clone(),
            header_count: self.headers.len(),
            header_bytes: self
                .headers
                .iter()
                .map(|header| header.name.as_str().len() + header.value_len() + 4)
                .sum(),
            body_kind: self.body.kind().into(),
            body_bytes: self.body.total_bytes(),
            body_sha256: self.body.sha256(),
            content_type: self.content_type.clone(),
            request_fingerprint_sha256: self.request_fingerprint_sha256.clone(),
            audit_anchor: channel.audit_anchor().into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RequestReceipt {
    pub channel_id: String,
    pub channel_kind: ChannelKind,
    pub authority: String,
    pub method: String,
    pub target_sha256: String,
    pub header_count: usize,
    pub header_bytes: usize,
    pub body_kind: String,
    pub body_bytes: usize,
    pub body_sha256: String,
    pub content_type: Option<String>,
    pub request_fingerprint_sha256: String,
    pub audit_anchor: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResponseLimits {
    pub maximum_header_count: usize,
    pub maximum_header_bytes: usize,
    pub maximum_body_bytes: usize,
    pub maximum_preview_bytes: usize,
}

impl Default for ResponseLimits {
    fn default() -> Self {
        Self {
            maximum_header_count: 128,
            maximum_header_bytes: 64 * 1024,
            maximum_body_bytes: 8 * 1024 * 1024,
            maximum_preview_bytes: 1024,
        }
    }
}

pub struct ResponseBodyPreview {
    bytes: Vec<u8>,
}

impl fmt::Debug for ResponseBodyPreview {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResponseBodyPreview")
            .field("bytes", &self.bytes.len())
            .field("sha256", &hash_bytes(&self.bytes))
            .finish()
    }
}

impl ResponseBodyPreview {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResponseHeaderMetadata {
    pub name: String,
    pub value_bytes: usize,
    pub value_sha256: String,
}

pub struct ResponseEnvelope {
    pub status: u16,
    pub headers: Vec<ResponseHeaderMetadata>,
    pub body_bytes: usize,
    pub body_sha256: String,
    pub body_truncated: bool,
    pub content_type: Option<String>,
    pub charset: Option<String>,
    pub redirect_location_sha256: Option<String>,
    pub set_cookie_count: usize,
    pub preview: ResponseBodyPreview,
    pub stream_audit_anchor: String,
    pub tls_audit_anchor: Option<String>,
    pub http_audit_anchor: String,
}

impl fmt::Debug for ResponseEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResponseEnvelope")
            .field("status", &self.status)
            .field("header_count", &self.headers.len())
            .field("body_bytes", &self.body_bytes)
            .field("body_sha256", &self.body_sha256)
            .field("body_truncated", &self.body_truncated)
            .field("content_type", &self.content_type)
            .field("charset", &self.charset)
            .field("redirect_location_sha256", &self.redirect_location_sha256)
            .field("set_cookie_count", &self.set_cookie_count)
            .field("preview", &self.preview)
            .finish()
    }
}

