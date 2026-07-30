impl fmt::Debug for HttpChannelGrant {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpChannelGrant")
            .field("channel_id", &self.channel_id)
            .field("kind", &self.kind)
            .field("stream_id", &self.stream.stream_id)
            .field("authority", &self.stream.http_host)
            .field("consumed", &self.consumed)
            .field("grant_fingerprint_sha256", &self.grant_fingerprint_sha256)
            .finish()
    }
}

impl HttpChannelGrant {
    pub fn plain(
        channel_id: impl Into<String>,
        stream: StreamBindingSnapshot,
    ) -> Result<Self, ChannelError> {
        let channel_id = channel_id.into();
        validate_identifier(&channel_id)?;
        stream.validate()?;
        if stream.scheme != "http" || stream.sni.is_some() {
            return Err(ChannelError::PlainChannelRequiresHttp);
        }
        Ok(Self::build(channel_id, ChannelKind::PlainHttp, stream, None))
    }

    pub fn verified_tls(
        channel_id: impl Into<String>,
        stream: StreamBindingSnapshot,
        tls: TlsBindingSnapshot,
    ) -> Result<Self, ChannelError> {
        let channel_id = channel_id.into();
        validate_identifier(&channel_id)?;
        stream.validate()?;
        tls.validate()?;
        if stream.scheme != "https" {
            return Err(ChannelError::TlsChannelRequiresHttps);
        }
        compare_tls_binding(&stream, &tls)?;
        Ok(Self::build(
            channel_id,
            ChannelKind::VerifiedTls,
            stream,
            Some(tls),
        ))
    }

    fn build(
        channel_id: String,
        kind: ChannelKind,
        stream: StreamBindingSnapshot,
        tls: Option<TlsBindingSnapshot>,
    ) -> Self {
        let fingerprint = hash_serializable(&(
            &channel_id,
            &kind,
            &stream,
            tls.as_ref().map(|value| &value.tls_audit_anchor),
        ));
        Self {
            channel_id,
            kind,
            stream,
            tls,
            consumed: false,
            grant_fingerprint_sha256: fingerprint,
        }
    }

    pub fn consume(&mut self) -> Result<HttpChannelLease, ChannelError> {
        if self.consumed {
            return Err(ChannelError::ChannelReplay);
        }
        self.consumed = true;
        Ok(HttpChannelLease {
            channel_id: self.channel_id.clone(),
            kind: self.kind.clone(),
            stream: self.stream.clone(),
            tls_audit_anchor: self
                .tls
                .as_ref()
                .map(|value| value.tls_audit_anchor.clone()),
            grant_fingerprint_sha256: self.grant_fingerprint_sha256.clone(),
        })
    }

    pub fn is_consumed(&self) -> bool {
        self.consumed
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HttpChannelLease {
    pub channel_id: String,
    pub kind: ChannelKind,
    pub stream: StreamBindingSnapshot,
    pub tls_audit_anchor: Option<String>,
    pub grant_fingerprint_sha256: String,
}

impl HttpChannelLease {
    pub fn permits_sensitive_headers(&self) -> bool {
        self.kind.permits_sensitive_headers()
    }

    pub fn audit_anchor(&self) -> &str {
        self.tls_audit_anchor
            .as_deref()
            .unwrap_or(&self.stream.stream_audit_anchor)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Get,
    Head,
    Options,
    Post,
    Put,
    Patch,
    Delete,
}

impl HttpMethod {
    pub fn parse(value: &str) -> Result<Self, ChannelError> {
        match value {
            "GET" => Ok(Self::Get),
            "HEAD" => Ok(Self::Head),
            "OPTIONS" => Ok(Self::Options),
            "POST" => Ok(Self::Post),
            "PUT" => Ok(Self::Put),
            "PATCH" => Ok(Self::Patch),
            "DELETE" => Ok(Self::Delete),
            _ => Err(ChannelError::InvalidMethod),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Options => "OPTIONS",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
        }
    }

    pub fn normally_has_body(self) -> bool {
        matches!(self, Self::Post | Self::Put | Self::Patch)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RequestTarget {
    origin_form: String,
    sha256: String,
}

impl RequestTarget {
    pub fn new(path: &str, query: impl IntoIterator<Item = (String, String)>) -> Result<Self, ChannelError> {
        let path = normalize_path(path)?;
        let mut pairs = query.into_iter().collect::<Vec<_>>();
        pairs.sort();
        let target = if pairs.is_empty() {
            path
        } else {
            let encoded = pairs
                .into_iter()
                .map(|(name, value)| format!("{}={}", percent_encode(&name), percent_encode(&value)))
                .collect::<Vec<_>>()
                .join("&");
            format!("{path}?{encoded}")
        };
        if target.len() > 16 * 1024 {
            return Err(ChannelError::InvalidTarget("target is too long".into()));
        }
        Ok(Self {
            sha256: hash_bytes(target.as_bytes()),
            origin_form: target,
        })
    }

    pub fn as_str(&self) -> &str {
        &self.origin_form
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct HeaderName(String);

impl HeaderName {
    pub fn parse(value: &str) -> Result<Self, ChannelError> {
        let normalized = value.to_ascii_lowercase();
        if normalized.is_empty()
            || normalized.len() > 128
            || !normalized.bytes().all(is_token_byte)
        {
            return Err(ChannelError::InvalidHeader("invalid header name".into()));
        }
        if forbidden_framing_headers().contains(normalized.as_str()) {
            return Err(ChannelError::InvalidHeader(
                "caller cannot set authority or framing headers".into(),
            ));
        }
        Ok(Self(normalized))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_sensitive(&self) -> bool {
        sensitive_headers().contains(self.0.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestHeader {
    pub name: HeaderName,
    value: Vec<u8>,
}

impl RequestHeader {
    pub fn new(name: HeaderName, value: impl Into<Vec<u8>>) -> Result<Self, ChannelError> {
        let value = value.into();
        if value.len() > 8 * 1024
            || value
                .iter()
                .any(|byte| matches!(*byte, 0 | b'\r' | b'\n') || (*byte < 0x20 && *byte != b'\t'))
        {
            return Err(ChannelError::InvalidHeader("invalid header value".into()));
        }
        Ok(Self { name, value })
    }

    pub fn value_sha256(&self) -> String {
        hash_bytes(&self.value)
    }

    pub fn value_len(&self) -> usize {
        self.value.len()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum BodySource {
    Empty,
    Fixed(Vec<u8>),
    Chunks(Vec<Vec<u8>>),
    Form(BTreeMap<String, String>),
    Json(Vec<u8>),
    Multipart {
        boundary: String,
        parts: Vec<MultipartPart>,
    },
}

impl fmt::Debug for BodySource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BodySource")
            .field("kind", &self.kind())
            .field("bytes", &self.total_bytes())
            .field("sha256", &self.sha256())
            .finish()
    }
}

