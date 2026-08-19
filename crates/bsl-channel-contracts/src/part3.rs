impl BodySource {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::Fixed(_) => "fixed",
            Self::Chunks(_) => "chunks",
            Self::Form(_) => "form",
            Self::Json(_) => "json",
            Self::Multipart { .. } => "multipart",
        }
    }

    pub fn validate(&self) -> Result<(), ChannelError> {
        let bytes = self.total_bytes();
        if bytes > MAX_REQUEST_BODY_BYTES {
            return Err(ChannelError::RequestLimit("body byte limit".into()));
        }
        match self {
            Self::Chunks(chunks) if chunks.len() > MAX_BODY_CHUNKS => {
                Err(ChannelError::RequestLimit("body chunk limit".into()))
            }
            Self::Json(bytes) => {
                if bytes.is_empty() || !matches!(bytes.first(), Some(b'{') | Some(b'[')) {
                    return Err(ChannelError::InvalidBody(
                        "JSON body must begin with an object or array".into(),
                    ));
                }
                Ok(())
            }
            Self::Multipart { boundary, parts } => {
                validate_boundary(boundary)?;
                if parts.is_empty() || parts.len() > 256 {
                    return Err(ChannelError::InvalidBody(
                        "multipart part count is outside the supported range".into(),
                    ));
                }
                for part in parts {
                    part.validate()?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    pub fn total_bytes(&self) -> usize {
        match self {
            Self::Empty => 0,
            Self::Fixed(bytes) | Self::Json(bytes) => bytes.len(),
            Self::Chunks(chunks) => chunks.iter().map(Vec::len).sum(),
            Self::Form(fields) => fields
                .iter()
                .map(|(name, value)| percent_encode(name).len() + percent_encode(value).len() + 2)
                .sum(),
            Self::Multipart { boundary, parts } => parts
                .iter()
                .map(|part| part.body.len() + part.name.len() + part.content_type.len() + boundary.len() + 64)
                .sum(),
        }
    }

    pub fn sha256(&self) -> String {
        match self {
            Self::Empty => hash_bytes(&[]),
            Self::Fixed(bytes) | Self::Json(bytes) => hash_bytes(bytes),
            Self::Chunks(chunks) => {
                let mut hasher = Sha256::new();
                for chunk in chunks {
                    hasher.update((chunk.len() as u64).to_be_bytes());
                    hasher.update(chunk);
                }
                lower_hex(&hasher.finalize())
            }
            Self::Form(fields) => hash_bytes(
                fields
                    .iter()
                    .map(|(name, value)| format!("{}={}", percent_encode(name), percent_encode(value)))
                    .collect::<Vec<_>>()
                    .join("&")
                    .as_bytes(),
            ),
            Self::Multipart { boundary, parts } => {
                let mut hasher = Sha256::new();
                hasher.update(boundary.as_bytes());
                for part in parts {
                    hasher.update(part.name.as_bytes());
                    hasher.update(part.content_type.as_bytes());
                    hasher.update((part.body.len() as u64).to_be_bytes());
                    hasher.update(&part.body);
                }
                lower_hex(&hasher.finalize())
            }
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct MultipartPart {
    pub name: String,
    pub content_type: String,
    pub body: Vec<u8>,
}

impl fmt::Debug for MultipartPart {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MultipartPart")
            .field("name", &self.name)
            .field("content_type", &self.content_type)
            .field("body_bytes", &self.body.len())
            .field("body_sha256", &hash_bytes(&self.body))
            .finish()
    }
}

impl MultipartPart {
    fn validate(&self) -> Result<(), ChannelError> {
        if self.name.is_empty()
            || self.name.len() > 128
            || self
                .name
                .bytes()
                .any(|byte| matches!(byte, b'\r' | b'\n' | b'"' | 0))
        {
            return Err(ChannelError::InvalidBody(
                "multipart part name is invalid".into(),
            ));
        }
        if self.content_type.is_empty()
            || self.content_type.len() > 256
            || !self.content_type.is_ascii()
        {
            return Err(ChannelError::InvalidBody(
                "multipart content type is invalid".into(),
            ));
        }
        Ok(())
    }
}

pub struct TypedRequestPlan {
    pub method: HttpMethod,
    pub target: RequestTarget,
    headers: Vec<RequestHeader>,
    pub body: BodySource,
    pub content_type: Option<String>,
    pub request_fingerprint_sha256: String,
}

impl fmt::Debug for TypedRequestPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TypedRequestPlan")
            .field("method", &self.method)
            .field("target_sha256", &self.target.sha256)
            .field("header_count", &self.headers.len())
            .field("body", &self.body)
            .field("content_type", &self.content_type)
            .field("request_fingerprint_sha256", &self.request_fingerprint_sha256)
            .finish()
    }
}

