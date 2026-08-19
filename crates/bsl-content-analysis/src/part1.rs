use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;

pub const MAX_MEDIA_TYPE_BYTES: usize = 1024;
pub const MAX_MEDIA_PARAMETERS: usize = 32;
pub const MAX_COMPRESSED_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_DECOMPRESSED_BYTES: u64 = 128 * 1024 * 1024;
pub const MAX_ENCODING_LAYERS: usize = 2;
pub const MAX_COMPRESSION_RATIO: u64 = 100;
pub const MAX_DOCUMENT_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_DOCUMENT_NODES: usize = 100_000;
pub const MAX_DOCUMENT_DEPTH: usize = 256;
pub const MAX_DISCOVERY_ITEMS: usize = 50_000;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ContentError {
    #[error("media type is invalid: {0}")]
    InvalidMediaType(String),
    #[error("charset is unsupported: {0}")]
    UnsupportedCharset(String),
    #[error("content encoding observation is invalid: {0}")]
    InvalidEncoding(String),
    #[error("structured content is invalid: {0}")]
    InvalidStructuredContent(String),
    #[error("structured content exceeds a resource limit: {0}")]
    ResourceLimit(String),
    #[error("discovered URL is invalid or unsafe: {0}")]
    InvalidDiscoveredUrl(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MediaType {
    pub type_name: String,
    pub subtype: String,
    pub parameters: BTreeMap<String, String>,
}

impl MediaType {
    pub fn parse(input: &[u8]) -> Result<Self, ContentError> {
        if input.is_empty() || input.len() > MAX_MEDIA_TYPE_BYTES || !input.is_ascii() {
            return Err(ContentError::InvalidMediaType(
                "value must be bounded ASCII".into(),
            ));
        }
        let value = std::str::from_utf8(input)
            .map_err(|_| ContentError::InvalidMediaType("value is not UTF-8 ASCII".into()))?;
        if value.bytes().any(|byte| matches!(byte, b'\r' | b'\n' | 0)) {
            return Err(ContentError::InvalidMediaType(
                "control bytes are forbidden".into(),
            ));
        }
        let mut segments = value.split(';');
        let essence = segments
            .next()
            .ok_or_else(|| ContentError::InvalidMediaType("missing essence".into()))?
            .trim()
            .to_ascii_lowercase();
        let (type_name, subtype) = essence
            .split_once('/')
            .ok_or_else(|| ContentError::InvalidMediaType("missing slash".into()))?;
        if !valid_token(type_name) || !valid_token(subtype) {
            return Err(ContentError::InvalidMediaType(
                "type or subtype token is invalid".into(),
            ));
        }
        let mut parameters = BTreeMap::new();
        for segment in segments {
            if parameters.len() >= MAX_MEDIA_PARAMETERS {
                return Err(ContentError::InvalidMediaType(
                    "too many parameters".into(),
                ));
            }
            let segment = segment.trim();
            if segment.is_empty() {
                return Err(ContentError::InvalidMediaType(
                    "empty parameter segment".into(),
                ));
            }
            let (name, raw_value) = segment
                .split_once('=')
                .ok_or_else(|| ContentError::InvalidMediaType("parameter lacks equals".into()))?;
            let name = name.trim().to_ascii_lowercase();
            if !valid_token(&name) {
                return Err(ContentError::InvalidMediaType(
                    "parameter name is invalid".into(),
                ));
            }
            let parsed = parse_parameter_value(raw_value.trim())?;
            if parameters.insert(name, parsed).is_some() {
                return Err(ContentError::InvalidMediaType(
                    "duplicate parameter".into(),
                ));
            }
        }
        Ok(Self {
            type_name: type_name.into(),
            subtype: subtype.into(),
            parameters,
        })
    }

    pub fn essence(&self) -> String {
        format!("{}/{}", self.type_name, self.subtype)
    }

    pub fn charset(&self) -> Result<Option<Charset>, ContentError> {
        self.parameters
            .get("charset")
            .map(|value| Charset::parse(value))
            .transpose()
    }

    pub fn classification(&self) -> ContentClassification {
        match (self.type_name.as_str(), self.subtype.as_str()) {
            ("text", "html") | ("application", "xhtml+xml") => ContentClassification::Html,
            ("application", "json") => ContentClassification::Json,
            (_, subtype) if subtype.ends_with("+json") => ContentClassification::Json,
            ("application", "xml") | ("text", "xml") => ContentClassification::Xml,
            (_, subtype) if subtype.ends_with("+xml") => ContentClassification::Xml,
            ("text", _) => ContentClassification::Text,
            _ => ContentClassification::Binary,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Charset {
    Utf8,
    UsAscii,
}

impl Charset {
    pub fn parse(value: &str) -> Result<Self, ContentError> {
        match value.trim().trim_matches('"').to_ascii_lowercase().as_str() {
            "utf-8" | "utf8" => Ok(Self::Utf8),
            "us-ascii" | "ascii" => Ok(Self::UsAscii),
            other => Err(ContentError::UnsupportedCharset(other.into())),
        }
    }

    pub fn validate(self, bytes: &[u8]) -> Result<(), ContentError> {
        match self {
            Self::Utf8 => std::str::from_utf8(bytes)
                .map(|_| ())
                .map_err(|_| ContentError::InvalidStructuredContent("invalid UTF-8".into())),
            Self::UsAscii => {
                if bytes.is_ascii() {
                    Ok(())
                } else {
                    Err(ContentError::InvalidStructuredContent(
                        "non-ASCII byte under US-ASCII declaration".into(),
                    ))
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ContentClassification {
    Html,
    Json,
    Xml,
    Text,
    Binary,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContentTypeAssessment {
    pub declared: Option<MediaType>,
    pub classification: ContentClassification,
    pub charset: Option<Charset>,
    pub declared_sha256: Option<String>,
    pub sniffing_performed: bool,
}

impl ContentTypeAssessment {
    pub fn strict(declared: Option<&[u8]>, body: &[u8]) -> Result<Self, ContentError> {
        let media = declared.map(MediaType::parse).transpose()?;
        let classification = media
            .as_ref()
            .map(MediaType::classification)
            .unwrap_or(ContentClassification::Binary);
        let charset = media.as_ref().map(MediaType::charset).transpose()?.flatten();
        if let Some(charset) = charset {
            charset.validate(body)?;
        }
        Ok(Self {
            declared_sha256: declared.map(hash_bytes),
            declared: media,
            classification,
            charset,
            sniffing_performed: false,
        })
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ContentEncoding {
    Identity,
    Gzip,
    Deflate,
    Brotli,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncodingLayerObservation {
    pub encoding: ContentEncoding,
    pub input_bytes: u64,
    pub output_bytes: u64,
    pub output_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncodingReceipt {
    pub layers: Vec<EncodingLayerObservation>,
    pub original_bytes: u64,
    pub final_bytes: u64,
    pub maximum_observed_ratio: u64,
    pub final_sha256: String,
}

