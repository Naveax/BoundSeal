use std::any::TypeId;

use nxb_stream::{BoundedByteStream, ByteStreamBackend, StreamControl};
use nxb_tls::TlsSessionGrant;
use nxb_vault::SecretHeaderLease;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    codec, Http1AuditChain, Http1Error, Http1Exchange, Http1Limits, Http1Request,
};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Http1ChannelKind {
    PlainHttp,
    VerifiedTls,
    NetworklessFixture,
}

impl Http1ChannelKind {
    fn code(self) -> &'static str {
        match self {
            Self::PlainHttp => "plain_http",
            Self::VerifiedTls => "verified_tls",
            Self::NetworklessFixture => "networkless_fixture",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Http1ChannelAuditEvent {
    pub channel_kind: String,
    pub stream_id: String,
    pub execution_id: String,
    pub ticket_id: String,
    pub binding_hash: String,
    pub authority: String,
    pub port: u16,
    pub redirect_depth: u8,
    pub tls_audit_anchor: Option<String>,
    pub http_exchange_id: String,
    pub http_audit_tail: String,
    pub response_status: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Http1ChannelAuditRecord {
    pub sequence: u64,
    pub previous_hash: String,
    pub event: Http1ChannelAuditEvent,
    pub record_hash: String,
}

#[derive(Debug)]
pub struct Http1ChannelAuditChain {
    genesis_hash: String,
    records: Vec<Http1ChannelAuditRecord>,
    tail_hash: String,
}

impl Http1ChannelAuditChain {
    fn new(genesis_hash: impl Into<String>) -> Result<Self, Http1Error> {
        let genesis_hash = genesis_hash.into();
        require_sha256(&genesis_hash, "channel audit genesis")?;
        Ok(Self {
            tail_hash: genesis_hash.clone(),
            genesis_hash,
            records: Vec::new(),
        })
    }

    fn append(
        &mut self,
        event: Http1ChannelAuditEvent,
    ) -> Result<&Http1ChannelAuditRecord, Http1Error> {
        let sequence = self.records.len() as u64 + 1;
        let previous_hash = self.tail_hash.clone();
        let record_hash = record_hash(sequence, &previous_hash, &event)?;
        self.records.push(Http1ChannelAuditRecord {
            sequence,
            previous_hash,
            event,
            record_hash: record_hash.clone(),
        });
        self.tail_hash = record_hash;
        Ok(self.records.last().expect("channel audit append"))
    }

    pub fn records(&self) -> &[Http1ChannelAuditRecord] {
        &self.records
    }

    pub fn tail_hash(&self) -> &str {
        &self.tail_hash
    }

    pub fn verify(&self) -> Result<(), Http1Error> {
        let mut previous_hash = self.genesis_hash.clone();
        for (index, record) in self.records.iter().enumerate() {
            if record.sequence != index as u64 + 1 {
                return Err(Http1Error::InvalidRequest(format!(
                    "HTTP channel audit sequence mismatch at record {index}"
                )));
            }
            if record.previous_hash != previous_hash {
                return Err(Http1Error::InvalidRequest(format!(
                    "HTTP channel audit previous-hash mismatch at record {index}"
                )));
            }
            let expected = record_hash(record.sequence, &record.previous_hash, &record.event)?;
            if record.record_hash != expected {
                return Err(Http1Error::InvalidRequest(format!(
                    "HTTP channel audit record-hash mismatch at record {index}"
                )));
            }
            previous_hash = expected;
        }
        if self.tail_hash != previous_hash {
            return Err(Http1Error::InvalidRequest(
                "HTTP channel audit tail mismatch".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct Http1Codec<B> {
    inner: codec::Http1Codec<B>,
    kind: Http1ChannelKind,
    tls_audit_anchor: Option<String>,
    channel_audit: Http1ChannelAuditChain,
}

impl<B: ByteStreamBackend + 'static> Http1Codec<B> {
    pub fn new(stream: BoundedByteStream<B>, limits: Http1Limits) -> Result<Self, Http1Error> {
        stream.audit().verify()?;
        let grant = stream.grant();
        let kind = if grant.scheme() == "http" && grant.sni().is_none() {
            Http1ChannelKind::PlainHttp
        } else if is_networkless_fixture_backend::<B>() {
            Http1ChannelKind::NetworklessFixture
        } else {
            return Err(Http1Error::InvalidRequest(
                "HTTPS streams require Http1Codec::new_verified_tls".into(),
            ));
        };
        let genesis = stream.audit().tail_hash().to_string();
        Ok(Self {
            inner: codec::Http1Codec::new(stream, limits)?,
            kind,
            tls_audit_anchor: None,
            channel_audit: Http1ChannelAuditChain::new(genesis)?,
        })
    }

    pub fn new_verified_tls(
        stream: BoundedByteStream<B>,
        tls: &TlsSessionGrant,
        limits: Http1Limits,
    ) -> Result<Self, Http1Error> {
        stream.audit().verify()?;
        validate_tls_binding(&stream, tls)?;
        let tls_audit_anchor = tls.tls_audit_anchor().to_string();
        Ok(Self {
            inner: codec::Http1Codec::new(stream, limits)?,
            kind: Http1ChannelKind::VerifiedTls,
            tls_audit_anchor: Some(tls_audit_anchor.clone()),
            channel_audit: Http1ChannelAuditChain::new(tls_audit_anchor)?,
        })
    }

    pub fn exchange(
        &mut self,
        request: &Http1Request,
        control: StreamControl,
    ) -> Result<Http1Exchange, Http1Error> {
        let exchange = self.inner.exchange(request, control)?;
        self.record_exchange(&exchange)?;
        Ok(exchange)
    }

    pub fn exchange_with_secret_headers(
        &mut self,
        request: &Http1Request,
        secret_headers: &mut SecretHeaderLease,
        now_epoch_seconds: i64,
        control: StreamControl,
    ) -> Result<Http1Exchange, Http1Error> {
        let fixture_https = self.kind == Http1ChannelKind::NetworklessFixture
            && self.inner.stream().grant().scheme() == "https";
        if self.kind != Http1ChannelKind::VerifiedTls && !fixture_https {
            return Err(Http1Error::InvalidRequest(
                "vault-managed secret headers require a verified TLS channel".into(),
            ));
        }
        let exchange = self.inner.exchange_with_secret_headers(
            request,
            secret_headers,
            now_epoch_seconds,
            control,
        )?;
        self.record_exchange(&exchange)?;
        Ok(exchange)
    }

    pub fn stream(&self) -> &BoundedByteStream<B> {
        self.inner.stream()
    }

    pub fn stream_mut(&mut self) -> &mut BoundedByteStream<B> {
        self.inner.stream_mut()
    }

    pub fn audit(&self) -> &Http1AuditChain {
        self.inner.audit()
    }

    pub fn channel_audit(&self) -> &Http1ChannelAuditChain {
        &self.channel_audit
    }

    pub fn channel_kind(&self) -> Http1ChannelKind {
        self.kind
    }

    pub fn into_stream(self) -> BoundedByteStream<B> {
        self.inner.into_stream()
    }

    fn record_exchange(&mut self, exchange: &Http1Exchange) -> Result<(), Http1Error> {
        let grant = self.inner.stream().grant();
        self.channel_audit.append(Http1ChannelAuditEvent {
            channel_kind: self.kind.code().into(),
            stream_id: grant.stream_id().into(),
            execution_id: grant.execution_id().into(),
            ticket_id: grant.ticket_id().into(),
            binding_hash: grant.binding_hash().into(),
            authority: grant.http_host().into(),
            port: grant.port(),
            redirect_depth: grant.redirect_depth(),
            tls_audit_anchor: self.tls_audit_anchor.clone(),
            http_exchange_id: exchange.receipt.exchange_id.clone(),
            http_audit_tail: exchange.receipt.http_audit_tail.clone(),
            response_status: exchange.response.status_code,
        })?;
        Ok(())
    }
}

fn is_networkless_fixture_backend<B: ByteStreamBackend + 'static>() -> bool {
    #[cfg(feature = "networkless-fixture")]
    {
        TypeId::of::<B>() == TypeId::of::<nxb_stream_fixture::InMemoryDuplex>()
    }
    #[cfg(not(feature = "networkless-fixture"))]
    {
        let _ = TypeId::of::<B>();
        false
    }
}

fn validate_tls_binding<B: ByteStreamBackend>(
    stream: &BoundedByteStream<B>,
    tls: &TlsSessionGrant,
) -> Result<(), Http1Error> {
    let grant = stream.grant();
    if grant.scheme() != "https" {
        return Err(Http1Error::InvalidRequest(
            "verified TLS channel requires an HTTPS stream".into(),
        ));
    }
    let checks = [
        (grant.stream_id() == tls.stream_id(), "stream_id"),
        (grant.execution_id() == tls.execution_id(), "execution_id"),
        (grant.ticket_id() == tls.ticket_id(), "ticket_id"),
        (grant.binding_hash() == tls.binding_hash(), "binding_hash"),
        (
            stream.audit().tail_hash() == tls.stream_audit_anchor(),
            "stream_audit_anchor",
        ),
        (grant.sni() == Some(tls.sni()), "sni"),
        (grant.http_host() == tls.http_host(), "http_host"),
        (grant.port() == tls.port(), "port"),
        (
            grant.redirect_depth() == tls.redirect_depth(),
            "redirect_depth",
        ),
    ];
    for (matches, field) in checks {
        if !matches {
            return Err(Http1Error::InvalidRequest(format!(
                "TLS grant does not match stream field: {field}"
            )));
        }
    }
    if tls.alpn() != "http/1.1" {
        return Err(Http1Error::InvalidRequest(
            "TLS grant ALPN must be http/1.1".into(),
        ));
    }
    require_sha256(tls.tls_audit_anchor(), "TLS audit anchor")?;
    Ok(())
}

fn record_hash(
    sequence: u64,
    previous_hash: &str,
    event: &Http1ChannelAuditEvent,
) -> Result<String, Http1Error> {
    let bytes = serde_json::to_vec(&(sequence, previous_hash, event)).map_err(|error| {
        Http1Error::InvalidRequest(format!("HTTP channel audit serialization failed: {error}"))
    })?;
    Ok(lower_hex(&Sha256::digest(bytes)))
}

fn require_sha256(value: &str, field: &str) -> Result<(), Http1Error> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Http1Error::InvalidRequest(format!(
            "{field} must be lowercase SHA-256"
        )));
    }
    Ok(())
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
