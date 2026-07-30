use std::collections::{BTreeMap, BTreeSet};

use nxb_stream::{BoundedByteStream, ByteStreamBackend, StreamControl, StreamOperationOutcome};
use nxb_vault::SecretHeaderLease;
use sha2::{Digest, Sha256};

use crate::{
    parser::{is_token_byte, parse_response, ParseProgress},
    Http1AuditChain, Http1AuditEvent, Http1Error, Http1Exchange, Http1ExchangeReceipt, Http1Header,
    Http1Limits, Http1Request,
};

#[derive(Debug)]
pub struct Http1Codec<B> {
    stream: BoundedByteStream<B>,
    limits: Http1Limits,
    audit: Http1AuditChain,
    next_exchange_id: u64,
    completed: bool,
}

impl<B: ByteStreamBackend> Http1Codec<B> {
    pub fn new(stream: BoundedByteStream<B>, limits: Http1Limits) -> Result<Self, Http1Error> {
        let limits = limits.validate()?;
        stream.audit().verify()?;
        let audit = Http1AuditChain::new(stream.audit().tail_hash())?;
        Ok(Self {
            stream,
            limits,
            audit,
            next_exchange_id: 1,
            completed: false,
        })
    }

    pub fn exchange(
        &mut self,
        request: &Http1Request,
        control: StreamControl,
    ) -> Result<Http1Exchange, Http1Error> {
        self.exchange_internal(request, None, 0, control)
    }

    pub fn exchange_with_secret_headers(
        &mut self,
        request: &Http1Request,
        secret_headers: &mut SecretHeaderLease,
        now_epoch_seconds: i64,
        control: StreamControl,
    ) -> Result<Http1Exchange, Http1Error> {
        self.exchange_internal(
            request,
            Some(secret_headers),
            now_epoch_seconds,
            control,
        )
    }

    fn exchange_internal(
        &mut self,
        request: &Http1Request,
        secret_headers: Option<&mut SecretHeaderLease>,
        now_epoch_seconds: i64,
        control: StreamControl,
    ) -> Result<Http1Exchange, Http1Error> {
        if self.completed {
            return Err(Http1Error::ExchangeAlreadyCompleted);
        }
        if self.stream.state().is_terminal() {
            return Err(Http1Error::StreamState {
                state: self.stream.state(),
            });
        }

        let authority = self.stream.grant().http_host().to_string();
        let scheme = self.stream.grant().scheme().to_string();
        let serialized = serialize_request(
            request,
            &authority,
            &scheme,
            &self.limits,
            secret_headers.map(|lease| (lease, now_epoch_seconds)),
        )?;
        let stream_audit_before = self.stream.audit().tail_hash().to_string();
        self.write_all(&serialized.wire, control)?;
        let (response, response_wire) = self.read_response(&request.method, control)?;

        if !self.stream.state().is_terminal() {
            self.stream.close()?;
        }
        self.stream.audit().verify()?;
        let stream_audit_after = self.stream.audit().tail_hash().to_string();
        self.completed = true;

        let exchange_id = format!("http1-exchange-{:020}", self.next_exchange_id);
        self.next_exchange_id = self.next_exchange_id.saturating_add(1);
        let request_body_sha256 = payload_hash(&request.body);
        let response_body_sha256 = payload_hash(&response.body);
        let request_target_sha256 = payload_hash(request.target.as_bytes());
        let request_wire_sha256 = payload_hash(&serialized.redacted_audit_wire);
        let response_wire_sha256 = payload_hash(&response_wire);
        let mut metadata = BTreeMap::from([
            ("connection_policy".into(), "close_after_exchange".into()),
            ("authority_source".into(), "stream_grant".into()),
            (
                "secret_header_count".into(),
                serialized.secret_header_count.to_string(),
            ),
            (
                "secret_wire_audit_policy".into(),
                "length_only_redaction".into(),
            ),
        ]);
        if let Some(fingerprint) = &serialized.secret_lease_fingerprint {
            metadata.insert("secret_lease_fingerprint".into(), fingerprint.clone());
        }

        let event = Http1AuditEvent {
            exchange_id: exchange_id.clone(),
            stream_id: self.stream.grant().stream_id().into(),
            execution_id: self.stream.grant().execution_id().into(),
            request_method: request.method.clone(),
            request_target_sha256: request_target_sha256.clone(),
            request_wire_sha256: request_wire_sha256.clone(),
            request_body_sha256: request_body_sha256.clone(),
            request_header_count: serialized.header_count,
            request_body_bytes: request.body.len() as u64,
            response_wire_sha256: response_wire_sha256.clone(),
            response_body_sha256: response_body_sha256.clone(),
            response_status: response.status_code,
            response_version: response.version.code().into(),
            response_framing: response.framing.code().into(),
            response_header_count: response.headers.len() as u64,
            response_trailer_count: response.trailers.len() as u64,
            response_body_bytes: response.body.len() as u64,
            interim_responses: response.interim_responses,
            stream_audit_before: stream_audit_before.clone(),
            stream_audit_after: stream_audit_after.clone(),
            metadata,
        };
        let http_audit_tail = self.audit.append(event)?.record_hash.clone();
        let receipt = Http1ExchangeReceipt {
            exchange_id,
            stream_id: self.stream.grant().stream_id().into(),
            execution_id: self.stream.grant().execution_id().into(),
            request_method: request.method.clone(),
            request_target_sha256,
            request_wire_sha256,
            request_body_sha256,
            request_header_count: serialized.header_count,
            request_body_bytes: request.body.len() as u64,
            response_wire_sha256,
            response_body_sha256,
            response_status: response.status_code,
            response_version: response.version.code().into(),
            response_framing: response.framing.code().into(),
            response_header_count: response.headers.len() as u64,
            response_trailer_count: response.trailers.len() as u64,
            response_body_bytes: response.body.len() as u64,
            interim_responses: response.interim_responses,
            stream_audit_before,
            stream_audit_after,
            http_audit_tail,
        };
        Ok(Http1Exchange { response, receipt })
    }

    pub fn stream(&self) -> &BoundedByteStream<B> {
        &self.stream
    }

    pub fn stream_mut(&mut self) -> &mut BoundedByteStream<B> {
        &mut self.stream
    }

    pub fn audit(&self) -> &Http1AuditChain {
        &self.audit
    }

    pub fn into_stream(self) -> BoundedByteStream<B> {
        self.stream
    }

    fn write_all(&mut self, bytes: &[u8], control: StreamControl) -> Result<(), Http1Error> {
        let mut offset = 0usize;
        let mut backpressure_events = 0u64;
        while offset < bytes.len() {
            let remaining = bytes.len() - offset;
            let chunk_len = remaining.min(self.limits.io_operation_bytes as usize);
            let result = self
                .stream
                .write(&bytes[offset..offset + chunk_len], control)?;
            match result.receipt.outcome {
                StreamOperationOutcome::Written | StreamOperationOutcome::PartialWrite => {
                    let transferred = result.receipt.transferred_bytes as usize;
                    if transferred == 0 || transferred > chunk_len {
                        return Err(Http1Error::InvalidRequest(
                            "stream reported an invalid write length".into(),
                        ));
                    }
                    offset += transferred;
                    backpressure_events = 0;
                }
                StreamOperationOutcome::Backpressure => {
                    backpressure_events = backpressure_events.saturating_add(1);
                    if backpressure_events > self.limits.maximum_backpressure_events {
                        return Err(Http1Error::BackpressureBudgetExceeded);
                    }
                }
                outcome => return Err(Http1Error::StreamOutcome { outcome }),
            }
        }
        Ok(())
    }

    fn read_response(
        &mut self,
        request_method: &str,
        control: StreamControl,
    ) -> Result<(crate::Http1Response, Vec<u8>), Http1Error> {
        let mut wire = Vec::new();
        let mut eof = false;
        let mut backpressure_events = 0u64;

        loop {
            match parse_response(&wire, eof, request_method, &self.limits)? {
                ParseProgress::Complete(parsed) => {
                    if parsed.consumed_wire_bytes != wire.len() {
                        return Err(Http1Error::InvalidResponse(
                            "bytes remained after the framed response".into(),
                        ));
                    }
                    return Ok((parsed.response, wire));
                }
                ParseProgress::Incomplete if eof => {
                    return Err(Http1Error::TruncatedResponse(
                        "stream reached EOF before response framing completed".into(),
                    ));
                }
                ParseProgress::Incomplete => {}
            }

            let result = self.stream.read(self.limits.io_operation_bytes, control)?;
            match result.receipt.outcome {
                StreamOperationOutcome::Data => {
                    if result.bytes.is_empty() {
                        return Err(Http1Error::InvalidResponse(
                            "stream reported data without bytes".into(),
                        ));
                    }
                    wire.extend_from_slice(&result.bytes);
                    backpressure_events = 0;
                }
                StreamOperationOutcome::Backpressure => {
                    backpressure_events = backpressure_events.saturating_add(1);
                    if backpressure_events > self.limits.maximum_backpressure_events {
                        return Err(Http1Error::BackpressureBudgetExceeded);
                    }
                }
                StreamOperationOutcome::Eof => eof = true,
                StreamOperationOutcome::Truncated => {
                    return Err(Http1Error::TruncatedResponse(
                        "underlying stream reported truncation".into(),
                    ));
                }
                outcome => return Err(Http1Error::StreamOutcome { outcome }),
            }
            if wire.len() as u64 > self.limits.maximum_response_wire_bytes {
                return Err(Http1Error::InvalidResponse(
                    "response wire bytes exceed configured limit".into(),
                ));
            }
        }
    }
}

struct SerializedRequest {
    wire: Vec<u8>,
    redacted_audit_wire: Vec<u8>,
    header_count: u64,
    secret_header_count: u64,
    secret_lease_fingerprint: Option<String>,
}

fn serialize_request(
    request: &Http1Request,
    authority: &str,
    scheme: &str,
    limits: &Http1Limits,
    secret_headers: Option<(&mut SecretHeaderLease, i64)>,
) -> Result<SerializedRequest, Http1Error> {
    validate_method(&request.method)?;
    validate_target(&request.method, &request.target)?;
    if authority.is_empty()
        || authority.bytes().any(|byte| {
            byte.is_ascii_control() || byte == b' ' || matches!(byte, b'/' | b'\\' | b'@')
        })
    {
        return Err(Http1Error::InvalidRequest(
            "stream authority is malformed".into(),
        ));
    }
    if request.body.len() as u64 > limits.maximum_request_body_bytes {
        return Err(Http1Error::InvalidRequest(
            "request body exceeds configured limit".into(),
        ));
    }

    let mut output = Vec::new();
    let mut audit_output = Vec::new();
    append_request_prefix(&mut output, request, authority);
    append_request_prefix(&mut audit_output, request, authority);

    let mut public_names = BTreeSet::new();
    for header in &request.headers {
        let normalized_name = validate_request_header(header, limits)?;
        if is_managed_request_header(&normalized_name) {
            return Err(Http1Error::InvalidRequest(format!(
                "caller cannot supply managed header: {normalized_name}"
            )));
        }
        if is_sensitive_request_header(&normalized_name) {
            return Err(Http1Error::InvalidRequest(format!(
                "caller cannot supply vault-managed header: {normalized_name}"
            )));
        }
        public_names.insert(normalized_name.clone());
        append_header(&mut output, &normalized_name, &header.value);
        append_header(&mut audit_output, &normalized_name, &header.value);
    }

    let mut secret_header_count = 0u64;
    let mut secret_lease_fingerprint = None;
    if let Some((lease, now_epoch_seconds)) = secret_headers {
        let mut batch = lease.take_for(authority, scheme, now_epoch_seconds)?;
        for name in &public_names {
            if batch.contains_name(name) {
                return Err(Http1Error::InvalidRequest(format!(
                    "public and secret headers collide: {name}"
                )));
            }
        }
        secret_header_count = batch.header_count();
        secret_lease_fingerprint = Some(batch.lease_fingerprint().to_string());
        if request.headers.len() as u64 + secret_header_count + 3 > limits.maximum_header_count {
            return Err(Http1Error::InvalidRequest(
                "request header count exceeds configured limit".into(),
            ));
        }
        batch.append_http1(&mut output, &mut audit_output)?;
    } else if request.headers.len() as u64 + 3 > limits.maximum_header_count {
        return Err(Http1Error::InvalidRequest(
            "request header count exceeds configured limit".into(),
        ));
    }

    let content_length = request.body.len().to_string();
    append_header(&mut output, "Content-Length", content_length.as_bytes());
    append_header(
        &mut audit_output,
        "Content-Length",
        content_length.as_bytes(),
    );
    append_header(&mut output, "Connection", b"close");
    append_header(&mut audit_output, "Connection", b"close");
    output.extend_from_slice(b"\r\n");
    audit_output.extend_from_slice(b"\r\n");
    if output.len() as u64 > limits.maximum_request_header_bytes {
        return Err(Http1Error::InvalidRequest(
            "request header block exceeds configured limit".into(),
        ));
    }
    output.extend_from_slice(&request.body);
    audit_output.extend_from_slice(&request.body);
    Ok(SerializedRequest {
        wire: output,
        redacted_audit_wire: audit_output,
        header_count: request.headers.len() as u64 + secret_header_count + 3,
        secret_header_count,
        secret_lease_fingerprint,
    })
}

fn append_request_prefix(output: &mut Vec<u8>, request: &Http1Request, authority: &str) {
    output.extend_from_slice(request.method.as_bytes());
    output.push(b' ');
    output.extend_from_slice(request.target.as_bytes());
    output.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    output.extend_from_slice(authority.as_bytes());
    output.extend_from_slice(b"\r\n");
}

fn append_header(output: &mut Vec<u8>, name: &str, value: &[u8]) {
    output.extend_from_slice(name.as_bytes());
    output.extend_from_slice(b": ");
    output.extend_from_slice(value);
    output.extend_from_slice(b"\r\n");
}

fn validate_method(method: &str) -> Result<(), Http1Error> {
    if method.is_empty()
        || method.len() > 32
        || !method.bytes().all(is_token_byte)
        || !method.bytes().all(|byte| !byte.is_ascii_lowercase())
        || method == "CONNECT"
    {
        return Err(Http1Error::InvalidRequest(
            "method must be an uppercase token and CONNECT is unsupported".into(),
        ));
    }
    Ok(())
}

fn validate_target(method: &str, target: &str) -> Result<(), Http1Error> {
    if target.is_empty()
        || target.len() > 8 * 1024
        || target
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
        || target.contains('#')
        || target.starts_with("http://")
        || target.starts_with("https://")
        || target.starts_with("//")
    {
        return Err(Http1Error::InvalidRequest(
            "request target must be bounded origin-form without fragment".into(),
        ));
    }
    if target == "*" {
        if method != "OPTIONS" {
            return Err(Http1Error::InvalidRequest(
                "asterisk-form is allowed only for OPTIONS".into(),
            ));
        }
    } else if !target.starts_with('/') {
        return Err(Http1Error::InvalidRequest(
            "request target must use origin-form".into(),
        ));
    }
    Ok(())
}

fn validate_request_header(
    header: &Http1Header,
    limits: &Http1Limits,
) -> Result<String, Http1Error> {
    if header.name.is_empty()
        || header.name.len() as u64 > limits.maximum_header_name_bytes
        || !header.name.bytes().all(is_token_byte)
    {
        return Err(Http1Error::InvalidRequest(
            "request header name is invalid".into(),
        ));
    }
    if header.value.len() as u64 > limits.maximum_header_value_bytes
        || header
            .value
            .iter()
            .any(|byte| (*byte < 0x20 && *byte != b'\t') || *byte == 0x7f)
    {
        return Err(Http1Error::InvalidRequest(
            "request header value is invalid".into(),
        ));
    }
    Ok(header.name.to_ascii_lowercase())
}

fn is_managed_request_header(name: &str) -> bool {
    matches!(
        name,
        "host"
            | "content-length"
            | "transfer-encoding"
            | "connection"
            | "proxy-connection"
            | "expect"
            | "upgrade"
            | "trailer"
            | "te"
    )
}

fn is_sensitive_request_header(name: &str) -> bool {
    matches!(
        name,
        "authorization"
            | "proxy-authorization"
            | "cookie"
            | "x-api-key"
            | "x-csrf-token"
    )
}

fn payload_hash(bytes: &[u8]) -> String {
    lower_hex(&Sha256::digest(bytes))
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
