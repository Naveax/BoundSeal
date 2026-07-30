impl ChannelAuditChain {
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
            tail_hash: CHANNEL_AUDIT_GENESIS_HASH.into(),
        }
    }

    pub fn append(&mut self, event: ChannelAuditEvent) -> Result<&ChannelAuditRecord, ChannelError> {
        let sequence = self.records.len() as u64 + 1;
        let previous_hash = self.tail_hash.clone();
        let record_hash = hash_serializable(&(sequence, &previous_hash, &event));
        self.records.push(ChannelAuditRecord {
            sequence,
            previous_hash,
            event,
            record_hash: record_hash.clone(),
        });
        self.tail_hash = record_hash;
        Ok(self.records.last().expect("channel audit append"))
    }

    pub fn records(&self) -> &[ChannelAuditRecord] {
        &self.records
    }

    pub fn tail_hash(&self) -> &str {
        &self.tail_hash
    }

    pub fn verify(&self) -> Result<(), ChannelError> {
        let mut previous = CHANNEL_AUDIT_GENESIS_HASH.to_string();
        for (index, record) in self.records.iter().enumerate() {
            if record.sequence != index as u64 + 1 {
                return Err(ChannelError::AuditSequenceMismatch {
                    record_index: index,
                });
            }
            if record.previous_hash != previous {
                return Err(ChannelError::AuditPreviousHashMismatch {
                    record_index: index,
                });
            }
            let expected = hash_serializable(&(record.sequence, &record.previous_hash, &record.event));
            if record.record_hash != expected {
                return Err(ChannelError::AuditRecordHashMismatch {
                    record_index: index,
                });
            }
            previous = expected;
        }
        if self.tail_hash != previous {
            return Err(ChannelError::AuditTailMismatch);
        }
        Ok(())
    }
}

fn compare_tls_binding(
    stream: &StreamBindingSnapshot,
    tls: &TlsBindingSnapshot,
) -> Result<(), ChannelError> {
    let checks = [
        (stream.stream_id == tls.stream_id, "stream_id"),
        (stream.execution_id == tls.execution_id, "execution_id"),
        (stream.ticket_id == tls.ticket_id, "ticket_id"),
        (stream.binding_hash == tls.binding_hash, "binding_hash"),
        (
            stream.stream_audit_anchor == tls.stream_audit_anchor,
            "stream_audit_anchor",
        ),
        (stream.sni.as_deref() == Some(tls.sni.as_str()), "sni"),
        (stream.http_host == tls.http_host, "http_host"),
        (stream.port == tls.port, "port"),
        (
            stream.redirect_depth == tls.redirect_depth,
            "redirect_depth",
        ),
    ];
    for (matches, field) in checks {
        if !matches {
            return Err(ChannelError::TlsBindingMismatch(field));
        }
    }
    if tls.alpn != "http/1.1" {
        return Err(ChannelError::InvalidAlpn);
    }
    Ok(())
}

fn validate_identifier(value: &str) -> Result<(), ChannelError> {
    if value.is_empty()
        || value.len() > 160
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(ChannelError::InvalidIdentifier);
    }
    Ok(())
}

fn validate_sha256(value: &str, name: &str) -> Result<(), ChannelError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ChannelError::InvalidStreamBinding(format!(
            "{name} must be lowercase SHA-256"
        )));
    }
    Ok(())
}

fn validate_dns_name(value: &str) -> Result<(), ChannelError> {
    if value.is_empty()
        || value.len() > 253
        || !value.is_ascii()
        || value.starts_with('.')
        || value.ends_with('.')
        || value.split('.').count() < 2
        || value.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(ChannelError::InvalidTlsBinding("invalid SNI".into()));
    }
    Ok(())
}

fn validate_authority(value: &str) -> Result<(), ChannelError> {
    if value.is_empty()
        || value.len() > 320
        || !value.is_ascii()
        || value.bytes().any(|byte| {
            byte.is_ascii_control()
                || matches!(byte, b' ' | b'\t' | b'/' | b'\\' | b'@' | b'#' | b'?')
        })
    {
        return Err(ChannelError::InvalidStreamBinding(
            "invalid HTTP authority".into(),
        ));
    }
    Ok(())
}

fn normalize_path(value: &str) -> Result<String, ChannelError> {
    if value.is_empty()
        || !value.starts_with('/')
        || value.starts_with("//")
        || value.contains('#')
        || value.contains('?')
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ' || byte == b'\\')
    {
        return Err(ChannelError::InvalidTarget(
            "path must be a clean origin-form path".into(),
        ));
    }
    Ok(value.to_string())
}

fn percent_encode(value: &str) -> String {
    let mut output = String::new();
    for byte in value.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'.' | b'_' | b'~') {
            output.push(*byte as char);
        } else {
            output.push('%');
            output.push_str(&format!("{byte:02X}"));
        }
    }
    output
}

fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn forbidden_framing_headers() -> BTreeSet<&'static str> {
    BTreeSet::from([
        "host",
        "content-length",
        "transfer-encoding",
        "connection",
        "proxy-connection",
        "expect",
        "upgrade",
        "trailer",
        "te",
    ])
}

fn sensitive_headers() -> BTreeSet<&'static str> {
    BTreeSet::from([
        "authorization",
        "proxy-authorization",
        "cookie",
        "x-api-key",
        "x-csrf-token",
    ])
}

fn validate_boundary(value: &str) -> Result<(), ChannelError> {
    if value.len() < 12
        || value.len() > 70
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(ChannelError::InvalidBody(
            "multipart boundary is invalid".into(),
        ));
    }
    Ok(())
}

fn hash_serializable<T: Serialize>(value: &T) -> String {
    match serde_json::to_vec(value) {
        Ok(bytes) => hash_bytes(&bytes),
        Err(error) => hash_bytes(error.to_string().as_bytes()),
    }
}

fn hash_bytes(bytes: &[u8]) -> String {
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

