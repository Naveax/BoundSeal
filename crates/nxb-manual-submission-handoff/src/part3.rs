fn verify_component_bindings(
    closure: &RunClosureCertificate,
    report: &ReportBundle,
    export_manifest: &ExportManifest,
) -> Result<(), ManualHandoffError> {
    if closure.manifest.disposition == ClosureDisposition::Aborted
        || closure.manifest.artifacts.report_json_sha256 != report.json_sha256
        || closure.manifest.artifacts.report_markdown_sha256 != report.markdown_sha256
        || closure.manifest.artifacts.evidence_export_root_sha256 != export_manifest.root_sha256
        || closure.manifest.artifacts.knowledge_audit_tail_sha256
            != report.document.source_audit_tail_hash
        || closure.manifest.policy_snapshot_sha256 != report.document.policy_snapshot_sha256
        || closure.manifest.policy_snapshot_sha256 != export_manifest.policy_snapshot_sha256
        || report.document.evidence_manifest_sha256 != export_manifest.root_sha256
    {
        return Err(ManualHandoffError::ComponentMismatch);
    }
    Ok(())
}

fn verify_report_bundle(report: &ReportBundle) -> Result<(), ManualHandoffError> {
    let parsed: ReportDocument = serde_json::from_str(&report.json)
        .map_err(|error| ManualHandoffError::ReportSerialization(error.to_string()))?;
    let canonical_json = serde_json::to_string_pretty(&report.document)
        .map_err(|error| ManualHandoffError::ReportSerialization(error.to_string()))?;
    if parsed != report.document
        || report.json != canonical_json
        || hash_bytes(report.json.as_bytes()) != report.json_sha256
        || hash_bytes(report.markdown.as_bytes()) != report.markdown_sha256
    {
        return Err(ManualHandoffError::ReportDigestMismatch);
    }
    validate_report_document(&report.document)
}

fn validate_report_document(document: &ReportDocument) -> Result<(), ManualHandoffError> {
    validate_identifier(&document.report_id)?;
    validate_sha256(&document.policy_snapshot_sha256)?;
    validate_sha256(&document.evidence_manifest_sha256)?;
    validate_sha256(&document.source_audit_tail_hash)?;
    if document.program_name.is_empty()
        || document.program_name.len() > 256
        || document.program_name.bytes().any(|byte| byte == 0)
        || document.generated_at_epoch_seconds <= 0
        || document.findings.is_empty()
        || document.findings.len() > MAX_FINDINGS
        || contains_report_secret_like_text(&document.program_name)
    {
        return Err(ManualHandoffError::InvalidReportDocument);
    }
    let mut previous_finding_id: Option<&str> = None;
    for finding in &document.findings {
        validate_identifier(&finding.finding_id)?;
        validate_identifier(&finding.rule_id)?;
        validate_sha256(&finding.endpoint_sha256)?;
        if finding.title.is_empty()
            || finding.title.len() > 512
            || finding.summary.is_empty()
            || finding.summary.len() > 2_048
            || finding.origin.is_empty()
            || finding.origin.len() > 512
            || finding
                .title
                .bytes()
                .chain(finding.summary.bytes())
                .chain(finding.origin.bytes())
                .any(|byte| byte == 0)
            || finding.evidence_ids.is_empty()
            || contains_report_secret_like_text(&finding.title)
            || contains_report_secret_like_text(&finding.summary)
        {
            return Err(ManualHandoffError::InvalidReportDocument);
        }
        if let Some(previous) = previous_finding_id {
            if previous >= finding.finding_id.as_str() {
                return Err(ManualHandoffError::NonCanonicalFindingOrder);
            }
        }
        previous_finding_id = Some(&finding.finding_id);
        for evidence_id in &finding.evidence_ids {
            validate_identifier(evidence_id)?;
        }
    }
    Ok(())
}

fn calculate_finding_set_sha256(document: &ReportDocument) -> Result<String, ManualHandoffError> {
    let rows = document
        .findings
        .iter()
        .map(|finding| {
            (
                &finding.finding_id,
                &finding.rule_id,
                &finding.endpoint_sha256,
                &finding.evidence_ids,
            )
        })
        .collect::<Vec<_>>();
    hash_serializable(&rows)
}

fn validate_program_handle(value: &str) -> Result<(), ManualHandoffError> {
    if value.is_empty()
        || value.len() > MAX_PROGRAM_HANDLE_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(ManualHandoffError::InvalidProgramHandle);
    }
    Ok(())
}

fn validate_metadata(values: &BTreeMap<String, String>) -> Result<(), ManualHandoffError> {
    if values.len() > MAX_HANDOFF_METADATA {
        return Err(ManualHandoffError::MetadataLimit);
    }
    for (key, value) in values {
        validate_identifier(key)?;
        if value.is_empty()
            || value.len() > 512
            || value.bytes().any(|byte| byte == 0)
            || contains_secret_like_text(value)
        {
            return Err(ManualHandoffError::UnsafeMetadata);
        }
    }
    Ok(())
}

fn contains_secret_like_text(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    [
        "authorization:",
        "proxy-authorization:",
        "cookie:",
        "set-cookie:",
        "bearer ",
        "password=",
        "token=",
        "secret=",
        "private_key",
        "http://",
        "https://",
        "file://",
        "ssh://",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn contains_report_secret_like_text(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    [
        "authorization: bearer ",
        "proxy-authorization:",
        "cookie:",
        "set-cookie:",
        "password=",
        "client_secret=",
        "access_token=",
        "refresh_token=",
        "api_key=",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn validate_identifier(value: &str) -> Result<(), ManualHandoffError> {
    if value.is_empty()
        || value.len() > 192
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(ManualHandoffError::InvalidIdentifier);
    }
    Ok(())
}

fn validate_sha256(value: &str) -> Result<(), ManualHandoffError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ManualHandoffError::InvalidSha256);
    }
    Ok(())
}

fn hash_bytes(bytes: &[u8]) -> String {
    lower_hex(&Sha256::digest(bytes))
}

fn hash_serializable<T: Serialize>(value: &T) -> Result<String, ManualHandoffError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| ManualHandoffError::Serialization(error.to_string()))?;
    Ok(hash_bytes(&bytes))
}

fn decode_hex(value: &str) -> Result<Vec<u8>, ManualHandoffError> {
    if value.is_empty() || !value.len().is_multiple_of(2) {
        return Err(ManualHandoffError::InvalidSignature);
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|chunk| {
            let high = decode_nibble(chunk[0])?;
            let low = decode_nibble(chunk[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn decode_nibble(value: u8) -> Result<u8, ManualHandoffError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(ManualHandoffError::InvalidSignature),
    }
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

#[derive(Debug, Error)]
pub enum ManualHandoffError {
    #[error("handoff component binding mismatch")]
    ComponentMismatch,
    #[error("closure signature encoding is invalid")]
    InvalidClosureSignatureEncoding,
    #[error("aborted closure cannot be prepared for submission")]
    AbortedClosureNotSubmittable,
    #[error("manual review is not approved")]
    ReviewNotApproved,
    #[error("manual review time window is invalid")]
    InvalidReviewWindow,
    #[error("untested scope acknowledgement does not match closure")]
    UntestedScopeMismatch,
    #[error("handoff generation time is invalid")]
    InvalidGenerationTime,
    #[error("report bundle digest mismatch")]
    ReportDigestMismatch,
    #[error("report document is invalid or not safely redacted")]
    InvalidReportDocument,
    #[error("report findings are not in canonical order")]
    NonCanonicalFindingOrder,
    #[error("report serialization failed: {0}")]
    ReportSerialization(String),
    #[error("handoff finding count is invalid")]
    InvalidFindingCount,
    #[error("program handle is invalid")]
    InvalidProgramHandle,
    #[error("handoff metadata limit exceeded")]
    MetadataLimit,
    #[error("handoff metadata contains unsafe content")]
    UnsafeMetadata,
    #[error("handoff identifier is invalid")]
    InvalidIdentifier,
    #[error("handoff SHA-256 field is invalid")]
    InvalidSha256,
    #[error("handoff ID mismatch")]
    HandoffIdMismatch,
    #[error("handoff manifest digest mismatch")]
    ManifestDigestMismatch,
    #[error("handoff public key does not match signed plan")]
    PublicKeyMismatch,
    #[error("handoff signature is invalid")]
    InvalidSignature,
    #[error("handoff serialization failed: {0}")]
    Serialization(String),
    #[error(transparent)]
    Closure(#[from] nxb_run_closure::RunClosureError),
    #[error(transparent)]
    Knowledge(#[from] nxb_knowledge_reporting::KnowledgeError),
}
