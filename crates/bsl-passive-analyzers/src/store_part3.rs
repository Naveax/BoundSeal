fn validate_sealer<S: SegmentSealer>(sealer: &S) -> Result<(), FindingStoreError> {
    let algorithm = sealer.algorithm_id();
    let key_id = sealer.key_id_sha256();
    if algorithm.is_empty()
        || algorithm.len() > 128
        || algorithm.eq_ignore_ascii_case("plaintext")
        || algorithm.eq_ignore_ascii_case("identity")
        || algorithm.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(FindingStoreError::InvalidSealer(
            "algorithm must identify authenticated encryption".into(),
        ));
    }
    if !is_sha256(key_id) {
        return Err(FindingStoreError::InvalidSealer(
            "key identifier must be a SHA-256 digest".into(),
        ));
    }
    Ok(())
}

fn validate_payload<S: SegmentSealer>(
    payload: &SealedPayload,
    sealer: &S,
    plaintext: &[u8],
) -> Result<(), FindingStoreError> {
    if payload.algorithm != sealer.algorithm_id()
        || payload.key_id_sha256 != sealer.key_id_sha256()
        || payload.nonce.len() < 12
        || payload.authentication_tag.len() < 16
        || payload.ciphertext.is_empty()
        || payload.ciphertext == plaintext
        || (payload.ciphertext.len() as u64)
            > (plaintext.len() as u64).saturating_add(sealer.maximum_overhead_bytes())
    {
        return Err(FindingStoreError::InvalidSealer(
            "sealed payload does not satisfy the backend contract".into(),
        ));
    }
    Ok(())
}

fn validate_finding(finding: &Finding) -> Result<(), FindingStoreError> {
    for (value, name, maximum) in [
        (finding.finding_id.as_str(), "finding_id", 64_usize),
        (finding.rule_id.as_str(), "rule_id", 192),
        (finding.title.as_str(), "title", 512),
        (finding.origin.as_str(), "origin", 2048),
        (finding.endpoint_sha256.as_str(), "endpoint_sha256", 64),
        (finding.evidence_sha256.as_str(), "evidence_sha256", 64),
        (finding.summary.as_str(), "summary", 4096),
    ] {
        if value.is_empty()
            || value.len() > maximum
            || value
                .bytes()
                .any(|byte| byte == 0 || byte == b'\r' || byte == b'\n')
        {
            return Err(FindingStoreError::InvalidFinding(name.into()));
        }
    }
    if !is_sha256(&finding.finding_id)
        || !is_sha256(&finding.endpoint_sha256)
        || !is_sha256(&finding.evidence_sha256)
    {
        return Err(FindingStoreError::InvalidFinding(
            "digest field is not canonical SHA-256".into(),
        ));
    }
    if finding.metadata.len() > MAX_METADATA_ENTRIES {
        return Err(FindingStoreError::InvalidFinding(
            "metadata entry bound".into(),
        ));
    }
    for (key, value) in &finding.metadata {
        if key.is_empty()
            || key.len() > 128
            || value.len() > MAX_METADATA_VALUE_BYTES
            || key.bytes().any(|byte| byte.is_ascii_control())
            || value
                .bytes()
                .any(|byte| byte == 0 || byte == b'\r' || byte == b'\n')
            || forbidden_secret_key(key)
        {
            return Err(FindingStoreError::InvalidFinding(
                "metadata key/value policy".into(),
            ));
        }
    }
    Ok(())
}

fn forbidden_secret_key(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase();
    [
        "authorization_value",
        "cookie_value",
        "set_cookie_value",
        "password",
        "secret_value",
        "token_value",
        "request_body",
        "response_body",
        "raw_header",
    ]
    .iter()
    .any(|forbidden| normalized == *forbidden || normalized.ends_with(forbidden))
}

fn load_and_verify_manifest(
    root: &Path,
    manifest_path: &Path,
    store_id: &str,
) -> Result<Vec<SegmentManifestRecord>, FindingStoreError> {
    let file = File::open(manifest_path).map_err(io_error)?;
    let reader = BufReader::new(file);
    let mut manifest = Vec::new();
    let mut previous_hash = hash_bytes(format!("bsl-finding-store:{store_id}").as_bytes());

    for (index, line) in reader.lines().enumerate() {
        let line = line.map_err(io_error)?;
        if line.trim().is_empty() {
            continue;
        }
        let record: SegmentManifestRecord =
            serde_json::from_str(&line).map_err(serialization_error)?;
        if record.sequence != manifest.len() as u64 + 1 {
            return Err(FindingStoreError::ManifestChain {
                record_index: index,
            });
        }
        if record.previous_hash != previous_hash {
            return Err(FindingStoreError::ManifestChain {
                record_index: index,
            });
        }
        let expected = manifest_record_hash(&record)?;
        if record.record_hash != expected {
            return Err(FindingStoreError::ManifestRecordHash {
                record_index: index,
            });
        }
        verify_segment_file(root, &record)?;
        previous_hash = record.record_hash.clone();
        manifest.push(record);
    }
    Ok(manifest)
}

fn verify_segment_file(
    root: &Path,
    record: &SegmentManifestRecord,
) -> Result<(), FindingStoreError> {
    let path = root.join(&record.file_name);
    if !path.is_file() {
        return Err(FindingStoreError::MissingSegment(record.file_name.clone()));
    }
    let bytes = fs::read(&path).map_err(io_error)?;
    if hash_bytes(&bytes) != record.file_sha256 {
        return Err(FindingStoreError::SegmentFileHash(
            record.file_name.clone(),
        ));
    }
    let segment: SegmentFile =
        serde_json::from_slice(&bytes).map_err(serialization_error)?;
    let ciphertext = decode_hex(&segment.ciphertext_hex)?;
    if segment.version != STORE_FORMAT_VERSION
        || bytes.len() as u64 != record.sealed_bytes
        || hash_bytes(&ciphertext) != record.ciphertext_sha256
        || segment.sequence != record.sequence
        || segment.algorithm != record.algorithm
        || segment.key_id_sha256 != record.key_id_sha256
        || segment.plaintext_sha256 != record.plaintext_sha256
        || segment.finding_count != record.finding_count
        || segment.plaintext_bytes != record.plaintext_bytes
    {
        return Err(FindingStoreError::SegmentPayloadHash(
            record.file_name.clone(),
        ));
    }
    Ok(())
}

fn reject_orphan_segments(
    root: &Path,
    manifest: &[SegmentManifestRecord],
) -> Result<(), FindingStoreError> {
    let referenced = manifest
        .iter()
        .map(|record| record.file_name.as_str())
        .collect::<BTreeSet<_>>();
    for entry in fs::read_dir(root).map_err(io_error)? {
        let entry = entry.map_err(io_error)?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.ends_with(".tmp") {
            return Err(FindingStoreError::OrphanSegment(name));
        }
        if name.starts_with("segment-")
            && name.ends_with(".bsl")
            && !referenced.contains(name.as_str())
        {
            return Err(FindingStoreError::OrphanSegment(name));
        }
    }
    Ok(())
}
