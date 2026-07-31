fn encode_fixed_run(ids: &[String]) -> Result<Vec<u8>, ExactDedupError> {
    if ids.is_empty() || ids.len() > MAX_RUN_ENTRIES {
        return Err(ExactDedupError::RunStructure(
            "run entry count is outside policy".into(),
        ));
    }
    let mut previous: Option<&str> = None;
    let mut bytes = Vec::with_capacity(ids.len().saturating_mul(FIXED_RECORD_BYTES as usize));
    for id in ids {
        validate_finding_id(id)?;
        if previous.is_some_and(|value| value >= id.as_str()) {
            return Err(ExactDedupError::RunStructure(
                "run identifiers are not strictly sorted".into(),
            ));
        }
        bytes.extend_from_slice(id.as_bytes());
        bytes.push(b'\n');
        previous = Some(id);
    }
    Ok(bytes)
}

fn run_contains_exact(
    path: &Path,
    record: &DedupRunRecord,
    finding_id: &str,
) -> Result<bool, ExactDedupError> {
    let mut file = File::open(path).map_err(dedup_io_error)?;
    let mut low = 0_u64;
    let mut high = record.entry_count;
    let mut buffer = [0_u8; FIXED_RECORD_BYTES as usize];

    while low < high {
        let midpoint = low + (high - low) / 2;
        file.seek(SeekFrom::Start(midpoint.saturating_mul(FIXED_RECORD_BYTES)))
            .map_err(dedup_io_error)?;
        file.read_exact(&mut buffer).map_err(dedup_io_error)?;
        if buffer[FINDING_ID_HEX_BYTES] != b'\n' {
            return Err(ExactDedupError::RunStructure(record.file_name.clone()));
        }
        let candidate = std::str::from_utf8(&buffer[..FINDING_ID_HEX_BYTES])
            .map_err(|error| ExactDedupError::RunStructure(error.to_string()))?;
        match candidate.cmp(finding_id) {
            std::cmp::Ordering::Less => low = midpoint.saturating_add(1),
            std::cmp::Ordering::Greater => high = midpoint,
            std::cmp::Ordering::Equal => return Ok(true),
        }
    }
    Ok(false)
}

fn load_and_verify_dedup_manifest(
    root: &Path,
    manifest_path: &Path,
    index_id: &str,
) -> Result<Vec<DedupRunRecord>, ExactDedupError> {
    let content = fs::read_to_string(manifest_path).map_err(dedup_io_error)?;
    let mut records = Vec::new();
    let mut previous_hash = dedup_hash(format!("nxb-exact-dedup:{index_id}").as_bytes());
    for (index, line) in content.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let record: DedupRunRecord =
            serde_json::from_str(line).map_err(dedup_serialization_error)?;
        if record.sequence != records.len() as u64 + 1
            || record.previous_hash != previous_hash
        {
            return Err(ExactDedupError::ManifestChain {
                record_index: index,
            });
        }
        let expected = dedup_manifest_record_hash(&record)?;
        if record.record_hash != expected {
            return Err(ExactDedupError::ManifestRecordHash {
                record_index: index,
            });
        }
        verify_dedup_run(root, &record)?;
        previous_hash = record.record_hash.clone();
        records.push(record);
    }
    Ok(records)
}

fn verify_dedup_run(root: &Path, record: &DedupRunRecord) -> Result<(), ExactDedupError> {
    if record.entry_count == 0 || record.entry_count > MAX_RUN_ENTRIES as u64 {
        return Err(ExactDedupError::RunStructure(record.file_name.clone()));
    }
    validate_finding_id(&record.first_finding_id)?;
    validate_finding_id(&record.last_finding_id)?;
    if record.first_finding_id > record.last_finding_id {
        return Err(ExactDedupError::RunStructure(record.file_name.clone()));
    }

    let path = root.join(&record.file_name);
    if !path.is_file() {
        return Err(ExactDedupError::MissingRun(record.file_name.clone()));
    }
    let metadata = fs::metadata(&path).map_err(dedup_io_error)?;
    let expected_bytes = record.entry_count.saturating_mul(FIXED_RECORD_BYTES);
    if metadata.len() != expected_bytes || record.file_bytes != expected_bytes {
        return Err(ExactDedupError::RunStructure(record.file_name.clone()));
    }
    let bytes = fs::read(&path).map_err(dedup_io_error)?;
    if dedup_hash(&bytes) != record.file_sha256 {
        return Err(ExactDedupError::RunHash(record.file_name.clone()));
    }

    let mut previous: Option<&[u8]> = None;
    for chunk in bytes.chunks_exact(FIXED_RECORD_BYTES as usize) {
        if chunk[FINDING_ID_HEX_BYTES] != b'\n'
            || !chunk[..FINDING_ID_HEX_BYTES]
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
            || previous.is_some_and(|value| value >= &chunk[..FINDING_ID_HEX_BYTES])
        {
            return Err(ExactDedupError::RunStructure(record.file_name.clone()));
        }
        previous = Some(&chunk[..FINDING_ID_HEX_BYTES]);
    }
    let first = std::str::from_utf8(&bytes[..FINDING_ID_HEX_BYTES])
        .map_err(|error| ExactDedupError::RunStructure(error.to_string()))?;
    let last_offset = (record.entry_count - 1).saturating_mul(FIXED_RECORD_BYTES) as usize;
    let last = std::str::from_utf8(
        &bytes[last_offset..last_offset.saturating_add(FINDING_ID_HEX_BYTES)],
    )
    .map_err(|error| ExactDedupError::RunStructure(error.to_string()))?;
    if first != record.first_finding_id || last != record.last_finding_id {
        return Err(ExactDedupError::RunStructure(record.file_name.clone()));
    }
    Ok(())
}

fn reject_orphan_runs(root: &Path, records: &[DedupRunRecord]) -> Result<(), ExactDedupError> {
    let referenced = records
        .iter()
        .map(|record| record.file_name.as_str())
        .collect::<BTreeSet<_>>();
    for entry in fs::read_dir(root).map_err(dedup_io_error)? {
        let entry = entry.map_err(dedup_io_error)?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.ends_with(".tmp") {
            return Err(ExactDedupError::OrphanRun(name));
        }
        if name.starts_with("dedup-run-")
            && name.ends_with(".idx")
            && !referenced.contains(name.as_str())
        {
            return Err(ExactDedupError::OrphanRun(name));
        }
    }
    Ok(())
}

fn dedup_manifest_record_hash(record: &DedupRunRecord) -> Result<String, ExactDedupError> {
    serde_json::to_vec(&(
        record.sequence,
        &record.previous_hash,
        &record.file_name,
        &record.file_sha256,
        &record.first_finding_id,
        &record.last_finding_id,
        record.entry_count,
        record.file_bytes,
    ))
    .map(|bytes| dedup_hash(&bytes))
    .map_err(dedup_serialization_error)
}

fn atomic_write_dedup_run(
    root: &Path,
    file_name: &str,
    bytes: &[u8],
) -> Result<(), ExactDedupError> {
    let final_path = root.join(file_name);
    if final_path.exists() {
        return Err(ExactDedupError::Io(
            "append-only dedup run already exists".into(),
        ));
    }
    let temporary_path = root.join(format!("{file_name}.tmp"));
    {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary_path)
            .map_err(dedup_io_error)?;
        file.write_all(bytes).map_err(dedup_io_error)?;
        file.sync_all().map_err(dedup_io_error)?;
    }
    fs::rename(&temporary_path, &final_path).map_err(dedup_io_error)?;
    dedup_sync_directory(root)?;
    Ok(())
}

fn append_dedup_manifest_line(path: &Path, line: &[u8]) -> Result<(), ExactDedupError> {
    let mut file = OpenOptions::new()
        .append(true)
        .open(path)
        .map_err(dedup_io_error)?;
    file.write_all(line).map_err(dedup_io_error)?;
    file.sync_all().map_err(dedup_io_error)?;
    if let Some(parent) = path.parent() {
        dedup_sync_directory(parent)?;
    }
    Ok(())
}

fn dedup_sync_directory(path: &Path) -> Result<(), ExactDedupError> {
    #[cfg(unix)]
    {
        File::open(path)
            .map_err(dedup_io_error)?
            .sync_all()
            .map_err(dedup_io_error)?;
    }
    Ok(())
}

fn dedup_directory_bytes(root: &Path) -> Result<u64, ExactDedupError> {
    let mut total = 0_u64;
    for entry in fs::read_dir(root).map_err(dedup_io_error)? {
        let entry = entry.map_err(dedup_io_error)?;
        if entry.file_type().map_err(dedup_io_error)?.is_file() {
            total = total.saturating_add(entry.metadata().map_err(dedup_io_error)?.len());
        }
    }
    Ok(total)
}

fn validate_index_identifier(value: &str) -> Result<(), ExactDedupError> {
    if value.is_empty()
        || value.len() > 192
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
        })
    {
        return Err(ExactDedupError::InvalidConfig("index_id".into()));
    }
    Ok(())
}

fn validate_finding_id(value: &str) -> Result<(), ExactDedupError> {
    if value.len() != FINDING_ID_HEX_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ExactDedupError::InvalidFindingId);
    }
    Ok(())
}

fn dedup_hash(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn dedup_io_error(error: std::io::Error) -> ExactDedupError {
    ExactDedupError::Io(error.to_string())
}

fn dedup_serialization_error(error: impl std::fmt::Display) -> ExactDedupError {
    ExactDedupError::Serialization(error.to_string())
}
