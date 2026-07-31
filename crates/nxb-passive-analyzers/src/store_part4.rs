fn manifest_record_hash(
    record: &SegmentManifestRecord,
) -> Result<String, FindingStoreError> {
    serde_json::to_vec(&(
        record.sequence,
        &record.previous_hash,
        &record.file_name,
        &record.file_sha256,
        &record.ciphertext_sha256,
        &record.plaintext_sha256,
        &record.algorithm,
        &record.key_id_sha256,
        record.finding_count,
        record.plaintext_bytes,
        record.sealed_bytes,
    ))
    .map(|bytes| hash_bytes(&bytes))
    .map_err(serialization_error)
}

fn atomic_write_segment(
    root: &Path,
    file_name: &str,
    bytes: &[u8],
) -> Result<(), FindingStoreError> {
    let final_path = root.join(file_name);
    if final_path.exists() {
        return Err(FindingStoreError::Io(
            "append-only segment path already exists".into(),
        ));
    }
    let temporary_path = root.join(format!("{file_name}.tmp"));
    {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary_path)
            .map_err(io_error)?;
        file.write_all(bytes).map_err(io_error)?;
        file.sync_all().map_err(io_error)?;
    }
    fs::rename(&temporary_path, &final_path).map_err(io_error)?;
    sync_directory(root)?;
    Ok(())
}

fn append_manifest_line(path: &Path, line: &[u8]) -> Result<(), FindingStoreError> {
    let mut file = OpenOptions::new()
        .append(true)
        .open(path)
        .map_err(io_error)?;
    file.write_all(line).map_err(io_error)?;
    file.sync_all().map_err(io_error)?;
    if let Some(parent) = path.parent() {
        sync_directory(parent)?;
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), FindingStoreError> {
    #[cfg(unix)]
    {
        File::open(path)
            .map_err(io_error)?
            .sync_all()
            .map_err(io_error)?;
    }
    Ok(())
}

fn directory_accounted_bytes(root: &Path) -> Result<u64, FindingStoreError> {
    let mut total = 0_u64;
    for entry in fs::read_dir(root).map_err(io_error)? {
        let entry = entry.map_err(io_error)?;
        if entry.file_type().map_err(io_error)?.is_file() {
            total = total.saturating_add(entry.metadata().map_err(io_error)?.len());
        }
    }
    Ok(total)
}

fn validate_identifier(value: &str, name: &str) -> Result<(), FindingStoreError> {
    if value.is_empty()
        || value.len() > 192
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
        })
    {
        return Err(FindingStoreError::InvalidConfig(name.into()));
    }
    Ok(())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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

fn decode_hex(value: &str) -> Result<Vec<u8>, FindingStoreError> {
    if value.len() % 2 != 0 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(FindingStoreError::Serialization(
            "segment hex field is invalid".into(),
        ));
    }
    let mut output = Vec::with_capacity(value.len() / 2);
    let bytes = value.as_bytes();
    for pair in bytes.chunks_exact(2) {
        let high = decode_nibble(pair[0])?;
        let low = decode_nibble(pair[1])?;
        output.push((high << 4) | low);
    }
    Ok(output)
}

fn decode_nibble(byte: u8) -> Result<u8, FindingStoreError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(FindingStoreError::Serialization(
            "segment hex nibble is invalid".into(),
        )),
    }
}

fn io_error(error: std::io::Error) -> FindingStoreError {
    FindingStoreError::Io(error.to_string())
}

fn serialization_error(error: impl std::fmt::Display) -> FindingStoreError {
    FindingStoreError::Serialization(error.to_string())
}
