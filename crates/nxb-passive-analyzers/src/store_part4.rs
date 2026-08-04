fn persist_record_bytes(
    root: &Path,
    prefix: &str,
    sequence: u64,
    bytes: &[u8],
) -> Result<PathBuf, FindingStoreError> {
    let final_path = root.join(format!("{prefix}-{sequence:020}.json"));
    let temporary = root.join(format!(".{prefix}-{sequence:020}.{}.tmp", std::process::id()));
    let publication = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(io_error)?;
        file.write_all(bytes).map_err(io_error)?;
        file.sync_all().map_err(io_error)?;
        fs::hard_link(&temporary, &final_path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                FindingStoreError::RecordAlreadyExists
            } else {
                io_error(error)
            }
        })?;
        sync_directory(root)?;
        Ok::<(), FindingStoreError>(())
    })();
    let _ = fs::remove_file(&temporary);
    publication?;
    Ok(final_path)
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

fn sync_directory(_path: &Path) -> Result<(), FindingStoreError> {
    #[cfg(unix)]
    {
        File::open(_path)
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
        return Err(FindingStoreError::InvalidIdentifier(name.into()));
    }
    Ok(())
}

fn validate_sha256(value: &str, name: &str) -> Result<(), FindingStoreError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(FindingStoreError::InvalidSha256(name.into()));
    }
    Ok(())
}

fn io_error(error: std::io::Error) -> FindingStoreError {
    FindingStoreError::Io(error.to_string())
}
