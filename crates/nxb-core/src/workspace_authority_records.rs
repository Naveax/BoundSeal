use std::{collections::BTreeMap, fs, path::Path};

use anyhow::{bail, Result};

const RECORD_DIRECTORIES: &[&str] = &["targets", "sessions", "runs", "evidence", "reports"];

pub(crate) fn count_target_readiness_records(root: &Path) -> Result<BTreeMap<String, u64>> {
    let mut records = BTreeMap::new();
    for directory in RECORD_DIRECTORIES {
        let authority_path = crate::workspace::pin_private_child_path(
            root,
            directory,
            "workspace record directory",
        )?;
        records.insert((*directory).to_owned(), count_regular_files(&authority_path)?);
    }
    Ok(records)
}

fn count_regular_files(directory: &Path) -> Result<u64> {
    let mut count = 0_u64;
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        crate::workspace::reject_path_indirections(&path, "workspace record")?;
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() || metadata_is_windows_reparse(&metadata) {
            bail!("record directory contains a symbolic link or reparse point: {}", path.display());
        }
        if !metadata.is_file() {
            continue;
        }

        let file_name = path.file_name().and_then(|value| value.to_str());
        if file_name
            .and_then(crate::workspace_impl::create_document_temporary_destination)
            .is_some()
        {
            continue;
        }

        count = count
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("record count overflow"))?;
    }
    Ok(count)
}

#[cfg(windows)]
fn metadata_is_windows_reparse(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn metadata_is_windows_reparse(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readiness_record_directories_match_workspace_status_contract() {
        assert_eq!(
            RECORD_DIRECTORIES,
            &["targets", "sessions", "runs", "evidence", "reports"]
        );
    }
}
