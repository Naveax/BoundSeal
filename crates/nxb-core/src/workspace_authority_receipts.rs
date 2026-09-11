use std::{fs, path::Path};

use anyhow::{bail, Context, Result};

const MAX_RECEIPTS: usize = 1_024;

pub(crate) fn validate_target_readiness_receipts(root: &Path) -> Result<usize> {
    let state = crate::workspace::pin_private_child_path(
        root,
        "state",
        "migration state directory",
    )?;
    let receipts = state.join("migrations");

    if !crate::workspace::safe_exists(&receipts)? {
        return Ok(0);
    }

    crate::workspace::reject_path_indirections(&receipts, "migration receipts directory")?;
    let metadata = fs::symlink_metadata(&receipts)
        .with_context(|| format!("could not inspect {}", receipts.display()))?;
    if !metadata.is_dir() {
        bail!("migration receipts path is not a directory");
    }
    crate::workspace_impl::validate_private_permissions(&receipts, true)?;

    let mut count = 0_usize;
    for entry in fs::read_dir(&receipts)
        .with_context(|| format!("could not enumerate {}", receipts.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        crate::workspace::reject_path_indirections(&path, "migration receipt")?;
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.is_file() {
            bail!("migration receipts directory contains a non-file entry");
        }
        let file_name = entry.file_name();
        if file_name
            .to_str()
            .and_then(crate::workspace_impl::create_document_temporary_destination)
            .is_some()
        {
            continue;
        }
        crate::workspace_impl::validate_private_permissions(&path, false)?;
        count = count
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("receipt count overflow"))?;
        if count > MAX_RECEIPTS {
            bail!("migration receipt count exceeds the supported limit");
        }
    }

    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipt_limit_matches_workspace_migration_contract() {
        assert_eq!(MAX_RECEIPTS, 1_024);
    }

    #[test]
    fn prepared_publication_residue_uses_the_quarantined_temp_shape() {
        assert_eq!(
            crate::workspace_impl::create_document_temporary_destination(
                ".nxb-migration-0-1-example.json.0123456789abcdef01234567.tmp"
            ),
            Some("nxb-migration-0-1-example.json")
        );
    }
}
