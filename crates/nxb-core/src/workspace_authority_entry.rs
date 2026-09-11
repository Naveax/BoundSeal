use std::path::Path;

use anyhow::{Context, Result};
use serde_json::{json, Value};

pub(crate) use crate::workspace_authority_base::*;

const DOCTOR_DIRECTORIES: &[&str] = &[
    "config", "targets", "sessions", "runs", "evidence", "reports", "state", "tmp",
];

pub(crate) fn create_document(path: &Path, bytes: &[u8]) -> Result<()> {
    crate::workspace_authority_publication::create_document(path, bytes)
}

pub(crate) fn create_document_error_published(error: &anyhow::Error) -> bool {
    crate::workspace_authority_publication::error_published(error)
        || crate::workspace_authority_base::create_document_error_published(error)
}

pub(crate) fn doctor_value(workspace: &Path) -> Result<Value> {
    let mut checks = Vec::new();
    let canonical_root = match crate::workspace_authority_base::validate_workspace_root(workspace, false) {
        Ok(root) => {
            checks.push(json!({
                "name": "workspace_root",
                "status": "pass",
                "detail": format!("canonical root: {}", root.display()),
            }));
            Some(root)
        }
        Err(error) => {
            checks.push(json!({
                "name": "workspace_root",
                "status": "fail",
                "detail": error.to_string(),
            }));
            None
        }
    };

    let mut workspace_id = None;
    if let Some(root) = canonical_root.as_ref() {
        let manifest_path = root.join(crate::workspace_impl::MANIFEST_FILE);
        match crate::workspace_authority_base::read_document(&manifest_path, "workspace manifest")
            .and_then(|bytes| {
                let manifest: crate::workspace_impl::ManifestV1 = serde_json::from_slice(&bytes)
                    .context("workspace manifest is invalid")?;
                crate::workspace_impl::validate_manifest_v1(&manifest)?;
                Ok(manifest)
            })
        {
            Ok(manifest) => {
                workspace_id = Some(manifest.workspace_id);
                checks.push(json!({
                    "name": "manifest",
                    "status": "pass",
                    "detail": format!(
                        "schema={} secret_storage=external_provider_only",
                        manifest.schema_version
                    ),
                }));
            }
            Err(error) => checks.push(json!({
                "name": "manifest",
                "status": "fail",
                "detail": error.to_string(),
            })),
        }

        for directory in DOCTOR_DIRECTORIES {
            match crate::workspace_authority_base::pin_private_child_path(
                root,
                directory,
                "workspace canonical directory",
            ) {
                Ok(path) => checks.push(json!({
                    "name": format!("directory_{directory}"),
                    "status": "pass",
                    "detail": path.display().to_string(),
                })),
                Err(error) => checks.push(json!({
                    "name": format!("directory_{directory}"),
                    "status": "fail",
                    "detail": error.to_string(),
                })),
            }
        }

        match crate::workspace_doctor_probe::run(&root.join("tmp")) {
            Ok(()) => checks.push(json!({
                "name": "atomic_write_probe",
                "status": "pass",
                "detail": "object-lifetime create/write/sync/finalization succeeded",
            })),
            Err(error) => checks.push(json!({
                "name": "atomic_write_probe",
                "status": "fail",
                "detail": error.to_string(),
            })),
        }
    }

    let errors = checks
        .iter()
        .filter(|check| check.get("status").and_then(Value::as_str) == Some("fail"))
        .count();

    Ok(json!({
        "status": if errors == 0 { "healthy" } else { "unhealthy" },
        "workspace": workspace.display().to_string(),
        "workspace_id": workspace_id,
        "checks": checks,
        "errors": errors,
    }))
}

pub(crate) fn status_value(workspace: &Path) -> Result<Value> {
    let mut value = crate::workspace_authority_base::status_value(workspace)?;
    let records = crate::workspace_authority_records::count_target_readiness_records(workspace)?;
    let object = value
        .as_object_mut()
        .context("workspace authority status returned a non-object JSON document")?;
    object.insert(
        "records".to_owned(),
        serde_json::to_value(records).context("could not serialize workspace authority records")?,
    );
    Ok(value)
}
