use std::{fs, path::PathBuf};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use crate::{engine, migration_io, LegacyManifestV0, CURRENT_SCHEMA_VERSION, MANIFEST_FILE, PRODUCT_NAME};

fn workspace(name: &str, schema: u32) -> PathBuf {
    let root = std::env::temp_dir().join(format!("nxb-migration-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir(&root).unwrap();
    #[cfg(unix)]
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let state = root.join("state");
    fs::create_dir(&state).unwrap();
    #[cfg(unix)]
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    let receipts = state.join("migrations");
    fs::create_dir(&receipts).unwrap();
    #[cfg(unix)]
    fs::set_permissions(&receipts, fs::Permissions::from_mode(0o700)).unwrap();
    let bytes = if schema == 0 {
        let mut value = serde_json::to_vec_pretty(&LegacyManifestV0 {
            schema_version: 0,
            product: PRODUCT_NAME.into(),
            workspace_id: "nxb-workspace-test-0001".into(),
            name: "Migration Test".into(),
            created_at: "2026-08-05T00:00:00Z".into(),
        }).unwrap();
        value.push(b'\n');
        value
    } else {
        format!("{{\n  \"schema_version\": {schema},\n  \"product\": \"NXBounty\",\n  \"workspace_id\": \"nxb-workspace-test-0001\",\n  \"name\": \"Migration Test\",\n  \"created_at\": \"2026-08-05T00:00:00Z\"\n}}\n").into_bytes()
    };
    fs::write(root.join(MANIFEST_FILE), bytes).unwrap();
    #[cfg(unix)]
    fs::set_permissions(root.join(MANIFEST_FILE), fs::Permissions::from_mode(0o600)).unwrap();
    root
}

#[test]
fn migrates_schema_zero_and_writes_receipt() {
    let root = workspace("apply", 0);
    let paths = migration_io::ensure_state_layout(&root).unwrap();
    let source = migration_io::read_document(&paths.manifest, "manifest").unwrap();
    let plan = engine::plan(&source).unwrap();
    engine::prepare(&paths, &plan, &source).unwrap();
    engine::recover(&paths).unwrap();
    assert_eq!(migration_io::optional_manifest_schema(&paths.manifest).unwrap(), Some(1));
    assert!(paths.receipt(&plan.migration_id).is_file());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn recovers_prepared_source_manifest() {
    let root = workspace("prepared", 0);
    let paths = migration_io::ensure_state_layout(&root).unwrap();
    let source = migration_io::read_document(&paths.manifest, "manifest").unwrap();
    let plan = engine::plan(&source).unwrap();
    engine::prepare(&paths, &plan, &source).unwrap();
    engine::recover(&paths).unwrap();
    assert_eq!(migration_io::transient_state(&paths).unwrap(), 0);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn recovers_target_published_before_applied_marker() {
    let root = workspace("published", 0);
    let paths = migration_io::ensure_state_layout(&root).unwrap();
    let source = migration_io::read_document(&paths.manifest, "manifest").unwrap();
    let plan = engine::plan(&source).unwrap();
    engine::prepare(&paths, &plan, &source).unwrap();
    migration_io::replace_document(&paths.manifest, &plan.target_bytes).unwrap();
    engine::recover(&paths).unwrap();
    assert_eq!(migration_io::transient_state(&paths).unwrap(), 0);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn recovers_orphan_backup_before_journal() {
    let root = workspace("orphan", 0);
    let paths = migration_io::ensure_state_layout(&root).unwrap();
    let source = migration_io::read_document(&paths.manifest, "manifest").unwrap();
    migration_io::create_document(&paths.backup, &source).unwrap();
    engine::recover(&paths).unwrap();
    assert_eq!(migration_io::optional_manifest_schema(&paths.manifest).unwrap(), Some(1));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn rejects_manifest_tamper_during_active_migration() {
    let root = workspace("tamper", 0);
    let paths = migration_io::ensure_state_layout(&root).unwrap();
    let source = migration_io::read_document(&paths.manifest, "manifest").unwrap();
    let plan = engine::plan(&source).unwrap();
    engine::prepare(&paths, &plan, &source).unwrap();
    migration_io::replace_document(&paths.manifest, b"{\"schema_version\":0,\"tampered\":true}\n").unwrap();
    assert!(engine::recover(&paths).unwrap_err().to_string().contains("changed outside"));
    assert!(paths.backup.is_file());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn rejects_future_schema() {
    let root = workspace("future", CURRENT_SCHEMA_VERSION + 1);
    let paths = migration_io::ensure_state_layout(&root).unwrap();
    let bytes = migration_io::read_document(&paths.manifest, "manifest").unwrap();
    assert!(engine::plan(&bytes).is_err());
    fs::remove_dir_all(root).unwrap();
}
