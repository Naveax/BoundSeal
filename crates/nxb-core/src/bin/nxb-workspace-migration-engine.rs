use anyhow::{bail, Context, Result};

use crate::{
    manifest_schema, now, sha256, validate_common, validate_identifier, validate_manifest_v1,
    validate_sha, AppliedMarker, LegacyManifestV0, ManifestV1, MigrationPlan, MigrationReceipt,
    PreparedJournal, RecoveryDisposition, SecretStorageBoundary, CURRENT_SCHEMA_VERSION,
    JOURNAL_VERSION, RECEIPT_VERSION,
};
use crate::migration_io::{self, MigrationPaths};

pub(crate) fn plan(source: &[u8]) -> Result<MigrationPlan> {
    if manifest_schema(source)? != 0 { bail!("migration planner expected schema 0"); }
    let legacy: LegacyManifestV0 = serde_json::from_slice(source).context("legacy manifest is invalid")?;
    validate_common(
        legacy.schema_version,
        &legacy.product,
        &legacy.workspace_id,
        &legacy.name,
        &legacy.created_at,
    )?;
    let target = ManifestV1 {
        schema_version: CURRENT_SCHEMA_VERSION,
        product: legacy.product,
        workspace_id: legacy.workspace_id,
        name: legacy.name,
        created_at: legacy.created_at,
        secret_storage: SecretStorageBoundary::ExternalProviderOnly,
    };
    validate_manifest_v1(&target)?;
    let mut target_bytes = serde_json::to_vec_pretty(&target)?;
    target_bytes.push(b'\n');
    let source_sha256 = sha256(source);
    let target_sha256 = sha256(&target_bytes);
    let identity = sha256(format!("nxb-migration-v1:{source_sha256}:{target_sha256}").as_bytes());
    Ok(MigrationPlan {
        migration_id: format!("nxb-migration-0-1-{}", &identity[..24]),
        source_sha256,
        target_sha256,
        target_bytes,
    })
}

pub(crate) fn prepare(paths: &MigrationPaths, plan: &MigrationPlan, source: &[u8]) -> Result<()> {
    if migration_io::transient_state(paths)? != 0 { bail!("migration recovery is required first"); }
    if sha256(source) != plan.source_sha256 { bail!("migration source does not match its plan"); }
    migration_io::create_document(&paths.backup, source)?;
    let journal = PreparedJournal {
        journal_version: JOURNAL_VERSION,
        migration_id: plan.migration_id.clone(),
        from_schema: 0,
        to_schema: CURRENT_SCHEMA_VERSION,
        source_sha256: plan.source_sha256.clone(),
        target_sha256: plan.target_sha256.clone(),
        prepared_at: now(),
    };
    if let Err(error) = migration_io::create_json(&paths.active, &journal) {
        let _ = migration_io::remove_regular(&paths.backup);
        return Err(error);
    }
    Ok(())
}

pub(crate) fn recover(paths: &MigrationPaths) -> Result<RecoveryDisposition> {
    let active = migration_io::safe_exists(&paths.active)?;
    let backup = migration_io::safe_exists(&paths.backup)?;
    let applied = migration_io::safe_exists(&paths.applied)?;
    if !active && !backup && !applied { return Ok(RecoveryDisposition::None); }
    if !active && !backup { bail!("applied marker exists without prepared state"); }

    let (journal, source, plan) = if active {
        let journal: PreparedJournal = migration_io::read_json(&paths.active, "prepared journal")?;
        validate_journal(&journal)?;
        let receipt_path = paths.receipt(&journal.migration_id);
        if migration_io::safe_exists(&receipt_path)? {
            verify_committed(paths, &journal, &receipt_path)?;
            migration_io::cleanup(paths)?;
            return Ok(RecoveryDisposition::Cleanup);
        }
        if !backup { bail!("prepared journal exists without source backup"); }
        let source = migration_io::read_document(&paths.backup, "source backup")?;
        let plan = plan(&source)?;
        validate_journal_plan(&journal, &plan)?;
        (journal, source, plan)
    } else {
        let source = migration_io::read_document(&paths.backup, "orphan source backup")?;
        let plan = plan(&source)?;
        let journal = PreparedJournal {
            journal_version: JOURNAL_VERSION,
            migration_id: plan.migration_id.clone(),
            from_schema: 0,
            to_schema: CURRENT_SCHEMA_VERSION,
            source_sha256: plan.source_sha256.clone(),
            target_sha256: plan.target_sha256.clone(),
            prepared_at: now(),
        };
        migration_io::create_json(&paths.active, &journal)?;
        (journal, source, plan)
    };

    if sha256(&source) != journal.source_sha256 { bail!("source backup digest mismatch"); }
    let current = migration_io::read_optional_document(&paths.manifest, "workspace manifest")?;
    let current_hash = sha256(&current);
    if current.is_empty() || current_hash == plan.source_sha256 {
        migration_io::replace_document(&paths.manifest, &plan.target_bytes)?;
    } else if current_hash != plan.target_sha256 {
        bail!("workspace manifest changed outside the prepared migration");
    }

    let published = migration_io::read_document(&paths.manifest, "published manifest")?;
    if sha256(&published) != plan.target_sha256 { bail!("published manifest digest mismatch"); }
    validate_manifest_v1(&serde_json::from_slice(&published).context("published manifest is invalid")?)?;

    if applied {
        let marker: AppliedMarker = migration_io::read_json(&paths.applied, "applied marker")?;
        validate_marker(&marker, &plan)?;
    } else {
        migration_io::create_json(&paths.applied, &AppliedMarker {
            journal_version: JOURNAL_VERSION,
            migration_id: plan.migration_id.clone(),
            target_sha256: plan.target_sha256.clone(),
            applied_at: now(),
        })?;
    }

    let receipt = MigrationReceipt {
        receipt_version: RECEIPT_VERSION,
        migration_id: plan.migration_id.clone(),
        from_schema: 0,
        to_schema: CURRENT_SCHEMA_VERSION,
        source_sha256: plan.source_sha256,
        target_sha256: plan.target_sha256,
        committed_at: now(),
    };
    let receipt_path = paths.receipt(&receipt.migration_id);
    if migration_io::safe_exists(&receipt_path)? { verify_receipt(&receipt_path, &receipt)?; }
    else { migration_io::create_json(&receipt_path, &receipt)?; }
    migration_io::cleanup(paths)?;
    Ok(RecoveryDisposition::Recovered)
}

fn validate_journal(value: &PreparedJournal) -> Result<()> {
    if value.journal_version != JOURNAL_VERSION || value.from_schema != 0 || value.to_schema != CURRENT_SCHEMA_VERSION {
        bail!("prepared journal transition is invalid");
    }
    validate_identifier(&value.migration_id, "migration_id")?;
    validate_sha(&value.source_sha256, "source_sha256")?;
    validate_sha(&value.target_sha256, "target_sha256")?;
    validate_time(&value.prepared_at, "prepared_at")
}

fn validate_journal_plan(value: &PreparedJournal, plan: &MigrationPlan) -> Result<()> {
    if value.migration_id != plan.migration_id || value.source_sha256 != plan.source_sha256 || value.target_sha256 != plan.target_sha256 {
        bail!("prepared journal does not match the deterministic plan");
    }
    Ok(())
}

fn validate_marker(value: &AppliedMarker, plan: &MigrationPlan) -> Result<()> {
    if value.journal_version != JOURNAL_VERSION || value.migration_id != plan.migration_id || value.target_sha256 != plan.target_sha256 {
        bail!("applied marker does not match the deterministic plan");
    }
    validate_time(&value.applied_at, "applied_at")
}

fn verify_receipt(path: &std::path::Path, expected: &MigrationReceipt) -> Result<()> {
    let actual: MigrationReceipt = migration_io::read_json(path, "migration receipt")?;
    validate_receipt(&actual)?;
    if actual.migration_id != expected.migration_id
        || actual.from_schema != expected.from_schema
        || actual.to_schema != expected.to_schema
        || actual.source_sha256 != expected.source_sha256
        || actual.target_sha256 != expected.target_sha256
    {
        bail!("existing migration receipt conflicts with the completed migration");
    }
    Ok(())
}

fn verify_committed(paths: &MigrationPaths, journal: &PreparedJournal, receipt_path: &std::path::Path) -> Result<()> {
    let receipt: MigrationReceipt = migration_io::read_json(receipt_path, "migration receipt")?;
    validate_receipt(&receipt)?;
    if receipt.migration_id != journal.migration_id
        || receipt.source_sha256 != journal.source_sha256
        || receipt.target_sha256 != journal.target_sha256
    {
        bail!("migration receipt does not match the prepared journal");
    }
    let current = migration_io::read_document(&paths.manifest, "workspace manifest")?;
    if sha256(&current) != journal.target_sha256 { bail!("committed receipt exists but manifest is not the target"); }
    Ok(())
}

fn validate_receipt(value: &MigrationReceipt) -> Result<()> {
    if value.receipt_version != RECEIPT_VERSION || value.from_schema != 0 || value.to_schema != CURRENT_SCHEMA_VERSION {
        bail!("migration receipt transition is invalid");
    }
    validate_identifier(&value.migration_id, "migration_id")?;
    validate_sha(&value.source_sha256, "source_sha256")?;
    validate_sha(&value.target_sha256, "target_sha256")?;
    validate_time(&value.committed_at, "committed_at")
}

fn validate_time(value: &str, field: &str) -> Result<()> {
    let parsed = chrono::DateTime::parse_from_rfc3339(value).with_context(|| format!("{field} is invalid"))?;
    if parsed.offset().local_minus_utc() != 0 { bail!("{field} must use UTC"); }
    Ok(())
}
