#![forbid(unsafe_code)]

use std::{
    fs,
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand, ValueEnum};
use nxb_operator_runtime::RuntimeMethod;
use nxb_resumable_runner::{
    inspect_runner, request_emergency_stop_at, RunnerCandidate, RunnerManifest,
};
use nxb_unified_operator::UnifiedOperatorPlan;
use serde::{de::DeserializeOwned, Serialize};

const MAX_CONTROL_ARTIFACT_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Parser)]
#[command(
    name = "nxb-resumable-runner",
    version,
    about = "NXB-144 resumable bounded live-runner control plane"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Build a networkless runner manifest bound to one unified operator plan.
    Plan {
        #[arg(long)]
        unified_plan: PathBuf,
        #[arg(long, value_enum)]
        seed_method: MethodArg,
        #[arg(long)]
        seed_target: String,
        #[arg(long, default_value_t = 256)]
        maximum_queue_entries: u64,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        now: Option<String>,
    },
    /// Verify a runner manifest without acquiring execution ownership.
    VerifyManifest {
        #[arg(long)]
        unified_plan: PathBuf,
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        now: Option<String>,
    },
    /// Read and verify the latest durable runner checkpoint.
    Status {
        #[arg(long)]
        unified_plan: PathBuf,
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        runner_directory: PathBuf,
    },
    /// Persist an idempotent emergency-stop request for an active or resumable runner.
    RequestStop {
        #[arg(long)]
        runner_directory: PathBuf,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum MethodArg {
    Get,
    Head,
}

impl From<MethodArg> for RuntimeMethod {
    fn from(value: MethodArg) -> Self {
        match value {
            MethodArg::Get => RuntimeMethod::Get,
            MethodArg::Head => RuntimeMethod::Head,
        }
    }
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Plan {
            unified_plan,
            seed_method,
            seed_target,
            maximum_queue_entries,
            output,
            now,
        } => {
            let plan: UnifiedOperatorPlan = read_json(&unified_plan)?;
            let now = parse_now(now)?.timestamp();
            let manifest = RunnerManifest::build(
                &plan,
                RunnerCandidate::seed(seed_method.into(), seed_target, 0),
                maximum_queue_entries,
                now,
            )?;
            write_json(&output, &manifest)?;
            println!("resumable_runner_manifest: valid");
            println!("manifest_sha256: {}", manifest.manifest_sha256);
            println!("plan_sha256: {}", manifest.plan_sha256);
            println!("maximum_requests: {}", manifest.maximum_requests);
            println!("maximum_queue_entries: {}", manifest.maximum_queue_entries);
            println!("network_activity: none");
            println!("output: {}", output.display());
            Ok(())
        }
        Command::VerifyManifest {
            unified_plan,
            manifest,
            now,
        } => {
            let plan: UnifiedOperatorPlan = read_json(&unified_plan)?;
            let manifest: RunnerManifest = read_json(&manifest)?;
            manifest.validate(&plan, parse_now(now)?.timestamp())?;
            println!("resumable_runner_manifest: valid");
            println!("manifest_sha256: {}", manifest.manifest_sha256);
            println!("network_activity: none");
            Ok(())
        }
        Command::Status {
            unified_plan,
            manifest,
            runner_directory,
        } => {
            let plan: UnifiedOperatorPlan = read_json(&unified_plan)?;
            let manifest: RunnerManifest = read_json(&manifest)?;
            let checkpoint = inspect_runner(&runner_directory, &plan, &manifest)?;
            println!("resumable_runner_checkpoint: valid");
            println!("sequence: {}", checkpoint.sequence);
            println!("status: {:?}", checkpoint.status);
            println!("completed_requests: {}", checkpoint.completed_requests);
            println!("pending_requests: {}", checkpoint.pending_queue.len());
            println!("recovery_gap_count: {}", checkpoint.recovery_gap_count);
            println!("checkpoint_sha256: {}", checkpoint.checkpoint_sha256);
            Ok(())
        }
        Command::RequestStop { runner_directory } => {
            request_emergency_stop_at(&runner_directory)?;
            println!("emergency_stop: requested");
            println!("runner_directory: {}", runner_directory.display());
            Ok(())
        }
    }
}

fn parse_now(value: Option<String>) -> Result<DateTime<Utc>> {
    match value {
        Some(value) => DateTime::parse_from_rfc3339(&value)
            .with_context(|| format!("invalid RFC3339 timestamp: {value}"))
            .map(|value| value.with_timezone(&Utc)),
        None => Ok(Utc::now()),
    }
}

fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let metadata =
        fs::metadata(path).with_context(|| format!("could not stat {}", path.display()))?;
    if !metadata.is_file() || metadata.len() > MAX_CONTROL_ARTIFACT_BYTES {
        bail!("artifact is not a bounded regular file: {}", path.display());
    }
    let bytes = fs::read(path).with_context(|| format!("could not read {}", path.display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("could not parse JSON artifact {}", path.display()))
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("could not create {}", parent.display()))?;
    }
    let mut bytes =
        serde_json::to_vec_pretty(value).context("could not serialize JSON artifact")?;
    bytes.push(b'\n');
    if bytes.len() as u64 > MAX_CONTROL_ARTIFACT_BYTES {
        bail!("serialized artifact exceeds its byte bound");
    }
    let temporary = path.with_extension(format!("{}.tmp", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .with_context(|| format!("could not create {}", temporary.display()))?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .with_context(|| format!("could not write {}", temporary.display()))?;
    fs::hard_link(&temporary, path)
        .with_context(|| format!("could not publish {} without clobbering", path.display()))?;
    fs::remove_file(&temporary)
        .with_context(|| format!("could not remove {}", temporary.display()))?;
    Ok(())
}
