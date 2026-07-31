mod demo;

use std::{fs, net::IpAddr, path::PathBuf};

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use demo::{
    build_demo_receipt, default_demo_output, read_demo_receipt, verify_demo_receipt,
    write_demo_receipt, MILESTONE_END, MILESTONE_START, WORKSPACE_CRATE_COUNT,
};
use nxb_events::EventEnvelope;
use nxb_policy::{is_public_destination, TargetPolicy};

#[derive(Debug, Parser)]
#[command(name = "nxb", version, about = "NXBounty safety-contract utilities")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Parse and compile a target policy without making network requests.
    ValidatePolicy {
        path: PathBuf,
        /// Override current time using RFC3339, primarily for deterministic fixtures.
        #[arg(long)]
        now: Option<String>,
    },
    /// Parse and validate one canonical event JSON document.
    ValidateEvent { path: PathBuf },
    /// Check whether an IP is public according to the default egress guard.
    CheckDestination { ip: IpAddr },
    /// Print the contract-complete repository profile.
    SystemStatus,
    /// Generate and verify a deterministic networkless architecture smoke receipt.
    DemoRun {
        /// Receipt output path. Defaults to target/nxb-demo-receipt.json.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Verify a previously generated architecture smoke receipt.
    VerifyDemo { path: PathBuf },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::ValidatePolicy { path, now } => validate_policy(path, now),
        Command::ValidateEvent { path } => validate_event(path),
        Command::CheckDestination { ip } => check_destination(ip),
        Command::SystemStatus => system_status(),
        Command::DemoRun { output } => demo_run(output),
        Command::VerifyDemo { path } => verify_demo(path),
    }
}

fn validate_policy(path: PathBuf, now: Option<String>) -> Result<()> {
    let input = fs::read_to_string(&path)
        .with_context(|| format!("could not read policy file {}", path.display()))?;
    let now = match now {
        Some(value) => DateTime::parse_from_rfc3339(&value)
            .with_context(|| format!("invalid RFC3339 timestamp: {value}"))?
            .with_timezone(&Utc),
        None => Utc::now(),
    };

    let policy = TargetPolicy::from_toml(&input)?;
    let compiled = policy.compile(now)?;

    println!("policy: valid");
    println!("program: {}", compiled.program_name());
    println!("included_hosts: {}", compiled.included_host_count());
    println!(
        "maximum_total_requests: {}",
        compiled.maximum_total_requests()
    );
    Ok(())
}

fn validate_event(path: PathBuf) -> Result<()> {
    let input = fs::read_to_string(&path)
        .with_context(|| format!("could not read event file {}", path.display()))?;
    let event = EventEnvelope::from_json(&input)?;
    event.validate()?;

    println!("event: valid");
    println!("event_id: {}", event.event_id);
    println!("run_id: {}", event.run_id);
    Ok(())
}

fn check_destination(ip: IpAddr) -> Result<()> {
    if !is_public_destination(ip) {
        bail!("destination is denied by the default public-egress guard: {ip}");
    }

    println!("destination: public");
    println!("ip: {ip}");
    Ok(())
}

fn system_status() -> Result<()> {
    let receipt = build_demo_receipt()?;
    println!("status: contract-complete");
    println!("milestones: NXB-{MILESTONE_START}..NXB-{MILESTONE_END}");
    println!("workspace_crates: {WORKSPACE_CRATE_COUNT}");
    println!("execution_mode: synthetic-networkless");
    println!("live_network_adapter: disabled");
    println!("demo_tail_sha256: {}", receipt.tail_hash);
    Ok(())
}

fn demo_run(output: Option<PathBuf>) -> Result<()> {
    let output = output.unwrap_or_else(default_demo_output);
    let receipt = build_demo_receipt()?;
    write_demo_receipt(&output, &receipt)?;
    println!("demo: valid");
    println!("mode: {}", receipt.mode);
    println!("stages: {}", receipt.stage_count);
    println!("tail_sha256: {}", receipt.tail_hash);
    println!("receipt: {}", output.display());
    Ok(())
}

fn verify_demo(path: PathBuf) -> Result<()> {
    let receipt = read_demo_receipt(&path)?;
    verify_demo_receipt(&receipt)?;
    println!("demo_receipt: valid");
    println!("stages: {}", receipt.stage_count);
    println!("tail_sha256: {}", receipt.tail_hash);
    Ok(())
}
