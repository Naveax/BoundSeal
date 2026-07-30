use std::{fs, net::IpAddr, path::PathBuf};

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
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
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::ValidatePolicy { path, now } => validate_policy(path, now),
        Command::ValidateEvent { path } => validate_event(path),
        Command::CheckDestination { ip } => check_destination(ip),
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
